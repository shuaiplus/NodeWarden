import type { Env, PasskeyCredential, TokenResponse } from '../types';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { errorResponse, identityErrorResponse, jsonResponse } from '../utils/response';
import { randomChallenge, parseClientDataJSON } from '../utils/passkey';
import { generateUUID } from '../utils/uuid';
import { readAuthRequestDeviceInfo } from '../utils/device';
import { LIMITS } from '../config/limits';
import { buildAccountKeys, buildUserDecryptionOptions } from '../utils/user-decryption';
import { isTotpEnabled, verifyTotpToken } from '../utils/totp';

const PASSKEY_MAX = 5;
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const TWO_FACTOR_PROVIDER_AUTHENTICATOR = 0;

function rpIdFromUrl(url: string): string {
  return new URL(url).hostname;
}

function twoFactorRequiredResponse(message: string = 'Two factor required.'): Response {
  return jsonResponse(
    {
      error: 'invalid_grant',
      error_description: message,
      TwoFactorProviders: [String(TWO_FACTOR_PROVIDER_AUTHENTICATOR)],
      TwoFactorProviders2: { '0': null },
      ErrorModel: {
        Message: message,
        Object: 'error',
      },
    },
    400
  );
}

export async function handleListPasskeys(_request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const records = await storage.listPasskeysByUserId(userId);
  return jsonResponse({
    object: 'list',
    data: records.map((record) => ({
      id: record.id,
      name: record.name,
      credentialId: record.credentialId,
      creationDate: record.createdAt,
      revisionDate: record.updatedAt,
      lastUsedDate: record.lastUsedAt,
      object: 'passkeyCredential',
    })),
  });
}

export async function handleBeginPasskeyRegistration(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const passkeys = await storage.listPasskeysByUserId(userId);
  if (passkeys.length >= PASSKEY_MAX) return errorResponse('Maximum 5 passkeys are allowed', 400);

  const challenge = randomChallenge();
  const challengeId = generateUUID();
  await storage.createPasskeyChallenge(challengeId, userId, challenge, 'register', Date.now() + CHALLENGE_TTL_MS);

  return jsonResponse({
    challengeId,
    publicKey: {
      challenge,
      rp: {
        id: rpIdFromUrl(request.url),
        name: 'NodeWarden',
      },
      user: {
        id: userId,
        name: userId,
        displayName: userId,
      },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'preferred',
      },
      timeout: 60000,
      attestation: 'none',
      excludeCredentials: passkeys.map((pk) => ({ type: 'public-key', id: pk.credentialId })),
    },
  });
}

export async function handleFinishPasskeyRegistration(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const body = (await request.json()) as {
    challengeId?: string;
    name?: string;
    wrappedVaultKeys?: string;
    credential?: {
      id?: string;
      response?: {
        clientDataJSON?: string;
      };
    };
  };
  const challengeId = String(body.challengeId || '').trim();
  const name = String(body.name || '').trim();
  const wrappedVaultKeys = String(body.wrappedVaultKeys || '').trim();
  const credentialId = String(body.credential?.id || '').trim();
  const clientData = String(body.credential?.response?.clientDataJSON || '').trim();

  if (!challengeId || !name || !wrappedVaultKeys || !credentialId || !clientData) {
    return errorResponse('Invalid request payload', 400);
  }
  const challengeRecord = await storage.consumePasskeyChallenge(challengeId, 'register');
  if (!challengeRecord || challengeRecord.userId !== userId) return errorResponse('Challenge expired', 400);

  const parsedClientData = parseClientDataJSON(clientData);
  const origin = new URL(request.url).origin;
  if (!parsedClientData || parsedClientData.type !== 'webauthn.create' || parsedClientData.challenge !== challengeRecord.challenge || parsedClientData.origin !== origin) {
    return errorResponse('Passkey attestation invalid', 400);
  }

  const existing = await storage.getPasskeyByCredentialId(credentialId);
  if (existing) return errorResponse('Passkey already registered', 409);

  const now = new Date().toISOString();
  const record: PasskeyCredential = {
    id: generateUUID(),
    userId,
    credentialId,
    publicKey: 'client-asserted',
    counter: 0,
    transports: null,
    name: name.slice(0, 100),
    wrappedVaultKeys,
    createdAt: now,
    updatedAt: now,
    lastUsedAt: null,
  };
  await storage.createPasskey(record);
  return jsonResponse({ success: true, id: record.id, object: 'passkeyCredential' });
}

export async function handleRenamePasskey(request: Request, env: Env, userId: string, passkeyId: string): Promise<Response> {
  const body = (await request.json()) as { name?: string };
  const name = String(body.name || '').trim();
  if (!name) return errorResponse('Name is required', 400);
  const storage = new StorageService(env.DB);
  const ok = await storage.updatePasskeyName(userId, passkeyId, name.slice(0, 100));
  if (!ok) return errorResponse('Passkey not found', 404);
  return jsonResponse({ success: true });
}

export async function handleDeletePasskey(_request: Request, env: Env, userId: string, passkeyId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const ok = await storage.deletePasskey(userId, passkeyId);
  if (!ok) return errorResponse('Passkey not found', 404);
  return new Response(null, { status: 204 });
}

export async function handleBeginPasskeyLogin(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);
  const body = (await request.json().catch(() => ({}))) as { email?: string };
  const email = String(body.email || '').trim().toLowerCase();
  const user = email ? await storage.getUser(email) : null;
  const passkeys = user ? await storage.listPasskeysByUserId(user.id) : [];

  const challenge = randomChallenge();
  const challengeId = generateUUID();
  await storage.createPasskeyChallenge(challengeId, user?.id || null, challenge, 'login', Date.now() + CHALLENGE_TTL_MS);

  return jsonResponse({
    challengeId,
    publicKey: {
      challenge,
      rpId: rpIdFromUrl(request.url),
      timeout: 60000,
      userVerification: 'preferred',
      allowCredentials: passkeys.map((pk) => ({ type: 'public-key', id: pk.credentialId })),
    },
  });
}

export async function handleFinishPasskeyLogin(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const body = (await request.json()) as {
    challengeId?: string;
    twoFactorToken?: string;
    credential?: {
      id?: string;
      response?: {
        clientDataJSON?: string;
      };
    };
    deviceIdentifier?: string;
    deviceName?: string;
    deviceType?: string;
  };
  const challengeId = String(body.challengeId || '').trim();
  const credentialId = String(body.credential?.id || '').trim();
  const clientData = String(body.credential?.response?.clientDataJSON || '').trim();
  if (!challengeId || !credentialId || !clientData) return identityErrorResponse('Invalid request payload', 'invalid_request', 400);

  const challengeRecord = await storage.consumePasskeyChallenge(challengeId, 'login');
  if (!challengeRecord) return identityErrorResponse('Passkey challenge expired', 'invalid_grant', 400);

  const parsedClientData = parseClientDataJSON(clientData);
  const origin = new URL(request.url).origin;
  if (!parsedClientData || parsedClientData.type !== 'webauthn.get' || parsedClientData.challenge !== challengeRecord.challenge || parsedClientData.origin !== origin) {
    return identityErrorResponse('Passkey assertion invalid', 'invalid_grant', 400);
  }

  const credential = await storage.getPasskeyByCredentialId(credentialId);
  if (!credential) return identityErrorResponse('Passkey not recognized', 'invalid_grant', 400);
  const user = await storage.getUserById(credential.userId);
  if (!user || user.status !== 'active') return identityErrorResponse('Account is disabled', 'invalid_grant', 400);

  if (user.totpSecret && isTotpEnabled(user.totpSecret)) {
    const token = String(body.twoFactorToken || '').trim();
    if (!token) return twoFactorRequiredResponse();
    const totpOk = await verifyTotpToken(user.totpSecret, token);
    if (!totpOk) return identityErrorResponse('Two-step token is invalid. Try again.', 'invalid_grant', 400);
  }

  const deviceInfo = readAuthRequestDeviceInfo(body as Record<string, string>, request);
  const deviceSession = deviceInfo.deviceIdentifier ? { identifier: deviceInfo.deviceIdentifier, sessionStamp: generateUUID() } : null;
  if (deviceSession) {
    await storage.upsertDevice(user.id, deviceSession.identifier, deviceInfo.deviceName, deviceInfo.deviceType, deviceSession.sessionStamp);
  }

  const accessToken = await auth.generateAccessToken(user, deviceSession);
  const refreshToken = await auth.generateRefreshToken(user.id, deviceSession);
  await storage.touchPasskeyUsage(credential.id);

  let vaultKeys: { symEncKey: string; symMacKey: string } | undefined;
  try {
    const wrapped = JSON.parse(credential.wrappedVaultKeys) as { symEncKey?: string; symMacKey?: string };
    if (wrapped.symEncKey && wrapped.symMacKey) {
      vaultKeys = { symEncKey: wrapped.symEncKey, symMacKey: wrapped.symMacKey };
    }
  } catch {
    vaultKeys = undefined;
  }

  const response: TokenResponse = {
    access_token: accessToken,
    expires_in: LIMITS.auth.accessTokenTtlSeconds,
    token_type: 'Bearer',
    refresh_token: refreshToken,
    Key: user.key,
    PrivateKey: user.privateKey,
    AccountKeys: buildAccountKeys(user),
    accountKeys: buildAccountKeys(user),
    Kdf: user.kdfType,
    KdfIterations: user.kdfIterations,
    KdfMemory: user.kdfMemory,
    KdfParallelism: user.kdfParallelism,
    ForcePasswordReset: false,
    ResetMasterPassword: false,
    MasterPasswordPolicy: { Object: 'masterPasswordPolicy' },
    ApiUseKeyConnector: false,
    scope: 'api offline_access',
    unofficialServer: true,
    UserDecryptionOptions: buildUserDecryptionOptions(user),
    userDecryptionOptions: buildUserDecryptionOptions(user),
    VaultKeys: vaultKeys,
  };

  return jsonResponse(response);
}
