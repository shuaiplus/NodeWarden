import { Env, User, ProfileResponse, DEFAULT_DEV_SECRET } from '../types';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { RateLimitService, getClientIdentifier } from '../services/ratelimit';
import { jsonResponse, errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { LIMITS } from '../config/limits';
import { isTotpEnabled, verifyTotpToken } from '../utils/totp';
import { createRecoveryCode, recoveryCodeEquals } from '../utils/recovery-code';

function looksLikeEncString(value: string): boolean {
  if (!value) return false;
  const firstDot = value.indexOf('.');
  if (firstDot <= 0 || firstDot === value.length - 1) return false;
  const payload = value.slice(firstDot + 1);
  const parts = payload.split('|');
  // Bitwarden encrypted payloads should have at least IV + ciphertext.
  return parts.length >= 2;
}

function normalizeTotpSecret(input: string): string {
  return input.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/g, '');
}

function normalizeRecoveryCodeInput(input: string): string {
  return String(input || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
}

function jwtSecretUnsafeReason(env: Env): 'missing' | 'default' | 'too_short' | null {
  const secret = (env.JWT_SECRET || '').trim();
  if (!secret) return 'missing';
  if (secret === DEFAULT_DEV_SECRET) return 'default';
  if (secret.length < LIMITS.auth.jwtSecretMinLength) return 'too_short';
  return null;
}

function toProfile(user: User, env: Env): ProfileResponse {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    emailVerified: true,
    premium: true,
    premiumFromOrganization: false,
    usesKeyConnector: false,
    masterPasswordHint: null,
    culture: 'en-US',
    twoFactorEnabled: !!user.totpSecret || isTotpEnabled(env.TOTP_SECRET),
    key: user.key,
    privateKey: user.privateKey,
    accountKeys: null,
    securityStamp: user.securityStamp || user.id,
    organizations: [],
    providers: [],
    providerOrganizations: [],
    forcePasswordReset: false,
    avatarColor: null,
    creationDate: user.createdAt,
    role: user.role,
    status: user.status,
    object: 'profile',
  };
}

// POST /api/accounts/register
// - First user becomes admin.
// - Any subsequent user must provide a valid inviteCode.
export async function handleRegister(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);

  const unsafe = jwtSecretUnsafeReason(env);
  if (unsafe) {
    const message = unsafe === 'missing'
      ? 'JWT_SECRET is not set'
      : unsafe === 'default'
        ? 'JWT_SECRET is using the default/sample value. Please change it.'
        : 'JWT_SECRET must be at least 32 characters';
    return errorResponse(message, 400);
  }

  let body: {
    email?: string;
    name?: string;
    masterPasswordHash?: string;
    key?: string;
    kdf?: number;
    kdfIterations?: number;
    kdfMemory?: number;
    kdfParallelism?: number;
    inviteCode?: string;
    keys?: {
      publicKey?: string;
      encryptedPrivateKey?: string;
    };
  };

  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const email = body.email?.toLowerCase().trim();
  const name = body.name?.trim() || email;
  const masterPasswordHash = body.masterPasswordHash;
  const key = body.key;
  const privateKey = body.keys?.encryptedPrivateKey;
  const publicKey = body.keys?.publicKey;
  const inviteCode = (body.inviteCode || '').trim();

  if (!email || !masterPasswordHash || !key) {
    return errorResponse('Email, masterPasswordHash, and key are required', 400);
  }
  if (!privateKey || !publicKey) {
    return errorResponse('Private key and public key are required', 400);
  }
  if (!looksLikeEncString(key)) {
    return errorResponse('key is not a valid encrypted string', 400);
  }
  if (!looksLikeEncString(privateKey)) {
    return errorResponse('encryptedPrivateKey is not a valid encrypted string', 400);
  }

  const now = new Date().toISOString();
  const auth = new AuthService(env);
  const serverHash = await auth.hashPasswordServer(masterPasswordHash, email);

  const user: User = {
    id: generateUUID(),
    email,
    name: name || email,
    masterPasswordHash: serverHash,
    key,
    privateKey,
    publicKey,
    kdfType: body.kdf ?? 0,
    kdfIterations: body.kdfIterations ?? LIMITS.auth.defaultKdfIterations,
    kdfMemory: body.kdfMemory,
    kdfParallelism: body.kdfParallelism,
    securityStamp: generateUUID(),
    role: 'user',
    status: 'active',
    totpSecret: null,
    totpRecoveryCode: null,
    createdAt: now,
    updatedAt: now,
  };

  const userCount = await storage.getUserCount();
  if (userCount === 0) {
    user.role = 'admin';
    const created = await storage.createFirstUser(user);
    if (!created) {
      return errorResponse('Registration is temporarily unavailable, retry once', 409);
    }
    await storage.setRegistered();
    await storage.createAuditLog({
      id: generateUUID(),
      actorUserId: user.id,
      action: 'user.register.first_admin',
      targetType: 'user',
      targetId: user.id,
      metadata: JSON.stringify({ email: user.email }),
      createdAt: now,
    });
    return jsonResponse({ success: true, role: user.role }, 200);
  }

  if (!inviteCode) {
    return errorResponse('Invite code is required', 403);
  }

  try {
    await storage.createUser(user);
  } catch (error) {
    const msg = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
    if (msg.includes('unique') || msg.includes('constraint')) {
      return errorResponse('Email already registered', 409);
    }
    throw error;
  }

  const inviteMarked = await storage.markInviteUsed(inviteCode, user.id);
  if (!inviteMarked) {
    await storage.deleteUserById(user.id);
    return errorResponse('Invite code is invalid or expired', 403);
  }

  await storage.createAuditLog({
    id: generateUUID(),
    actorUserId: user.id,
    action: 'user.register.invite',
    targetType: 'user',
    targetId: user.id,
    metadata: JSON.stringify({ email: user.email, inviteCode }),
    createdAt: now,
  });

  return jsonResponse({ success: true, role: user.role }, 200);
}

// GET /api/accounts/profile
export async function handleGetProfile(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);
  return jsonResponse(toProfile(user, env));
}

// PUT /api/accounts/profile
export async function handleUpdateProfile(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: { name?: string; email?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (typeof body.name === 'string') {
    user.name = body.name.trim() || user.name;
  }
  if (typeof body.email === 'string') {
    const normalized = body.email.trim().toLowerCase();
    if (!normalized) return errorResponse('Email is required', 400);
    user.email = normalized;
  }
  user.updatedAt = new Date().toISOString();

  try {
    await storage.saveUser(user);
  } catch (error) {
    const msg = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
    if (msg.includes('unique') || msg.includes('constraint')) {
      return errorResponse('Email already registered', 409);
    }
    throw error;
  }

  return handleGetProfile(request, env, userId);
}

// POST /api/accounts/keys
export async function handleSetKeys(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);

  if (!user) {
    return errorResponse('User not found', 404);
  }

  let body: {
    masterPasswordHash?: string;
    key?: string;
    encryptedPrivateKey?: string;
    publicKey?: string;
  };

  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  // Require password verification before allowing key replacement.
  if (!body.masterPasswordHash) {
    return errorResponse('masterPasswordHash is required', 400);
  }
  const passwordValid = await auth.verifyPassword(body.masterPasswordHash, user.masterPasswordHash, user.email);
  if (!passwordValid) {
    return errorResponse('Invalid password', 400);
  }

  if (body.key) user.key = body.key;
  if (body.encryptedPrivateKey) user.privateKey = body.encryptedPrivateKey;
  if (body.publicKey) user.publicKey = body.publicKey;
  if (body.key && !looksLikeEncString(body.key)) {
    return errorResponse('key is not a valid encrypted string', 400);
  }
  if (body.encryptedPrivateKey && !looksLikeEncString(body.encryptedPrivateKey)) {
    return errorResponse('encryptedPrivateKey is not a valid encrypted string', 400);
  }
  user.updatedAt = new Date().toISOString();

  await storage.saveUser(user);

  return handleGetProfile(request, env, userId);
}

// POST/PUT /api/accounts/password
export async function handleChangePassword(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: {
    masterPasswordHash?: string;
    currentPasswordHash?: string;
    newMasterPasswordHash?: string;
    key?: string;
    newKey?: string;
    encryptedPrivateKey?: string;
    newEncryptedPrivateKey?: string;
    publicKey?: string;
    newPublicKey?: string;
    kdf?: number;
    kdfIterations?: number;
    kdfMemory?: number;
    kdfParallelism?: number;
  };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const currentHash = body.currentPasswordHash || body.masterPasswordHash;
  if (!currentHash) return errorResponse('Current password hash is required', 400);
  const valid = await auth.verifyPassword(currentHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse('Invalid password', 400);

  if (!body.newMasterPasswordHash) {
    return errorResponse('newMasterPasswordHash is required', 400);
  }
  const nextKey = body.newKey || body.key;
  const nextPrivateKey = body.newEncryptedPrivateKey || body.encryptedPrivateKey;
  const nextPublicKey = body.newPublicKey || body.publicKey;
  if (nextKey && !looksLikeEncString(nextKey)) {
    return errorResponse('new key is not a valid encrypted string', 400);
  }
  if (nextPrivateKey && !looksLikeEncString(nextPrivateKey)) {
    return errorResponse('new encryptedPrivateKey is not a valid encrypted string', 400);
  }

  user.masterPasswordHash = await auth.hashPasswordServer(body.newMasterPasswordHash, user.email);
  if (nextKey) user.key = nextKey;
  if (nextPrivateKey) user.privateKey = nextPrivateKey;
  if (nextPublicKey) user.publicKey = nextPublicKey;
  if (typeof body.kdf === 'number') user.kdfType = body.kdf;
  if (typeof body.kdfIterations === 'number') user.kdfIterations = body.kdfIterations;
  if (typeof body.kdfMemory === 'number') user.kdfMemory = body.kdfMemory;
  if (typeof body.kdfParallelism === 'number') user.kdfParallelism = body.kdfParallelism;
  user.securityStamp = generateUUID();
  user.updatedAt = new Date().toISOString();
  await storage.saveUser(user);
  await storage.deleteRefreshTokensByUserId(user.id);

  return new Response(null, { status: 200 });
}

// GET /api/accounts/totp
export async function handleGetTotpStatus(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  return jsonResponse({
    enabled: !!user.totpSecret,
    object: 'twoFactor',
  });
}

// PUT /api/accounts/totp
// enable: { enabled: true, secret: "...", token: "123456" }
// disable: { enabled: false, masterPasswordHash: "..." }
export async function handleSetTotpStatus(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: { enabled?: boolean; secret?: string; token?: string; masterPasswordHash?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (body.enabled === true) {
    const normalizedSecret = normalizeTotpSecret(body.secret || '');
    if (!isTotpEnabled(normalizedSecret)) {
      return errorResponse('Invalid TOTP secret', 400);
    }
    if (!body.token) {
      return errorResponse('TOTP token is required', 400);
    }
    const verified = await verifyTotpToken(normalizedSecret, body.token);
    if (!verified) {
      return errorResponse('Invalid TOTP token', 400);
    }
    user.totpSecret = normalizedSecret;
    if (!user.totpRecoveryCode) {
      user.totpRecoveryCode = createRecoveryCode();
    }
    user.updatedAt = new Date().toISOString();
    await storage.saveUser(user);
    await storage.deleteRefreshTokensByUserId(user.id);
    return jsonResponse({ enabled: true, recoveryCode: user.totpRecoveryCode, object: 'twoFactor' });
  }

  if (body.enabled === false) {
    if (!body.masterPasswordHash) {
      return errorResponse('masterPasswordHash is required to disable TOTP', 400);
    }
    const valid = await auth.verifyPassword(body.masterPasswordHash, user.masterPasswordHash, user.email);
    if (!valid) return errorResponse('Invalid password', 400);

    user.totpSecret = null;
    user.updatedAt = new Date().toISOString();
    await storage.saveUser(user);
    await storage.deleteRefreshTokensByUserId(user.id);
    return jsonResponse({ enabled: false, object: 'twoFactor' });
  }

  return errorResponse('enabled must be true or false', 400);
}

// POST /api/accounts/totp/recovery-code
export async function handleGetTotpRecoveryCode(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: Record<string, string | undefined>;
  try {
    const contentType = request.headers.get('content-type') || '';
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const formData = await request.formData();
      body = Object.fromEntries(formData.entries()) as Record<string, string>;
    } else {
      body = await request.json();
    }
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const currentHash = String(body.masterPasswordHash || body.master_password_hash || body.password || '').trim();
  if (!currentHash) return errorResponse('masterPasswordHash is required', 400);
  const valid = await auth.verifyPassword(currentHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse('Invalid password', 400);

  if (!user.totpRecoveryCode) {
    user.totpRecoveryCode = createRecoveryCode();
    user.updatedAt = new Date().toISOString();
    await storage.saveUser(user);
  }

  return jsonResponse({
    code: user.totpRecoveryCode,
    object: 'twoFactorRecover',
  });
}

// POST /identity/accounts/recover-2fa
// Disable TOTP by recovery code + password, then rotate recovery code.
export async function handleRecoverTwoFactor(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const rateLimit = new RateLimitService(env.DB);

  let body: Record<string, string | undefined>;
  try {
    const contentType = request.headers.get('content-type') || '';
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const formData = await request.formData();
      body = Object.fromEntries(formData.entries()) as Record<string, string>;
    } else {
      body = await request.json();
    }
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const email = String(body.email || body.username || '').trim().toLowerCase();
  const masterPasswordHash = String(body.masterPasswordHash || body.password || '').trim();
  const recoveryCode = normalizeRecoveryCodeInput(String(body.recoveryCode || body.twoFactorToken || body.recovery_code || ''));
  const recoverLimitKey = `${getClientIdentifier(request)}:recover-2fa:${email || 'unknown'}`;

  const recoverAttemptCheck = await rateLimit.checkLoginAttempt(recoverLimitKey);
  if (!recoverAttemptCheck.allowed) {
    return errorResponse(
      `Too many failed recovery attempts. Try again in ${Math.ceil((recoverAttemptCheck.retryAfterSeconds || 60) / 60)} minutes.`,
      429
    );
  }

  if (!email || !masterPasswordHash || !recoveryCode) {
    return errorResponse('Email, masterPasswordHash and recoveryCode are required', 400);
  }

  const user = await storage.getUser(email);
  if (!user || user.status !== 'active') {
    await rateLimit.recordFailedLogin(recoverLimitKey);
    return errorResponse('Invalid credentials or recovery code', 400);
  }

  const validPassword = await auth.verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email);
  if (!validPassword) {
    await rateLimit.recordFailedLogin(recoverLimitKey);
    return errorResponse('Invalid credentials or recovery code', 400);
  }

  if (!recoveryCodeEquals(recoveryCode, user.totpRecoveryCode)) {
    await rateLimit.recordFailedLogin(recoverLimitKey);
    return errorResponse('Invalid credentials or recovery code', 400);
  }

  user.totpSecret = null;
  user.totpRecoveryCode = createRecoveryCode();
  user.securityStamp = generateUUID();
  user.updatedAt = new Date().toISOString();
  await storage.saveUser(user);
  await storage.deleteRefreshTokensByUserId(user.id);
  await rateLimit.clearLoginAttempts(recoverLimitKey);

  return jsonResponse({
    success: true,
    twoFactorEnabled: false,
    newRecoveryCode: user.totpRecoveryCode,
    object: 'twoFactorRecovery',
  });
}

// GET /api/accounts/revision-date
export async function handleGetRevisionDate(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const revisionDate = await storage.getRevisionDate(userId);

  // Return as milliseconds timestamp (Bitwarden format)
  const timestamp = new Date(revisionDate).getTime();
  return jsonResponse(timestamp);
}

// POST /api/accounts/verify-password
export async function handleVerifyPassword(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);

  if (!user) {
    return errorResponse('User not found', 404);
  }

  let body: { masterPasswordHash?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.masterPasswordHash) {
    return errorResponse('masterPasswordHash is required', 400);
  }

  const valid = await auth.verifyPassword(body.masterPasswordHash, user.masterPasswordHash, user.email);
  if (!valid) {
    return errorResponse('Invalid password', 400);
  }

  return new Response(null, { status: 200 });
}
