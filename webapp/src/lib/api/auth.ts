import { bytesToBase64, decryptBw, encryptBw, hkdfExpand, pbkdf2 } from '../crypto';
import { t } from '../i18n';
import type { AuthorizedDevice } from '../types';
import type {
  Profile,
  SessionState,
  TokenError,
  TokenSuccess,
} from '../types';
import { parseJson, type AuthedFetch, type SessionSetter } from './shared';

const SESSION_KEY = 'nodewarden.web.session.v4';
const DEVICE_IDENTIFIER_KEY = 'nodewarden.web.device.identifier.v1';
const TOTP_REMEMBER_TOKEN_KEY = 'nodewarden.web.totp.remember-token.v1';

export interface PreloginResult {
  hash: string;
  masterKey: Uint8Array;
  kdfIterations: number;
}

export interface PreloginKdfConfig {
  kdfType: number;
  kdfIterations: number;
  kdfMemory: number | null;
  kdfParallelism: number | null;
}

function randomHex(length: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(Math.max(1, Math.ceil(length / 2))));
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, length);
}

function getOrCreateDeviceIdentifier(): string {
  const current = (localStorage.getItem(DEVICE_IDENTIFIER_KEY) || '').trim();
  if (current) return current;
  const next = `${randomHex(8)}-${randomHex(4)}-${randomHex(4)}-${randomHex(4)}-${randomHex(12)}`;
  localStorage.setItem(DEVICE_IDENTIFIER_KEY, next);
  return next;
}

function guessDeviceName(): string {
  const ua = (typeof navigator !== 'undefined' ? navigator.userAgent : '').toLowerCase();
  const platform = (typeof navigator !== 'undefined' ? navigator.platform : '').trim();
  const browser = ua.includes('edg/') ? 'Edge' : ua.includes('chrome/') ? 'Chrome' : ua.includes('firefox/') ? 'Firefox' : ua.includes('safari/') ? 'Safari' : 'Browser';
  const os = ua.includes('windows') ? 'Windows' : ua.includes('mac os') ? 'macOS' : ua.includes('linux') ? 'Linux' : ua.includes('android') ? 'Android' : ua.includes('iphone') || ua.includes('ipad') ? 'iOS' : platform || 'Unknown OS';
  return `${browser} on ${os}`.slice(0, 128);
}

function getRememberTwoFactorToken(): string | null {
  const token = (localStorage.getItem(TOTP_REMEMBER_TOKEN_KEY) || '').trim();
  return token || null;
}

function saveRememberTwoFactorToken(token: string | undefined): void {
  const normalized = String(token || '').trim();
  if (!normalized) return;
  localStorage.setItem(TOTP_REMEMBER_TOKEN_KEY, normalized);
}

function clearRememberTwoFactorToken(): void {
  localStorage.removeItem(TOTP_REMEMBER_TOKEN_KEY);
}

export function loadSession(): SessionState | null {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as SessionState;
    if (!parsed.accessToken || !parsed.refreshToken) return null;
    return {
      accessToken: parsed.accessToken,
      refreshToken: parsed.refreshToken,
      email: parsed.email,
    };
  } catch {
    return null;
  }
}

export function saveSession(session: SessionState | null): void {
  if (!session) {
    localStorage.removeItem(SESSION_KEY);
    return;
  }
  const persisted: SessionState = {
    accessToken: session.accessToken,
    refreshToken: session.refreshToken,
    email: session.email,
  };
  localStorage.setItem(SESSION_KEY, JSON.stringify(persisted));
}

export function getCurrentDeviceIdentifier(): string {
  return (localStorage.getItem(DEVICE_IDENTIFIER_KEY) || '').trim();
}

export async function deriveLoginHash(email: string, password: string, fallbackIterations: number): Promise<PreloginResult> {
  const pre = await fetch('/identity/accounts/prelogin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: email.toLowerCase() }),
  });
  if (!pre.ok) throw new Error('prelogin failed');
  const data = (await parseJson<{ kdfIterations?: number }>(pre)) || {};
  const iterations = Number(data.kdfIterations || fallbackIterations);
  const masterKey = await pbkdf2(password, email.toLowerCase(), iterations, 32);
  const hash = await pbkdf2(masterKey, password, 1, 32);
  return { hash: bytesToBase64(hash), masterKey, kdfIterations: iterations };
}

export async function deriveLoginHashLocally(
  email: string,
  password: string,
  fallbackIterations: number
): Promise<PreloginResult> {
  const normalizedEmail = String(email || '').trim().toLowerCase();
  const iterations = Number(fallbackIterations || 600000);
  const masterKey = await pbkdf2(password, normalizedEmail, iterations, 32);
  const hash = await pbkdf2(masterKey, password, 1, 32);
  return { hash: bytesToBase64(hash), masterKey, kdfIterations: iterations };
}

export async function getPreloginKdfConfig(email: string, fallbackIterations: number): Promise<PreloginKdfConfig> {
  const normalized = String(email || '').trim().toLowerCase();
  if (!normalized) throw new Error('Email is required');
  const pre = await fetch('/identity/accounts/prelogin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: normalized }),
  });
  if (!pre.ok) throw new Error('prelogin failed');
  const data = (await parseJson<{ kdf?: number; kdfIterations?: number; kdfMemory?: number | null; kdfParallelism?: number | null }>(pre)) || {};
  return {
    kdfType: Number(data.kdf ?? 0) || 0,
    kdfIterations: Number(data.kdfIterations || fallbackIterations),
    kdfMemory: data.kdfMemory == null ? null : Number(data.kdfMemory),
    kdfParallelism: data.kdfParallelism == null ? null : Number(data.kdfParallelism),
  };
}

export async function loginWithPassword(
  email: string,
  passwordHash: string,
  options?: {
    totpCode?: string;
    rememberDevice?: boolean;
    useRememberToken?: boolean;
  }
): Promise<TokenSuccess | TokenError> {
  const body = new URLSearchParams();
  body.set('grant_type', 'password');
  body.set('username', email.toLowerCase());
  body.set('password', passwordHash);
  body.set('scope', 'api offline_access');
  body.set('deviceIdentifier', getOrCreateDeviceIdentifier());
  body.set('deviceName', guessDeviceName());
  body.set('deviceType', '14');

  const rememberedToken = options?.useRememberToken ? getRememberTwoFactorToken() : null;
  if (rememberedToken) {
    body.set('twoFactorProvider', '5');
    body.set('twoFactorToken', rememberedToken);
  } else if (options?.totpCode) {
    body.set('twoFactorProvider', '0');
    body.set('twoFactorToken', options.totpCode);
    if (options.rememberDevice) {
      body.set('twoFactorRemember', '1');
    }
  }
  const resp = await fetch('/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  const json = (await parseJson<TokenSuccess & TokenError>(resp)) || {};
  if (resp.ok) {
    saveRememberTwoFactorToken((json as TokenSuccess).TwoFactorToken);
  } else if (rememberedToken) {
    clearRememberTwoFactorToken();
  }
  if (!resp.ok) return json;
  return json;
}

export async function refreshAccessToken(refreshToken: string): Promise<TokenSuccess | null> {
  const body = new URLSearchParams();
  body.set('grant_type', 'refresh_token');
  body.set('refresh_token', refreshToken);
  const resp = await fetch('/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  if (!resp.ok) return null;
  const json = await parseJson<TokenSuccess>(resp);
  return json || null;
}

export async function registerAccount(args: {
  email: string;
  name: string;
  password: string;
  masterPasswordHint?: string;
  inviteCode?: string;
  fallbackIterations: number;
}): Promise<{ ok: true } | { ok: false; message: string }> {
  try {
    const { email, name, password, masterPasswordHint, inviteCode, fallbackIterations } = args;
    const masterKey = await pbkdf2(password, email, fallbackIterations, 32);
    const masterHash = await pbkdf2(masterKey, password, 1, 32);
    const encKey = await hkdfExpand(masterKey, 'enc', 32);
    const macKey = await hkdfExpand(masterKey, 'mac', 32);
    const sym = crypto.getRandomValues(new Uint8Array(64));
    const encryptedVaultKey = await encryptBw(sym, encKey, macKey);

    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-1',
      },
      true,
      ['encrypt', 'decrypt']
    );
    const publicKey = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
    const privateKey = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
    const encryptedPrivateKey = await encryptBw(privateKey, sym.slice(0, 32), sym.slice(32, 64));

    const resp = await fetch('/api/accounts/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: email.toLowerCase(),
        name,
        masterPasswordHint: String(masterPasswordHint || '').trim() || undefined,
        masterPasswordHash: bytesToBase64(masterHash),
        key: encryptedVaultKey,
        kdf: 0,
        kdfIterations: fallbackIterations,
        inviteCode: inviteCode || undefined,
        keys: {
          publicKey: bytesToBase64(publicKey),
          encryptedPrivateKey,
        },
      }),
    });

    if (!resp.ok) {
      const json = await parseJson<TokenError>(resp);
      return { ok: false, message: json?.error_description || json?.error || 'Register failed' };
    }
    return { ok: true };
  } catch (error) {
    return { ok: false, message: error instanceof Error ? error.message : 'Register failed' };
  }
}

export async function getPasswordHint(email: string): Promise<{ masterPasswordHint: string | null }> {
  const resp = await fetch('/api/accounts/password-hint', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: email.trim().toLowerCase() }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(body?.error_description || body?.error || 'Failed to load password hint');
  }
  const body = (await parseJson<{ masterPasswordHint?: string | null }>(resp)) || {};
  return { masterPasswordHint: body.masterPasswordHint ?? null };
}

export function createAuthedFetch(getSession: () => SessionState | null, setSession: SessionSetter) {
  return async function authedFetch(input: string, init: RequestInit = {}): Promise<Response> {
    const session = getSession();
    if (!session?.accessToken) throw new Error('Unauthorized');
    const headers = new Headers(init.headers || {});
    headers.set('Authorization', `Bearer ${session.accessToken}`);

    let resp = await fetch(input, { ...init, headers });
    if (resp.status !== 401 || !session.refreshToken) return resp;

    const refreshed = await refreshAccessToken(session.refreshToken);
    if (!refreshed?.access_token) {
      setSession(null);
      throw new Error('Session expired');
    }

    const nextSession: SessionState = {
      ...session,
      accessToken: refreshed.access_token,
      refreshToken: refreshed.refresh_token || session.refreshToken,
    };
    setSession(nextSession);
    saveSession(nextSession);

    const retryHeaders = new Headers(init.headers || {});
    retryHeaders.set('Authorization', `Bearer ${nextSession.accessToken}`);
    resp = await fetch(input, { ...init, headers: retryHeaders });
    return resp;
  };
}

export async function getProfile(authedFetch: AuthedFetch): Promise<Profile> {
  const resp = await authedFetch('/api/accounts/profile');
  if (!resp.ok) throw new Error('Failed to load profile');
  const body = await parseJson<Profile>(resp);
  if (!body) throw new Error('Invalid profile');
  return body;
}

export async function updateProfile(
  authedFetch: AuthedFetch,
  payload: { masterPasswordHint: string }
): Promise<Profile> {
  const resp = await authedFetch('/api/accounts/profile', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      masterPasswordHint: String(payload.masterPasswordHint || '').trim() || null,
    }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(body?.error_description || body?.error || 'Save profile failed');
  }
  const body = await parseJson<Profile>(resp);
  if (!body) throw new Error('Invalid profile');
  return body;
}

export async function unlockVaultKey(profileKey: string, masterKey: Uint8Array): Promise<{ symEncKey: string; symMacKey: string }> {
  const encKey = await hkdfExpand(masterKey, 'enc', 32);
  const macKey = await hkdfExpand(masterKey, 'mac', 32);
  const keyBytes = await decryptBw(profileKey, encKey, macKey);
  if (!keyBytes || keyBytes.length < 64) throw new Error('Invalid profile key');
  return {
    symEncKey: bytesToBase64(keyBytes.slice(0, 32)),
    symMacKey: bytesToBase64(keyBytes.slice(32, 64)),
  };
}

export async function changeMasterPassword(
  authedFetch: AuthedFetch,
  args: {
    email: string;
    currentPassword: string;
    newPassword: string;
    currentIterations: number;
    profileKey: string;
  }
): Promise<void> {
  const current = await deriveLoginHash(args.email, args.currentPassword, args.currentIterations);
  const oldEnc = await hkdfExpand(current.masterKey, 'enc', 32);
  const oldMac = await hkdfExpand(current.masterKey, 'mac', 32);
  const userSym = await decryptBw(args.profileKey, oldEnc, oldMac);
  const nextMasterKey = await pbkdf2(args.newPassword, args.email, current.kdfIterations, 32);
  const nextHash = await pbkdf2(nextMasterKey, args.newPassword, 1, 32);
  const nextEnc = await hkdfExpand(nextMasterKey, 'enc', 32);
  const nextMac = await hkdfExpand(nextMasterKey, 'mac', 32);
  const newKey = await encryptBw(userSym.slice(0, 64), nextEnc, nextMac);

  const resp = await authedFetch('/api/accounts/password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      currentPasswordHash: current.hash,
      newMasterPasswordHash: bytesToBase64(nextHash),
      newKey,
      kdf: 0,
      kdfIterations: current.kdfIterations,
    }),
  });
  if (!resp.ok) throw new Error('Change master password failed');
}

export async function setTotp(
  authedFetch: AuthedFetch,
  payload: { enabled: boolean; token?: string; secret?: string; masterPasswordHash?: string }
): Promise<void> {
  const resp = await authedFetch('/api/accounts/totp', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(body?.error_description || body?.error || 'TOTP update failed');
  }
}

export async function verifyMasterPassword(
  authedFetch: AuthedFetch,
  masterPasswordHash: string
): Promise<void> {
  const resp = await authedFetch('/api/accounts/verify-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ masterPasswordHash }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(body?.error_description || body?.error || 'Master password verify failed');
  }
}

export async function getTotpStatus(authedFetch: AuthedFetch): Promise<{ enabled: boolean }> {
  const resp = await authedFetch('/api/accounts/totp');
  if (!resp.ok) throw new Error('Failed to load TOTP status');
  const body = (await parseJson<{ enabled?: boolean }>(resp)) || {};
  return { enabled: !!body.enabled };
}

export async function getTotpRecoveryCode(
  authedFetch: AuthedFetch,
  masterPasswordHash: string
): Promise<string> {
  const resp = await authedFetch('/api/accounts/totp/recovery-code', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ masterPasswordHash }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(body?.error_description || body?.error || 'Failed to get recovery code');
  }
  const body = (await parseJson<{ code?: string }>(resp)) || {};
  return String(body.code || '');
}

export async function recoverTwoFactor(
  email: string,
  masterPasswordHash: string,
  recoveryCode: string
): Promise<{ newRecoveryCode?: string }> {
  const resp = await fetch('/identity/accounts/recover-2fa', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: email.toLowerCase().trim(),
      masterPasswordHash,
      recoveryCode,
    }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(body?.error_description || body?.error || 'Recover 2FA failed');
  }
  return (await parseJson<{ newRecoveryCode?: string }>(resp)) || {};
}

export async function getAuthorizedDevices(authedFetch: AuthedFetch): Promise<AuthorizedDevice[]> {
  const resp = await authedFetch('/api/devices/authorized');
  if (!resp.ok) throw new Error(t('txt_load_devices_failed'));
  const body = await parseJson<{ object: 'list'; data: AuthorizedDevice[] }>(resp);
  return body?.data || [];
}

export async function revokeAuthorizedDeviceTrust(
  authedFetch: AuthedFetch,
  deviceIdentifier: string
): Promise<void> {
  const resp = await authedFetch(`/api/devices/authorized/${encodeURIComponent(deviceIdentifier)}`, { method: 'DELETE' });
  if (!resp.ok) throw new Error(t('txt_revoke_device_trust_failed'));
}

export async function revokeAllAuthorizedDeviceTrust(authedFetch: AuthedFetch): Promise<void> {
  const resp = await authedFetch('/api/devices/authorized', { method: 'DELETE' });
  if (!resp.ok) throw new Error(t('txt_revoke_all_device_trust_failed'));
}

export async function deleteAuthorizedDevice(
  authedFetch: AuthedFetch,
  deviceIdentifier: string
): Promise<void> {
  const resp = await authedFetch(`/api/devices/${encodeURIComponent(deviceIdentifier)}`, { method: 'DELETE' });
  if (!resp.ok) throw new Error(t('txt_remove_device_failed'));
}

export async function deleteAllAuthorizedDevices(authedFetch: AuthedFetch): Promise<void> {
  const resp = await authedFetch('/api/devices', { method: 'DELETE' });
  if (!resp.ok) throw new Error(t('txt_remove_all_devices_failed'));
}
