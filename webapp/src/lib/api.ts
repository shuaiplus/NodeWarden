import { base64ToBytes, bytesToBase64, decryptBw, decryptBwFileData, decryptStr, encryptBw, encryptBwFileData, hkdf, hkdfExpand, pbkdf2 } from './crypto';
import type {
  AuthorizedDevice,
  AdminInvite,
  AdminUser,
  Cipher,
  Folder,
  ListResponse,
  Profile,
  SessionState,
  Send,
  SendDraft,
  SetupStatusResponse,
  TokenError,
  TokenSuccess,
  VaultDraft,
  VaultDraftField,
  WebConfigResponse,
} from './types';

const SESSION_KEY = 'nodewarden.web.session.v4';
const DEVICE_IDENTIFIER_KEY = 'nodewarden.web.device.identifier.v1';
const TOTP_REMEMBER_TOKEN_KEY = 'nodewarden.web.totp.remember-token.v1';

type SessionSetter = (next: SessionState | null) => void;

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

async function parseJson<T>(response: Response): Promise<T | null> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

export async function getSetupStatus(): Promise<SetupStatusResponse> {
  const resp = await fetch('/setup/status');
  const body = await parseJson<SetupStatusResponse>(resp);
  return { registered: !!body?.registered };
}

export async function getWebConfig(): Promise<WebConfigResponse> {
  const resp = await fetch('/api/web/config');
  return (await parseJson<WebConfigResponse>(resp)) || {};
}

export interface PreloginResult {
  hash: string;
  masterKey: Uint8Array;
  kdfIterations: number;
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
    // Remember-token login failed; force the next attempt to use real TOTP.
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
  inviteCode?: string;
  fallbackIterations: number;
}): Promise<{ ok: true } | { ok: false; message: string }> {
  try {
    const { email, name, password, inviteCode, fallbackIterations } = args;
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

export async function getProfile(authedFetch: (input: string, init?: RequestInit) => Promise<Response>): Promise<Profile> {
  const resp = await authedFetch('/api/accounts/profile');
  if (!resp.ok) throw new Error('Failed to load profile');
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

export async function getFolders(authedFetch: (input: string, init?: RequestInit) => Promise<Response>): Promise<Folder[]> {
  const resp = await authedFetch('/api/folders');
  if (!resp.ok) throw new Error('Failed to load folders');
  const body = await parseJson<ListResponse<Folder>>(resp);
  return body?.data || [];
}

export async function createFolder(
  authedFetch: (input: string, init?: RequestInit) => Promise<Response>,
  name: string
): Promise<void> {
  const resp = await authedFetch('/api/folders', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  });
  if (!resp.ok) throw new Error('Create folder failed');
}

export async function getCiphers(authedFetch: (input: string, init?: RequestInit) => Promise<Response>): Promise<Cipher[]> {
  const resp = await authedFetch('/api/ciphers?deleted=true');
  if (!resp.ok) throw new Error('Failed to load ciphers');
  const body = await parseJson<ListResponse<Cipher>>(resp);
  return body?.data || [];
}

export async function getSends(authedFetch: (input: string, init?: RequestInit) => Promise<Response>): Promise<Send[]> {
  const resp = await authedFetch('/api/sends');
  if (!resp.ok) throw new Error('Failed to load sends');
  const body = await parseJson<ListResponse<Send>>(resp);
  return body?.data || [];
}

export async function changeMasterPassword(
  authedFetch: (input: string, init?: RequestInit) => Promise<Response>,
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
  authedFetch: (input: string, init?: RequestInit) => Promise<Response>,
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
  authedFetch: (input: string, init?: RequestInit) => Promise<Response>,
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

export async function getTotpStatus(
  authedFetch: (input: string, init?: RequestInit) => Promise<Response>
): Promise<{ enabled: boolean }> {
  const resp = await authedFetch('/api/accounts/totp');
  if (!resp.ok) throw new Error('Failed to load TOTP status');
  const body = (await parseJson<{ enabled?: boolean }>(resp)) || {};
  return { enabled: !!body.enabled };
}

export async function getTotpRecoveryCode(
  authedFetch: (input: string, init?: RequestInit) => Promise<Response>,
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

export async function getAuthorizedDevices(
  authedFetch: (input: string, init?: RequestInit) => Promise<Response>
): Promise<AuthorizedDevice[]> {
  const resp = await authedFetch('/api/devices/authorized');
  if (!resp.ok) throw new Error('Failed to load authorized devices');
  const body = await parseJson<ListResponse<AuthorizedDevice>>(resp);
  return body?.data || [];
}

export async function revokeAuthorizedDeviceTrust(
  authedFetch: (input: string, init?: RequestInit) => Promise<Response>,
  deviceIdentifier: string
): Promise<void> {
  const resp = await authedFetch(`/api/devices/authorized/${encodeURIComponent(deviceIdentifier)}`, { method: 'DELETE' });
  if (!resp.ok) throw new Error('Failed to revoke device authorization');
}

export async function revokeAllAuthorizedDeviceTrust(
  authedFetch: (input: string, init?: RequestInit) => Promise<Response>
): Promise<void> {
  const resp = await authedFetch('/api/devices/authorized', { method: 'DELETE' });
  if (!resp.ok) throw new Error('Failed to revoke all authorized devices');
}

export async function deleteAuthorizedDevice(
  authedFetch: (input: string, init?: RequestInit) => Promise<Response>,
  deviceIdentifier: string
): Promise<void> {
  const resp = await authedFetch(`/api/devices/${encodeURIComponent(deviceIdentifier)}`, { method: 'DELETE' });
  if (!resp.ok) throw new Error('Failed to remove device');
}

export async function listAdminUsers(authedFetch: (input: string, init?: RequestInit) => Promise<Response>): Promise<AdminUser[]> {
  const resp = await authedFetch('/api/admin/users');
  if (!resp.ok) throw new Error('Failed to load users');
  const body = await parseJson<ListResponse<AdminUser>>(resp);
  return body?.data || [];
}

export async function listAdminInvites(authedFetch: (input: string, init?: RequestInit) => Promise<Response>): Promise<AdminInvite[]> {
  const resp = await authedFetch('/api/admin/invites?includeInactive=true');
  if (!resp.ok) throw new Error('Failed to load invites');
  const body = await parseJson<ListResponse<AdminInvite>>(resp);
  return body?.data || [];
}

export async function createInvite(authedFetch: (input: string, init?: RequestInit) => Promise<Response>, hours: number): Promise<void> {
  const resp = await authedFetch('/api/admin/invites', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ expiresInHours: hours }),
  });
  if (!resp.ok) throw new Error('Create invite failed');
}

export async function revokeInvite(authedFetch: (input: string, init?: RequestInit) => Promise<Response>, code: string): Promise<void> {
  const resp = await authedFetch(`/api/admin/invites/${encodeURIComponent(code)}`, { method: 'DELETE' });
  if (!resp.ok) throw new Error('Revoke invite failed');
}

export async function deleteAllInvites(authedFetch: (input: string, init?: RequestInit) => Promise<Response>): Promise<void> {
  const resp = await authedFetch('/api/admin/invites', { method: 'DELETE' });
  if (!resp.ok) throw new Error('Delete all invites failed');
}

export async function setUserStatus(
  authedFetch: (input: string, init?: RequestInit) => Promise<Response>,
  userId: string,
  status: 'active' | 'banned'
): Promise<void> {
  const resp = await authedFetch(`/api/admin/users/${encodeURIComponent(userId)}/status`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  });
  if (!resp.ok) throw new Error('Update user status failed');
}

export async function deleteUser(authedFetch: (input: string, init?: RequestInit) => Promise<Response>, userId: string): Promise<void> {
  const resp = await authedFetch(`/api/admin/users/${encodeURIComponent(userId)}`, { method: 'DELETE' });
  if (!resp.ok) throw new Error('Delete user failed');
}

function asNullable(v: string): string | null {
  const s = String(v || '').trim();
  return s ? s : null;
}

function parseFieldType(v: number | string): 0 | 1 | 2 | 3 {
  if (typeof v === 'number') {
    if (v === 1 || v === 2 || v === 3) return v;
    return 0;
  }
  const s = String(v).trim().toLowerCase();
  if (s === '1' || s === 'hidden') return 1;
  if (s === '2' || s === 'boolean' || s === 'checkbox') return 2;
  if (s === '3' || s === 'linked' || s === 'link') return 3;
  return 0;
}

async function encryptTextValue(value: string, enc: Uint8Array, mac: Uint8Array): Promise<string | null> {
  const s = String(value || '');
  if (!s.trim()) return null;
  return encryptBw(new TextEncoder().encode(s), enc, mac);
}

async function encryptCustomFields(fields: VaultDraftField[], enc: Uint8Array, mac: Uint8Array): Promise<Array<{ type: number; name: string | null; value: string | null }>> {
  const out: Array<{ type: number; name: string | null; value: string | null }> = [];
  for (const field of fields || []) {
    const label = String(field.label || '').trim();
    if (!label) continue;
    out.push({
      type: parseFieldType(field.type),
      name: await encryptTextValue(label, enc, mac),
      value: await encryptTextValue(String(field.value || ''), enc, mac),
    });
  }
  return out;
}

async function encryptUris(uris: string[], enc: Uint8Array, mac: Uint8Array): Promise<Array<{ uri: string | null; match: null }>> {
  const out: Array<{ uri: string | null; match: null }> = [];
  for (const uri of uris || []) {
    const trimmed = String(uri || '').trim();
    if (!trimmed) continue;
    out.push({ uri: await encryptTextValue(trimmed, enc, mac), match: null });
  }
  return out;
}

async function getCipherKeys(cipher: Cipher | null, userEnc: Uint8Array, userMac: Uint8Array): Promise<{ enc: Uint8Array; mac: Uint8Array; key: string | null }> {
  if (cipher?.key) {
    try {
      const raw = await decryptBw(cipher.key, userEnc, userMac);
      if (raw.length >= 64) return { enc: raw.slice(0, 32), mac: raw.slice(32, 64), key: cipher.key };
    } catch {
      // use user key
    }
  }
  return { enc: userEnc, mac: userMac, key: null };
}

export async function createCipher(
  authedFetch: (input: string, init?: RequestInit) => Promise<Response>,
  session: SessionState,
  draft: VaultDraft
): Promise<void> {
  if (!session.symEncKey || !session.symMacKey) throw new Error('Vault key unavailable');
  const enc = base64ToBytes(session.symEncKey);
  const mac = base64ToBytes(session.symMacKey);
  const type = Number(draft.type || 1);

  const payload: Record<string, unknown> = {
    type,
    favorite: !!draft.favorite,
    folderId: asNullable(draft.folderId),
    reprompt: draft.reprompt ? 1 : 0,
    name: await encryptTextValue(draft.name, enc, mac),
    notes: await encryptTextValue(draft.notes, enc, mac),
    login: null,
    card: null,
    identity: null,
    secureNote: null,
    sshKey: null,
    fields: await encryptCustomFields(draft.customFields || [], enc, mac),
  };

  if (type === 1) {
    payload.login = {
      username: await encryptTextValue(draft.loginUsername, enc, mac),
      password: await encryptTextValue(draft.loginPassword, enc, mac),
      totp: await encryptTextValue(draft.loginTotp, enc, mac),
      uris: await encryptUris(draft.loginUris || [], enc, mac),
    };
  } else if (type === 3) {
    payload.card = {
      cardholderName: await encryptTextValue(draft.cardholderName, enc, mac),
      number: await encryptTextValue(draft.cardNumber, enc, mac),
      brand: await encryptTextValue(draft.cardBrand, enc, mac),
      expMonth: await encryptTextValue(draft.cardExpMonth, enc, mac),
      expYear: await encryptTextValue(draft.cardExpYear, enc, mac),
      code: await encryptTextValue(draft.cardCode, enc, mac),
    };
  } else if (type === 4) {
    payload.identity = {
      title: await encryptTextValue(draft.identTitle, enc, mac),
      firstName: await encryptTextValue(draft.identFirstName, enc, mac),
      middleName: await encryptTextValue(draft.identMiddleName, enc, mac),
      lastName: await encryptTextValue(draft.identLastName, enc, mac),
      username: await encryptTextValue(draft.identUsername, enc, mac),
      company: await encryptTextValue(draft.identCompany, enc, mac),
      ssn: await encryptTextValue(draft.identSsn, enc, mac),
      passportNumber: await encryptTextValue(draft.identPassportNumber, enc, mac),
      licenseNumber: await encryptTextValue(draft.identLicenseNumber, enc, mac),
      email: await encryptTextValue(draft.identEmail, enc, mac),
      phone: await encryptTextValue(draft.identPhone, enc, mac),
      address1: await encryptTextValue(draft.identAddress1, enc, mac),
      address2: await encryptTextValue(draft.identAddress2, enc, mac),
      address3: await encryptTextValue(draft.identAddress3, enc, mac),
      city: await encryptTextValue(draft.identCity, enc, mac),
      state: await encryptTextValue(draft.identState, enc, mac),
      postalCode: await encryptTextValue(draft.identPostalCode, enc, mac),
      country: await encryptTextValue(draft.identCountry, enc, mac),
    };
  } else if (type === 5) {
    payload.sshKey = {
      privateKey: await encryptTextValue(draft.sshPrivateKey, enc, mac),
      publicKey: await encryptTextValue(draft.sshPublicKey, enc, mac),
      fingerprint: await encryptTextValue(draft.sshFingerprint, enc, mac),
    };
  } else if (type === 2) {
    payload.secureNote = { type: 0 };
  }

  const resp = await authedFetch('/api/ciphers', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) throw new Error('Create item failed');
}

export async function updateCipher(
  authedFetch: (input: string, init?: RequestInit) => Promise<Response>,
  session: SessionState,
  cipher: Cipher,
  draft: VaultDraft
): Promise<void> {
  if (!session.symEncKey || !session.symMacKey) throw new Error('Vault key unavailable');
  const userEnc = base64ToBytes(session.symEncKey);
  const userMac = base64ToBytes(session.symMacKey);
  const keys = await getCipherKeys(cipher, userEnc, userMac);
  const type = Number(draft.type || cipher.type || 1);

  const payload: Record<string, unknown> = {
    id: cipher.id,
    type,
    key: keys.key,
    folderId: asNullable(draft.folderId),
    favorite: !!draft.favorite,
    reprompt: draft.reprompt ? 1 : 0,
    name: await encryptTextValue(draft.name, keys.enc, keys.mac),
    notes: await encryptTextValue(draft.notes, keys.enc, keys.mac),
    login: null,
    card: null,
    identity: null,
    secureNote: null,
    sshKey: null,
    fields: await encryptCustomFields(draft.customFields || [], keys.enc, keys.mac),
  };

  if (type === 1) {
    payload.login = {
      username: await encryptTextValue(draft.loginUsername, keys.enc, keys.mac),
      password: await encryptTextValue(draft.loginPassword, keys.enc, keys.mac),
      totp: await encryptTextValue(draft.loginTotp, keys.enc, keys.mac),
      uris: await encryptUris(draft.loginUris || [], keys.enc, keys.mac),
    };
  } else if (type === 3) {
    payload.card = {
      cardholderName: await encryptTextValue(draft.cardholderName, keys.enc, keys.mac),
      number: await encryptTextValue(draft.cardNumber, keys.enc, keys.mac),
      brand: await encryptTextValue(draft.cardBrand, keys.enc, keys.mac),
      expMonth: await encryptTextValue(draft.cardExpMonth, keys.enc, keys.mac),
      expYear: await encryptTextValue(draft.cardExpYear, keys.enc, keys.mac),
      code: await encryptTextValue(draft.cardCode, keys.enc, keys.mac),
    };
  } else if (type === 4) {
    payload.identity = {
      title: await encryptTextValue(draft.identTitle, keys.enc, keys.mac),
      firstName: await encryptTextValue(draft.identFirstName, keys.enc, keys.mac),
      middleName: await encryptTextValue(draft.identMiddleName, keys.enc, keys.mac),
      lastName: await encryptTextValue(draft.identLastName, keys.enc, keys.mac),
      username: await encryptTextValue(draft.identUsername, keys.enc, keys.mac),
      company: await encryptTextValue(draft.identCompany, keys.enc, keys.mac),
      ssn: await encryptTextValue(draft.identSsn, keys.enc, keys.mac),
      passportNumber: await encryptTextValue(draft.identPassportNumber, keys.enc, keys.mac),
      licenseNumber: await encryptTextValue(draft.identLicenseNumber, keys.enc, keys.mac),
      email: await encryptTextValue(draft.identEmail, keys.enc, keys.mac),
      phone: await encryptTextValue(draft.identPhone, keys.enc, keys.mac),
      address1: await encryptTextValue(draft.identAddress1, keys.enc, keys.mac),
      address2: await encryptTextValue(draft.identAddress2, keys.enc, keys.mac),
      address3: await encryptTextValue(draft.identAddress3, keys.enc, keys.mac),
      city: await encryptTextValue(draft.identCity, keys.enc, keys.mac),
      state: await encryptTextValue(draft.identState, keys.enc, keys.mac),
      postalCode: await encryptTextValue(draft.identPostalCode, keys.enc, keys.mac),
      country: await encryptTextValue(draft.identCountry, keys.enc, keys.mac),
    };
  } else if (type === 5) {
    payload.sshKey = {
      privateKey: await encryptTextValue(draft.sshPrivateKey, keys.enc, keys.mac),
      publicKey: await encryptTextValue(draft.sshPublicKey, keys.enc, keys.mac),
      fingerprint: await encryptTextValue(draft.sshFingerprint, keys.enc, keys.mac),
    };
  } else if (type === 2) {
    payload.secureNote = { type: 0 };
  }

  const resp = await authedFetch(`/api/ciphers/${encodeURIComponent(cipher.id)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) throw new Error('Update item failed');
}

export async function deleteCipher(
  authedFetch: (input: string, init?: RequestInit) => Promise<Response>,
  cipherId: string
): Promise<void> {
  const resp = await authedFetch(`/api/ciphers/${encodeURIComponent(cipherId)}`, { method: 'DELETE' });
  if (!resp.ok) throw new Error('Delete item failed');
}

export async function bulkMoveCiphers(
  authedFetch: (input: string, init?: RequestInit) => Promise<Response>,
  ids: string[],
  folderId: string | null
): Promise<void> {
  const resp = await authedFetch('/api/ciphers/move', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ids, folderId }),
  });
  if (!resp.ok) throw new Error('Bulk move failed');
}

function toIsoDateFromDays(value: string, required: boolean): string | null {
  const raw = String(value || '').trim();
  if (!raw) {
    if (required) throw new Error('Deletion days is required');
    return null;
  }
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) {
    if (required) throw new Error('Invalid deletion days');
    throw new Error('Invalid expiration days');
  }
  if (!required && n === 0) return null;
  const date = new Date(Date.now() + Math.floor(n) * 24 * 60 * 60 * 1000);
  return date.toISOString();
}

function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlToBytes(value: string): Uint8Array {
  const raw = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = raw + '='.repeat((4 - (raw.length % 4)) % 4);
  return base64ToBytes(padded);
}

const SEND_KEY_SALT = 'bitwarden-send';
const SEND_KEY_PURPOSE = 'send';
const SEND_KEY_SEED_BYTES = 16;
const SEND_PASSWORD_ITERATIONS = 100000;

async function parseErrorMessage(resp: Response, fallback: string): Promise<string> {
  const body = await parseJson<TokenError>(resp);
  return body?.error_description || body?.error || fallback;
}

async function toSendKeyParts(sendKeyMaterial: Uint8Array): Promise<{ enc: Uint8Array; mac: Uint8Array }> {
  // Legacy compatibility: early NodeWarden builds stored a full 64-byte key material.
  if (sendKeyMaterial.length >= 64) {
    return { enc: sendKeyMaterial.slice(0, 32), mac: sendKeyMaterial.slice(32, 64) };
  }
  // Official behavior: send URL key is seed material; derive 64-byte key via HKDF.
  const derived = await hkdf(sendKeyMaterial, SEND_KEY_SALT, SEND_KEY_PURPOSE, 64);
  return { enc: derived.slice(0, 32), mac: derived.slice(32, 64) };
}

async function hashSendPasswordB64(password: string, sendKeyMaterial: Uint8Array): Promise<string> {
  const hash = await pbkdf2(password, sendKeyMaterial, SEND_PASSWORD_ITERATIONS, 32);
  return bytesToBase64(hash);
}

function parseMaxAccessCountRaw(value: string): number | null {
  const raw = String(value || '').trim();
  if (!raw) return null;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) throw new Error('Invalid max access count');
  return Math.floor(n);
}

export async function createSend(
  authedFetch: (input: string, init?: RequestInit) => Promise<Response>,
  session: SessionState,
  draft: SendDraft
): Promise<Send> {
  if (!session.symEncKey || !session.symMacKey) throw new Error('Vault key unavailable');
  const userEnc = base64ToBytes(session.symEncKey);
  const userMac = base64ToBytes(session.symMacKey);
  const sendKeyMaterial = crypto.getRandomValues(new Uint8Array(SEND_KEY_SEED_BYTES));
  const sendKeyForUser = await encryptBw(sendKeyMaterial, userEnc, userMac);
  const sendKey = await toSendKeyParts(sendKeyMaterial);
  const nameCipher = await encryptTextValue(draft.name || '', sendKey.enc, sendKey.mac);
  const notesCipher = await encryptTextValue(draft.notes || '', sendKey.enc, sendKey.mac);

  const deletionIso = toIsoDateFromDays(draft.deletionDays, true)!;
  const expirationIso = toIsoDateFromDays(draft.expirationDays, false);
  const maxAccessCount = parseMaxAccessCountRaw(draft.maxAccessCount);
  const password = String(draft.password || '');
  const passwordHash = password ? await hashSendPasswordB64(password, sendKeyMaterial) : null;

  if (draft.type === 'text') {
    const text = String(draft.text || '').trim();
    if (!text) throw new Error('Send text is required');
    const textCipher = await encryptTextValue(text, sendKey.enc, sendKey.mac);

    const payload = {
      type: 0,
      name: nameCipher,
      notes: notesCipher,
      key: sendKeyForUser,
      text: {
        text: textCipher,
        hidden: false,
      },
      maxAccessCount,
      password: passwordHash,
      hideEmail: false,
      disabled: !!draft.disabled,
      deletionDate: deletionIso,
      expirationDate: expirationIso,
    };

    const resp = await authedFetch('/api/sends', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Create send failed'));
    const body = await parseJson<Send>(resp);
    if (!body?.id) throw new Error('Create send failed');
    return body;
  }

  if (!draft.file) throw new Error('File is required');
  const fileNameCipher = await encryptTextValue(draft.file.name, sendKey.enc, sendKey.mac);
  if (!fileNameCipher) throw new Error('Invalid file name');
  const plainFileBytes = new Uint8Array(await draft.file.arrayBuffer());
  const encryptedFileBytes = await encryptBwFileData(plainFileBytes, sendKey.enc, sendKey.mac);

  const fileResp = await authedFetch('/api/sends/file/v2', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      type: 1,
      name: nameCipher,
      notes: notesCipher,
      key: sendKeyForUser,
      file: {
        fileName: fileNameCipher,
      },
      fileLength: encryptedFileBytes.byteLength,
      maxAccessCount,
      password: passwordHash,
      hideEmail: false,
      disabled: !!draft.disabled,
      deletionDate: deletionIso,
      expirationDate: expirationIso,
    }),
  });
  if (!fileResp.ok) throw new Error(await parseErrorMessage(fileResp, 'Create file send failed'));

  const uploadInfo = await parseJson<{ url?: string; sendResponse?: Send }>(fileResp);
  const uploadUrl = uploadInfo?.url;
  if (!uploadUrl) throw new Error('Create file send failed: missing upload URL');

  const formData = new FormData();
  const encryptedBlob = new Blob([encryptedFileBytes as unknown as BlobPart], { type: 'application/octet-stream' });
  formData.set('data', encryptedBlob, fileNameCipher);
  const uploadResp = await authedFetch(uploadUrl, {
    method: 'POST',
    body: formData,
  });
  if (!uploadResp.ok) throw new Error(await parseErrorMessage(uploadResp, 'Upload send file failed'));
  if (!uploadInfo?.sendResponse?.id) throw new Error('Create file send failed');
  return uploadInfo.sendResponse;
}

export async function updateSend(
  authedFetch: (input: string, init?: RequestInit) => Promise<Response>,
  session: SessionState,
  send: Send,
  draft: SendDraft
): Promise<Send> {
  if (!session.symEncKey || !session.symMacKey) throw new Error('Vault key unavailable');
  if (!send.key) throw new Error('Send key unavailable');
  const userEnc = base64ToBytes(session.symEncKey);
  const userMac = base64ToBytes(session.symMacKey);
  const sendKeyMaterial = await decryptBw(send.key, userEnc, userMac);
  const sendKey = await toSendKeyParts(sendKeyMaterial);
  const nameCipher = await encryptTextValue(draft.name || '', sendKey.enc, sendKey.mac);
  const notesCipher = await encryptTextValue(draft.notes || '', sendKey.enc, sendKey.mac);

  const deletionIso = toIsoDateFromDays(draft.deletionDays, true)!;
  const expirationIso = toIsoDateFromDays(draft.expirationDays, false);
  const maxAccessCount = parseMaxAccessCountRaw(draft.maxAccessCount);

  if (draft.type === 'file' && draft.file) {
    throw new Error('Updating file content is not supported yet');
  }

  const textCipher = await encryptTextValue(String(draft.text || ''), sendKey.enc, sendKey.mac);

  const passwordRaw = String(draft.password || '');
  const passwordHash = passwordRaw ? await hashSendPasswordB64(passwordRaw, sendKeyMaterial) : null;

  const payload = {
    id: send.id,
    type: draft.type === 'file' ? 1 : 0,
    name: nameCipher,
    notes: notesCipher,
    key: send.key,
    text: {
      text: textCipher,
      hidden: false,
    },
    maxAccessCount,
    password: passwordHash,
    hideEmail: false,
    disabled: !!draft.disabled,
    deletionDate: deletionIso,
    expirationDate: expirationIso,
  };

  const resp = await authedFetch(`/api/sends/${encodeURIComponent(send.id)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Update send failed'));
  const body = await parseJson<Send>(resp);
  if (!body?.id) throw new Error('Update send failed');
  return body;
}

export async function deleteSend(
  authedFetch: (input: string, init?: RequestInit) => Promise<Response>,
  sendId: string
): Promise<void> {
  const resp = await authedFetch(`/api/sends/${encodeURIComponent(sendId)}`, { method: 'DELETE' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Delete send failed'));
}

async function buildPublicSendAccessPayload(password?: string, keyPart?: string | null): Promise<Record<string, unknown>> {
  const payload: Record<string, unknown> = {};
  const plainPassword = String(password || '').trim();
  if (!plainPassword) return payload;
  payload.password = plainPassword;

  // Official clients send a PBKDF2 hash bound to send key material.
  if (keyPart) {
    try {
      const sendKeyMaterial = base64UrlToBytes(keyPart);
      const passwordHashB64 = await hashSendPasswordB64(plainPassword, sendKeyMaterial);
      payload.passwordHash = passwordHashB64;
      payload.password_hash_b64 = passwordHashB64;
      payload.passwordHashB64 = passwordHashB64;
    } catch {
      // Fallback to plain password for legacy compatibility.
    }
  }
  return payload;
}

export async function accessPublicSend(accessId: string, keyPart?: string | null, password?: string): Promise<any> {
  const payload = await buildPublicSendAccessPayload(password, keyPart);
  const resp = await fetch(`/api/sends/access/${encodeURIComponent(accessId)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) {
    const message = await parseErrorMessage(resp, 'Failed to access send');
    const error = new Error(message) as Error & { status?: number };
    error.status = resp.status;
    throw error;
  }
  return (await parseJson<any>(resp)) || null;
}

export async function accessPublicSendFile(sendId: string, fileId: string, keyPart?: string | null, password?: string): Promise<string> {
  const payload = await buildPublicSendAccessPayload(password, keyPart);
  const resp = await fetch(`/api/sends/${encodeURIComponent(sendId)}/access/file/${encodeURIComponent(fileId)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) {
    const message = await parseErrorMessage(resp, 'Failed to access send file');
    const error = new Error(message) as Error & { status?: number };
    error.status = resp.status;
    throw error;
  }
  const body = await parseJson<{ url?: string }>(resp);
  if (!body?.url) throw new Error('Missing file URL');
  return body.url;
}

export async function decryptPublicSend(accessData: any, urlSafeKey: string): Promise<any> {
  const sendKeyMaterial = base64UrlToBytes(urlSafeKey);
  const sendKey = await toSendKeyParts(sendKeyMaterial);
  const out: any = { ...accessData };
  out.decName = await decryptStr(accessData?.name || '', sendKey.enc, sendKey.mac);
  if (accessData?.text?.text) {
    out.decText = await decryptStr(accessData.text.text, sendKey.enc, sendKey.mac);
  }
  if (accessData?.file?.fileName) {
    try {
      out.decFileName = await decryptStr(accessData.file.fileName, sendKey.enc, sendKey.mac);
    } catch {
      out.decFileName = String(accessData.file.fileName);
    }
  }
  return out;
}

export async function decryptPublicSendFileBytes(
  encryptedBytes: ArrayBuffer | Uint8Array,
  urlSafeKey: string
): Promise<Uint8Array> {
  const sendKeyMaterial = base64UrlToBytes(urlSafeKey);
  const sendKey = await toSendKeyParts(sendKeyMaterial);
  const encrypted = encryptedBytes instanceof Uint8Array ? encryptedBytes : new Uint8Array(encryptedBytes);
  return decryptBwFileData(encrypted, sendKey.enc, sendKey.mac);
}

export function buildSendShareKey(sendKeyEncrypted: string, userEncB64: string, userMacB64: string): Promise<string> {
  const userEnc = base64ToBytes(userEncB64);
  const userMac = base64ToBytes(userMacB64);
  return decryptBw(sendKeyEncrypted, userEnc, userMac).then((keyMaterial) => bytesToBase64Url(keyMaterial));
}
