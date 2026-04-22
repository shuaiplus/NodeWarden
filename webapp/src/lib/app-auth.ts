import {
  createAuthedFetch,
  deriveLoginHashLocally,
  getProfile,
  loadProfileSnapshot,
  loadSession,
  loginWithPassword,
  refreshAccessToken,
  recoverTwoFactor,
  registerAccount,
  unlockVaultKey,
} from './api/auth';
import type { AppPhase, PendingTwoFactor, Profile, SessionState, TokenSuccess, TwoFactorProvider, WebBootstrapResponse } from './types';

function readInviteCodeFromUrl(): string {
  if (typeof window === 'undefined') return '';

  const searchInvite = new URLSearchParams(window.location.search || '').get('invite');
  if (searchInvite && searchInvite.trim()) return searchInvite.trim();

  const rawHash = String(window.location.hash || '');
  const queryIndex = rawHash.indexOf('?');
  if (queryIndex >= 0) {
    const hashInvite = new URLSearchParams(rawHash.slice(queryIndex + 1)).get('invite');
    if (hashInvite && hashInvite.trim()) return hashInvite.trim();
  }

  return '';
}

export type JwtUnsafeReason = 'missing' | 'default' | 'too_short';

export interface BootstrapAppResult {
  defaultKdfIterations: number;
  jwtWarning: { reason: JwtUnsafeReason; minLength: number } | null;
  yubikeyOtpConfigured: boolean;
  session: SessionState | null;
  profile: Profile | null;
  phase: AppPhase;
  needsBackgroundHydration?: boolean;
}

export interface InitialAppBootstrapState {
  defaultKdfIterations: number;
  jwtWarning: { reason: JwtUnsafeReason; minLength: number } | null;
  yubikeyOtpConfigured: boolean;
  session: SessionState | null;
  phase: AppPhase;
}

export interface CompletedLogin {
  session: SessionState;
  profile: Profile;
  profilePromise: Promise<Profile>;
}

export type PasswordLoginResult =
  | { kind: 'success'; login: CompletedLogin }
  | { kind: 'twoFactor'; pendingTwoFactor: PendingTwoFactor }
  | { kind: 'error'; message: string };

export interface RecoverTwoFactorResult {
  login: CompletedLogin | null;
  newRecoveryCode: string | null;
}

function decodeJwtExp(accessToken: string | undefined): number | null {
  try {
    if (!accessToken) return null;
    const parts = accessToken.split('.');
    if (parts.length < 2) return null;
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = payload.padEnd(Math.ceil(payload.length / 4) * 4, '=');
    const json = JSON.parse(atob(padded)) as { exp?: unknown };
    const exp = Number(json.exp);
    return Number.isFinite(exp) ? exp : null;
  } catch {
    return null;
  }
}

async function maybeRefreshSession(session: SessionState): Promise<SessionState | null> {
  if (!session.refreshToken && session.authMode !== 'web-cookie') return session.accessToken ? session : null;
  const exp = decodeJwtExp(session.accessToken);
  const nowSeconds = Math.floor(Date.now() / 1000);

  if (session.accessToken && exp !== null && exp - nowSeconds > 60) {
    return session;
  }

  const refreshed = await refreshAccessToken(session);
  if (!refreshed.ok) {
    return session.accessToken && exp !== null && exp > nowSeconds ? session : null;
  }

  return {
    ...session,
    accessToken: refreshed.token.access_token,
    refreshToken: refreshed.token.refresh_token || session.refreshToken,
    authMode: refreshed.token.web_session ? 'web-cookie' : (session.authMode || 'token'),
  };
}

function readWindowBootstrap(): WebBootstrapResponse {
  if (typeof window === 'undefined') return {};
  const raw = (window as Window & { __NW_BOOT__?: WebBootstrapResponse }).__NW_BOOT__;
  return raw && typeof raw === 'object' ? raw : {};
}

function normalizeBootstrapResponse(
  boot: WebBootstrapResponse
): Pick<InitialAppBootstrapState, 'defaultKdfIterations' | 'jwtWarning' | 'yubikeyOtpConfigured'> {
  const defaultKdfIterations = Number(boot.defaultKdfIterations || 600000);
  const jwtUnsafeReason = boot.jwtUnsafeReason || null;
  const jwtWarning = jwtUnsafeReason
    ? {
        reason: jwtUnsafeReason,
        minLength: Number(boot.jwtSecretMinLength || 32),
      }
    : null;

  return {
    defaultKdfIterations,
    jwtWarning,
    yubikeyOtpConfigured: !!boot.yubikeyOtpConfigured,
  };
}

async function fetchBootstrapConfig(): Promise<WebBootstrapResponse> {
  try {
    const resp = await fetch('/api/web-bootstrap', {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!resp.ok) return {};
    return ((await resp.json()) as WebBootstrapResponse) || {};
  } catch {
    return {};
  }
}

interface AccessTokenClaims {
  sub?: string;
  email?: string;
  name?: string | null;
  premium?: boolean;
}

function decodeAccessTokenClaims(accessToken: string): AccessTokenClaims {
  try {
    const parts = accessToken.split('.');
    if (parts.length < 2) return {};
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = payload.padEnd(Math.ceil(payload.length / 4) * 4, '=');
    return (JSON.parse(atob(padded)) as AccessTokenClaims) || {};
  } catch {
    return {};
  }
}

function buildTransientProfile(token: TokenSuccess, email: string): Profile {
  const claims = decodeAccessTokenClaims(token.access_token);
  const normalizedEmail = String(claims.email || email || '').trim().toLowerCase();
  const accountKeys = token.accountKeys ?? token.AccountKeys ?? null;
  return {
    id: String(claims.sub || ''),
    email: normalizedEmail,
    name: String(claims.name || normalizedEmail || ''),
    key: String(token.Key || ''),
    privateKey: token.PrivateKey ?? null,
    role: 'user',
    premium: !!claims.premium,
    accountKeys,
    object: 'profile',
  };
}

export function readInitialAppBootstrapState(): InitialAppBootstrapState {
  const { defaultKdfIterations, jwtWarning, yubikeyOtpConfigured } = normalizeBootstrapResponse(readWindowBootstrap());
  const session = loadSession();
  const hasInviteCode = !!readInviteCodeFromUrl();

  return {
    defaultKdfIterations,
    jwtWarning,
    yubikeyOtpConfigured,
    session,
    phase: jwtWarning ? 'login' : session ? 'locked' : hasInviteCode ? 'register' : 'login',
  };
}

export async function bootstrapAppSession(initial: InitialAppBootstrapState): Promise<BootstrapAppResult> {
  const remoteBoot = await fetchBootstrapConfig();
  const normalizedBoot = normalizeBootstrapResponse(remoteBoot);
  const defaultKdfIterations = normalizedBoot.defaultKdfIterations || initial.defaultKdfIterations;
  const jwtWarning = normalizedBoot.jwtWarning ?? initial.jwtWarning;
  const yubikeyOtpConfigured = normalizedBoot.yubikeyOtpConfigured ?? initial.yubikeyOtpConfigured;

  if (jwtWarning) {
    return {
      defaultKdfIterations,
      jwtWarning,
      yubikeyOtpConfigured,
      session: null,
      profile: null,
      phase: 'login',
    };
  }

  const loaded = initial.session;
  if (!loaded) {
    return {
      defaultKdfIterations,
      jwtWarning: null,
      yubikeyOtpConfigured,
      session: null,
      profile: null,
      phase: initial.phase,
    };
  }

  const cachedProfile = loadProfileSnapshot(loaded.email);
  if (cachedProfile) {
    return {
      defaultKdfIterations,
      jwtWarning: null,
      yubikeyOtpConfigured,
      session: loaded,
      profile: cachedProfile,
      phase: 'locked',
      needsBackgroundHydration: true,
    };
  }

  return {
    defaultKdfIterations,
    jwtWarning: null,
    yubikeyOtpConfigured,
    session: loaded,
    profile: null,
    phase: 'locked',
    needsBackgroundHydration: true,
  };
}

export async function hydrateLockedSession(
  session: SessionState,
  fallbackProfile: Profile | null = null
): Promise<{ session: SessionState | null; profile: Profile | null }> {
  const refreshedSession = await maybeRefreshSession(session);
  if (!refreshedSession?.accessToken) {
    return { session: null, profile: null };
  }
  try {
    const profile = await getProfile(
      createAuthedFetch(
        () => refreshedSession,
        () => {}
      )
    );
    return {
      session: refreshedSession,
      profile,
    };
  } catch {
    return {
      session: refreshedSession,
      profile: fallbackProfile,
    };
  }
}

export async function completeLogin(
  token: TokenSuccess,
  email: string,
  masterKey: Uint8Array
): Promise<CompletedLogin> {
  const normalizedEmail = email.trim().toLowerCase();
  const baseSession: SessionState = {
    accessToken: token.access_token,
    refreshToken: token.refresh_token,
    email: normalizedEmail,
    authMode: token.web_session ? 'web-cookie' : 'token',
  };
  const tempFetch = createAuthedFetch(
    () => baseSession,
    () => {}
  );
  const profile = buildTransientProfile(token, normalizedEmail);
  if (!profile.key) {
    throw new Error('Missing profile key');
  }
  const keys = await unlockVaultKey(profile.key, masterKey);
  return {
    session: { ...baseSession, ...keys },
    profile,
    profilePromise: getProfile(tempFetch),
  };
}

export function parseTwoFactorChallenge(raw: {
  TwoFactorProviders?: unknown;
  TwoFactorProviders2?: unknown;
}): Pick<PendingTwoFactor, 'availableProviders' | 'preferredProvider' | 'providerData'> {
  const availableProviders = Array.isArray(raw.TwoFactorProviders)
    ? Array.from(
        new Set(
          raw.TwoFactorProviders
            .map((value) => String(value || '').trim())
            .filter((value): value is TwoFactorProvider => value === '0' || value === '3')
        )
      )
    : [];

  const providerData =
    raw.TwoFactorProviders2 && typeof raw.TwoFactorProviders2 === 'object'
      ? (raw.TwoFactorProviders2 as Partial<Record<TwoFactorProvider, unknown | null>>)
      : {};

  return {
    availableProviders,
    preferredProvider: availableProviders.includes('0') ? '0' : '3',
    providerData,
  };
}

export async function performPasswordLogin(
  email: string,
  password: string,
  fallbackIterations: number
): Promise<PasswordLoginResult> {
  const normalizedEmail = email.trim().toLowerCase();
  const derived = await deriveLoginHashLocally(normalizedEmail, password, fallbackIterations);
  const token = await loginWithPassword(normalizedEmail, derived.hash, { useRememberToken: true });

  if ('access_token' in token && token.access_token) {
    return {
      kind: 'success',
      login: await completeLogin(token, normalizedEmail, derived.masterKey),
    };
  }

  const tokenError = token as { TwoFactorProviders?: unknown; TwoFactorProviders2?: unknown; error_description?: string; error?: string };
  if (tokenError.TwoFactorProviders) {
    const challenge = parseTwoFactorChallenge({
      TwoFactorProviders: tokenError.TwoFactorProviders,
      TwoFactorProviders2: tokenError.TwoFactorProviders2,
    });
    return {
      kind: 'twoFactor',
      pendingTwoFactor: {
        email: normalizedEmail,
        passwordHash: derived.hash,
        masterKey: derived.masterKey,
        ...challenge,
      },
    };
  }

  return {
    kind: 'error',
    message: tokenError.error_description || tokenError.error || 'Login failed',
  };
}

export async function performTwoFactorLogin(
  pendingTwoFactor: PendingTwoFactor,
  twoFactorToken: string,
  rememberDevice: boolean,
  provider?: TwoFactorProvider
): Promise<CompletedLogin> {
  const effectiveProvider = provider || pendingTwoFactor.preferredProvider;
  const token = await loginWithPassword(pendingTwoFactor.email, pendingTwoFactor.passwordHash, {
    twoFactorProvider: effectiveProvider,
    twoFactorToken: twoFactorToken.trim(),
    rememberDevice,
  });
  if ('access_token' in token && token.access_token) {
    return completeLogin(token, pendingTwoFactor.email, pendingTwoFactor.masterKey);
  }
  const tokenError = token as { error_description?: string; error?: string };
  const fallbackMessage = effectiveProvider === '3' ? 'Two-factor verify failed' : 'TOTP verify failed';
  throw new Error(tokenError.error_description || tokenError.error || fallbackMessage);
}

export async function performRecoverTwoFactorLogin(
  email: string,
  password: string,
  recoveryCode: string,
  fallbackIterations: number
): Promise<RecoverTwoFactorResult> {
  const normalizedEmail = email.trim().toLowerCase();
  const derived = await deriveLoginHashLocally(normalizedEmail, password, fallbackIterations);
  const recovered = await recoverTwoFactor(normalizedEmail, derived.hash, recoveryCode.trim());
  const token = await loginWithPassword(normalizedEmail, derived.hash, { useRememberToken: false });

  if ('access_token' in token && token.access_token) {
    return {
      login: await completeLogin(token, normalizedEmail, derived.masterKey),
      newRecoveryCode: recovered.newRecoveryCode || null,
    };
  }

  return {
    login: null,
    newRecoveryCode: recovered.newRecoveryCode || null,
  };
}

export async function performRegistration(args: {
  email: string;
  name: string;
  password: string;
  masterPasswordHint: string;
  inviteCode: string;
  fallbackIterations: number;
}) {
  return registerAccount({
    email: args.email.trim().toLowerCase(),
    name: args.name.trim(),
    password: args.password,
    masterPasswordHint: args.masterPasswordHint.trim(),
    inviteCode: args.inviteCode.trim(),
    fallbackIterations: args.fallbackIterations,
  });
}

export async function performUnlock(
  session: SessionState,
  profile: Profile,
  password: string,
  fallbackIterations: number
): Promise<SessionState> {
  const derived = await deriveLoginHashLocally(profile.email || session.email, password, fallbackIterations);
  const keys = await unlockVaultKey(profile.key, derived.masterKey);
  const refreshedSession = await maybeRefreshSession(session);
  if (!refreshedSession) {
    throw new Error('Session expired');
  }
  return { ...refreshedSession, ...keys };
}
