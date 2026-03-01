import { Env, TokenResponse } from '../types';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { RateLimitService, getClientIdentifier } from '../services/ratelimit';
import { jsonResponse, errorResponse, identityErrorResponse } from '../utils/response';
import { LIMITS } from '../config/limits';
import { isTotpEnabled, verifyTotpToken } from '../utils/totp';
import { createRefreshToken } from '../utils/jwt';
import { readAuthRequestDeviceInfo } from '../utils/device';
import { createRecoveryCode, recoveryCodeEquals } from '../utils/recovery-code';
import { issueSendAccessToken } from './sends';

const TWO_FACTOR_REMEMBER_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const TWO_FACTOR_PROVIDER_AUTHENTICATOR = 0;
const TWO_FACTOR_PROVIDER_REMEMBER = 5;
const TWO_FACTOR_PROVIDER_RECOVERY_CODE = 8;

function resolveTotpSecret(userSecret: string | null, envSecret: string | undefined): string | null {
  if (userSecret && isTotpEnabled(userSecret)) {
    return userSecret;
  }
  if (isTotpEnabled(envSecret)) {
    return envSecret!;
  }
  return null;
}

function twoFactorRequiredResponse(message: string = 'Two factor required.', includeRecoveryCode: boolean = false): Response {
  const providers = includeRecoveryCode
    ? [String(TWO_FACTOR_PROVIDER_AUTHENTICATOR), String(TWO_FACTOR_PROVIDER_RECOVERY_CODE)]
    : [String(TWO_FACTOR_PROVIDER_AUTHENTICATOR)];
  const providers2: Record<string, null> = {};
  for (const provider of providers) providers2[provider] = null;

  // Bitwarden clients rely on these fields to trigger the 2FA UI flow.
  return jsonResponse(
    {
      error: 'invalid_grant',
      error_description: message,
      TwoFactorProviders: providers,
      TwoFactorProviders2: providers2,
      // Required by current Android parser (nullable value is acceptable).
      SsoEmail2faSessionToken: null,
      // Keep payload shape close to upstream implementations.
      MasterPasswordPolicy: {
        Object: 'masterPasswordPolicy',
      },
      ErrorModel: {
        Message: message,
        Object: 'error',
      },
    },
    400
  );
}

async function recordFailedLoginAndBuildResponse(
  rateLimit: RateLimitService,
  loginIdentifier: string,
  message: string
): Promise<Response> {
  const result = await rateLimit.recordFailedLogin(loginIdentifier);
  if (result.locked) {
    return identityErrorResponse(
      `Too many failed login attempts. Account locked for ${Math.ceil(result.retryAfterSeconds! / 60)} minutes.`,
      'TooManyRequests',
      429
    );
  }
  return identityErrorResponse(message, 'invalid_grant', 400);
}

async function recordFailedTwoFactorAndBuildResponse(
  rateLimit: RateLimitService,
  loginIdentifier: string
): Promise<Response> {
  const failed = await rateLimit.recordFailedLogin(loginIdentifier);
  if (failed.locked) {
    return identityErrorResponse(
      `Too many failed login attempts. Account locked for ${Math.ceil(failed.retryAfterSeconds! / 60)} minutes.`,
      'TooManyRequests',
      429
    );
  }
  return identityErrorResponse('Two-step token is invalid. Try again.', 'invalid_grant', 400);
}

// POST /identity/connect/token
export async function handleToken(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const rateLimit = new RateLimitService(env.DB);

  let body: Record<string, string>;
  const contentType = request.headers.get('content-type') || '';
  try {
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const formData = await request.formData();
      body = Object.fromEntries(formData.entries()) as Record<string, string>;
    } else {
      body = await request.json();
    }
  } catch {
    return identityErrorResponse('Invalid request payload', 'invalid_request', 400);
  }

  const grantType = body.grant_type;
  const clientIdentifier = getClientIdentifier(request);

  if (grantType === 'password') {
    // Login with password
    const email = body.username?.toLowerCase();
    const passwordHash = body.password;
    const twoFactorToken = body.twoFactorToken;
    const twoFactorProvider = body.twoFactorProvider;
    const twoFactorRemember = body.twoFactorRemember;
    const loginIdentifier = `${clientIdentifier}:${email}`;
    const deviceInfo = readAuthRequestDeviceInfo(body, request);

    if (!email || !passwordHash) {
      // Bitwarden clients expect OAuth-style error fields.
      return identityErrorResponse('Email and password are required', 'invalid_request', 400);
    }

    // Check login lockout before user lookup to reduce user-enumeration signal
    const loginCheck = await rateLimit.checkLoginAttempt(loginIdentifier);
    if (!loginCheck.allowed) {
      return identityErrorResponse(
        `Too many failed login attempts. Try again in ${Math.ceil(loginCheck.retryAfterSeconds! / 60)} minutes.`,
        'TooManyRequests',
        429
      );
    }

    const user = await storage.getUser(email);
    if (!user) {
      await rateLimit.recordFailedLogin(loginIdentifier);
      return identityErrorResponse('Username or password is incorrect. Try again', 'invalid_grant', 400);
    }
    if (user.status !== 'active') {
      await rateLimit.recordFailedLogin(loginIdentifier);
      return identityErrorResponse('Account is disabled', 'invalid_grant', 400);
    }

    const valid = await auth.verifyPassword(passwordHash, user.masterPasswordHash, user.email);
    if (!valid) {
      return recordFailedLoginAndBuildResponse(
        rateLimit,
        loginIdentifier,
        'Username or password is incorrect. Try again'
      );
    }

    // Optional 2FA: enabled per-user secret first, then falls back to global env secret for compatibility.
    let trustedTwoFactorTokenToReturn: string | undefined;
    const effectiveTotpSecret = resolveTotpSecret(user.totpSecret, env.TOTP_SECRET);
    if (effectiveTotpSecret) {
      const canUseRecoveryCode = !!user.totpRecoveryCode;
      const normalizedTwoFactorProvider = String(twoFactorProvider ?? '').trim();
      const normalizedTwoFactorToken = String(twoFactorToken ?? '').trim();
      let rememberRequested = ['1', 'true', 'True', 'TRUE', 'on', 'yes', 'Yes', 'YES'].includes(String(twoFactorRemember || '').trim());
      const hasProvider = normalizedTwoFactorProvider.length > 0;
      const hasToken = normalizedTwoFactorToken.length > 0;

      // Upstream-compatible behavior: if 2FA is required and either provider or token is missing,
      // respond with a 2FA challenge payload.
      if (!hasProvider || !hasToken) {
        return twoFactorRequiredResponse('Two factor required.', canUseRecoveryCode);
      }

      const parsedProvider = Number.parseInt(normalizedTwoFactorProvider, 10);
      if (!Number.isFinite(parsedProvider)) {
        return twoFactorRequiredResponse('Two factor required.', canUseRecoveryCode);
      }

      let passedByRememberToken = false;
      if (parsedProvider === TWO_FACTOR_PROVIDER_REMEMBER) {
        if (deviceInfo.deviceIdentifier) {
          const trustedUserId = await storage.getTrustedTwoFactorDeviceTokenUserId(
            normalizedTwoFactorToken,
            deviceInfo.deviceIdentifier
          );
          passedByRememberToken = trustedUserId === user.id;
        }

        // Remember token missing/invalid/expired should re-enter the 2FA challenge flow.
        if (!passedByRememberToken) {
          return twoFactorRequiredResponse('Two factor required.', canUseRecoveryCode);
        }
      } else if (parsedProvider === TWO_FACTOR_PROVIDER_AUTHENTICATOR) {
        const totpOk = await verifyTotpToken(effectiveTotpSecret, normalizedTwoFactorToken);
        if (!totpOk) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
      } else if (parsedProvider === TWO_FACTOR_PROVIDER_RECOVERY_CODE) {
        if (!recoveryCodeEquals(normalizedTwoFactorToken, user.totpRecoveryCode)) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
        user.totpSecret = null;
        user.totpRecoveryCode = createRecoveryCode();
        user.updatedAt = new Date().toISOString();
        await storage.saveUser(user);
        await storage.deleteRefreshTokensByUserId(user.id);
        rememberRequested = false;
      } else {
        // Unsupported provider for this server profile behaves as an invalid 2FA attempt.
        return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
      }

      // Upstream behavior: do not issue a new remember token when auth itself used remember provider.
      if (rememberRequested && !passedByRememberToken && deviceInfo.deviceIdentifier) {
        trustedTwoFactorTokenToReturn = createRefreshToken();
        await storage.saveTrustedTwoFactorDeviceToken(
          trustedTwoFactorTokenToReturn,
          user.id,
          deviceInfo.deviceIdentifier,
          Date.now() + TWO_FACTOR_REMEMBER_TTL_MS
        );
      }
    }

    // Persist device only after successful password + (optional) 2FA verification.
    if (deviceInfo.deviceIdentifier) {
      await storage.upsertDevice(user.id, deviceInfo.deviceIdentifier, deviceInfo.deviceName, deviceInfo.deviceType);
    }

    // Successful login - clear failed attempts
    await rateLimit.clearLoginAttempts(loginIdentifier);

    const accessToken = await auth.generateAccessToken(user);
    const refreshToken = await auth.generateRefreshToken(user.id);

    const response: TokenResponse = {
      access_token: accessToken,
      expires_in: LIMITS.auth.accessTokenTtlSeconds,
      token_type: 'Bearer',
      refresh_token: refreshToken,
      ...(trustedTwoFactorTokenToReturn ? { TwoFactorToken: trustedTwoFactorTokenToReturn } : {}),
      Key: user.key,
      PrivateKey: user.privateKey,
      Kdf: user.kdfType,
      KdfIterations: user.kdfIterations,
      KdfMemory: user.kdfMemory,
      KdfParallelism: user.kdfParallelism,
      ForcePasswordReset: false,
      ResetMasterPassword: false,
      scope: 'api offline_access',
      unofficialServer: true,
      UserDecryptionOptions: {
        HasMasterPassword: true,
        Object: 'userDecryptionOptions',
        MasterPasswordUnlock: {
          Kdf: {
            KdfType: user.kdfType,
            Iterations: user.kdfIterations,
            Memory: user.kdfMemory || null,
            Parallelism: user.kdfParallelism || null,
          },
          MasterKeyEncryptedUserKey: user.key,
          MasterKeyWrappedUserKey: user.key,
          Salt: email, // email is already lowercased above
          Object: 'masterPasswordUnlock',
        },
      },
    };

    return jsonResponse(response);

  } else if (grantType === 'send_access') {
    const sendAccessLimit = await rateLimit.consumeBudget(`${clientIdentifier}:public`, LIMITS.rateLimit.publicRequestsPerMinute);
    if (!sendAccessLimit.allowed) {
      return identityErrorResponse(
        `Rate limit exceeded. Try again in ${sendAccessLimit.retryAfterSeconds} seconds.`,
        'TooManyRequests',
        429
      );
    }

    const sendId = String(body.send_id || body.sendId || '').trim();
    if (!sendId) {
      return jsonResponse(
        {
          error: 'invalid_request',
          error_description: 'send_id is required',
          send_access_error_type: 'invalid_send_id',
          ErrorModel: {
            Message: 'send_id is required',
            Object: 'error',
          },
        },
        400
      );
    }

    const passwordHashB64 = String(
      body.password_hash_b64 || body.passwordHashB64 || body.passwordHash || body.password_hash || ''
    ).trim() || null;
    const password = String(body.password || '').trim() || null;

    const result = await issueSendAccessToken(env, sendId, passwordHashB64, password);
    if ('error' in result) {
      return result.error;
    }

    return jsonResponse({
      access_token: result.token,
      expires_in: LIMITS.auth.sendAccessTokenTtlSeconds,
      token_type: 'Bearer',
      scope: 'api.send',
      unofficialServer: true,
    });
  } else if (grantType === 'refresh_token') {
    // Refresh token
    const refreshToken = body.refresh_token;
    if (!refreshToken) {
      return identityErrorResponse('Refresh token is required', 'invalid_request', 400);
    }

    const result = await auth.refreshAccessToken(refreshToken);
    if (!result) {
      return identityErrorResponse('Invalid refresh token', 'invalid_grant', 400);
    }

    // Keep a short overlap window for old refresh token to absorb
    // concurrent refresh requests from multiple client contexts.
    await storage.constrainRefreshTokenExpiry(
      refreshToken,
      Date.now() + LIMITS.auth.refreshTokenOverlapGraceMs
    );

    const { accessToken, user } = result;
    const newRefreshToken = await auth.generateRefreshToken(user.id);

    const response: TokenResponse = {
      access_token: accessToken,
      expires_in: LIMITS.auth.accessTokenTtlSeconds,
      token_type: 'Bearer',
      refresh_token: newRefreshToken,
      Key: user.key,
      PrivateKey: user.privateKey,
      Kdf: user.kdfType,
      KdfIterations: user.kdfIterations,
      KdfMemory: user.kdfMemory,
      KdfParallelism: user.kdfParallelism,
      ForcePasswordReset: false,
      ResetMasterPassword: false,
      scope: 'api offline_access',
      unofficialServer: true,
      UserDecryptionOptions: {
        HasMasterPassword: true,
        Object: 'userDecryptionOptions',
        MasterPasswordUnlock: {
          Kdf: {
            KdfType: user.kdfType,
            Iterations: user.kdfIterations,
            Memory: user.kdfMemory || null,
            Parallelism: user.kdfParallelism || null,
          },
          MasterKeyEncryptedUserKey: user.key,
          MasterKeyWrappedUserKey: user.key,
          Salt: user.email.toLowerCase(),
          Object: 'masterPasswordUnlock',
        },
      },
    };

    return jsonResponse(response);
  }

  return identityErrorResponse('Unsupported grant type', 'unsupported_grant_type', 400);
}

// POST /identity/accounts/prelogin
export async function handlePrelogin(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { email?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const email = body.email?.toLowerCase();
  if (!email) {
    return errorResponse('Email is required', 400);
  }

  const user = await storage.getUser(email);

  // Return default KDF settings even if user doesn't exist (to prevent user enumeration)
  const kdfType = user?.kdfType ?? 0;
  const kdfIterations = user?.kdfIterations ?? LIMITS.auth.defaultKdfIterations;
  const kdfMemory = user?.kdfMemory;
  const kdfParallelism = user?.kdfParallelism;

  return jsonResponse({
    kdf: kdfType,
    kdfIterations: kdfIterations,
    kdfMemory: kdfMemory,
    kdfParallelism: kdfParallelism,
  });
}

// POST /identity/connect/revocation
// Best-effort OAuth token revocation endpoint.
// RFC 7009 allows returning 200 even if token is unknown.
export async function handleRevocation(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: Record<string, string>;
  const contentType = request.headers.get('content-type') || '';
  try {
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const formData = await request.formData();
      body = Object.fromEntries(formData.entries()) as Record<string, string>;
    } else {
      body = await request.json();
    }
  } catch {
    return new Response(null, { status: 200 });
  }

  const token = String(body.token || '').trim();
  if (token) {
    await storage.deleteRefreshToken(token);
  }

  return new Response(null, { status: 200 });
}
