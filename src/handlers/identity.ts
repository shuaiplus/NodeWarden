import { Env, TokenResponse } from '../types';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { RateLimitService, getClientIdentifier } from '../services/ratelimit';
import { jsonResponse, errorResponse, identityErrorResponse } from '../utils/response';
import { LIMITS } from '../config/limits';
import { isTotpEnabled, verifyTotpToken } from '../utils/totp';
import { createRefreshToken } from '../utils/jwt';
import { readAuthRequestDeviceInfo } from '../utils/device';

const TWO_FACTOR_REMEMBER_TTL_MS = 30 * 24 * 60 * 60 * 1000;

function twoFactorRequiredResponse(message: string = 'Two factor required.'): Response {
  // Bitwarden clients rely on these fields to trigger the 2FA UI flow.
  return jsonResponse(
    {
      error: 'invalid_grant',
      error_description: message,
      TwoFactorProviders: [0],
      TwoFactorProviders2: {
        '0': {
          Priority: 1,
        },
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

  if (grantType === 'password') {
    // Login with password
    const email = body.username?.toLowerCase();
    const passwordHash = body.password;
    const twoFactorToken = body.twoFactorToken;
    const twoFactorProvider = body.twoFactorProvider;
    const twoFactorRemember = body.twoFactorRemember;
    const loginIdentifier = getClientIdentifier(request);
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

    const valid = await auth.verifyPassword(passwordHash, user.masterPasswordHash);
    if (!valid) {
      return recordFailedLoginAndBuildResponse(
        rateLimit,
        loginIdentifier,
        'Username or password is incorrect. Try again'
      );
    }

    if (deviceInfo.deviceIdentifier) {
      await storage.upsertDevice(user.id, deviceInfo.deviceIdentifier, deviceInfo.deviceName, deviceInfo.deviceType);
    }

    // Optional 2FA: enabled only when TOTP_SECRET is configured in Workers env.
    let trustedTwoFactorTokenToReturn: string | undefined;
    if (isTotpEnabled(env.TOTP_SECRET)) {
      const rememberRequested = ['1', 'true', 'True', 'TRUE', 'on', 'yes', 'Yes', 'YES'].includes(String(twoFactorRemember || '').trim());

      // Bitwarden may reuse twoFactorToken as a remembered-device token on subsequent logins.
      let passedByRememberToken = false;
      if (twoFactorToken && !/^\d{6}$/.test(twoFactorToken) && deviceInfo.deviceIdentifier) {
        const trustedUserId = await storage.getTrustedTwoFactorDeviceTokenUserId(
          twoFactorToken,
          deviceInfo.deviceIdentifier
        );
        passedByRememberToken = trustedUserId === user.id;
      }

      if (!passedByRememberToken && !twoFactorToken) {
        return twoFactorRequiredResponse();
      }

      if (!passedByRememberToken) {
        const totpOk = await verifyTotpToken(env.TOTP_SECRET!, twoFactorToken);
        if (!totpOk) {
          const failed = await rateLimit.recordFailedLogin(loginIdentifier);
          if (failed.locked) {
            return identityErrorResponse(
              `Too many failed login attempts. Account locked for ${Math.ceil(failed.retryAfterSeconds! / 60)} minutes.`,
              'TooManyRequests',
              429
            );
          }
          return identityErrorResponse('Invalid two-factor token', 'invalid_grant', 400);
        }
      }

      if (rememberRequested && deviceInfo.deviceIdentifier) {
        trustedTwoFactorTokenToReturn = createRefreshToken();
        await storage.saveTrustedTwoFactorDeviceToken(
          trustedTwoFactorTokenToReturn,
          user.id,
          deviceInfo.deviceIdentifier,
          Date.now() + TWO_FACTOR_REMEMBER_TTL_MS
        );
      }
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

    // Revoke old refresh token (prevent reuse)
    await storage.deleteRefreshToken(refreshToken);

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
