import { DEFAULT_DEV_SECRET, Env } from './types';
import { AuthService } from './services/auth';
import { RateLimitService, getClientIdentifier } from './services/ratelimit';
import { handleCors, errorResponse } from './utils/response';
import { LIMITS } from './config/limits';
import { handleAuthenticatedRoute } from './router-authenticated';
import { handlePublicRoute } from './router-public';

function jwtSecretUnsafeReason(env: Env): 'missing' | 'default' | 'too_short' | null {
  const secret = (env.JWT_SECRET || '').trim();
  if (!secret) return 'missing';
  if (secret === DEFAULT_DEV_SECRET) return 'default';
  if (secret.length < LIMITS.auth.jwtSecretMinLength) return 'too_short';
  return null;
}

function isImportBypassRequest(request: Request, path: string, method: string): boolean {
  if (request.headers.get('X-NodeWarden-Import') !== '1') return false;

  if (method === 'POST') {
    if (path === '/api/ciphers/import') return true;
    if (/^\/api\/ciphers\/[a-f0-9-]+\/attachment\/v2$/i.test(path)) return true;
    if (/^\/api\/ciphers\/[a-f0-9-]+\/attachment\/[a-f0-9-]+$/i.test(path)) return true;
  }

  return false;
}

export async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const clientId = getClientIdentifier(request);

  async function enforcePublicRateLimit(
    category: string = 'public',
    maxRequests: number = LIMITS.rateLimit.publicRequestsPerMinute
  ): Promise<Response | null> {
    if (!clientId) {
      return new Response(
        JSON.stringify({
          error: 'Forbidden',
          error_description: 'Client IP is required',
        }),
        {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    const rateLimit = new RateLimitService(env.DB);
    const check = await rateLimit.consumeBudget(`${clientId}:${category}`, maxRequests);
    if (check.allowed) return null;

    return new Response(
      JSON.stringify({
        error: 'Too many requests',
        error_description: `Rate limit exceeded. Try again in ${check.retryAfterSeconds} seconds.`,
      }),
      {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(check.retryAfterSeconds || 60),
          'X-RateLimit-Remaining': '0',
        },
      }
    );
  }

  if (method === 'OPTIONS') {
    return handleCors(request);
  }

  try {
    const isLargeUploadPath =
      /^\/api\/ciphers\/[a-f0-9-]+\/attachment\/[a-f0-9-]+$/i.test(path) ||
      /^\/api\/sends\/[a-f0-9-]+\/file\/[a-f0-9-]+$/i.test(path) ||
      path === '/api/admin/backup/import';
    if (!isLargeUploadPath) {
      const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
      if (contentLength > LIMITS.request.maxBodyBytes) {
        return errorResponse('Request body too large', 413);
      }
    }

    const publicResponse = await handlePublicRoute(request, env, path, method, enforcePublicRateLimit);
    if (publicResponse) return publicResponse;

    const secretIssue = jwtSecretUnsafeReason(env);
    if (secretIssue) {
      return errorResponse('Server configuration error: JWT_SECRET is not set or too weak', 500);
    }

    const auth = new AuthService(env);
    const authHeader = request.headers.get('Authorization');
    const verified = await auth.verifyAccessTokenWithUser(authHeader);
    if (!verified) {
      return errorResponse('Unauthorized', 401);
    }
    const { payload, user: currentUser } = verified;

    const actingDeviceId = String(payload.did || '').trim();
    if (actingDeviceId) {
      const nextHeaders = new Headers(request.headers);
      nextHeaders.set('X-NodeWarden-Acting-Device-Id', actingDeviceId);
      request = new Request(request, { headers: nextHeaders });
    }

    const userId = payload.sub;
    if (currentUser.status !== 'active') {
      return errorResponse('Account is disabled', 403);
    }

    if (!isImportBypassRequest(request, path, method)) {
      const rateLimit = new RateLimitService(env.DB);
      const rateLimitCheck = await rateLimit.consumeBudget(`${userId}:api`, LIMITS.rateLimit.apiRequestsPerMinute);
      if (!rateLimitCheck.allowed) {
        return new Response(
          JSON.stringify({
            error: 'Too many requests',
            error_description: `Rate limit exceeded. Try again in ${rateLimitCheck.retryAfterSeconds} seconds.`,
          }),
          {
            status: 429,
            headers: {
              'Content-Type': 'application/json',
              'Retry-After': String(rateLimitCheck.retryAfterSeconds || 60),
              'X-RateLimit-Remaining': '0',
            },
          }
        );
      }
    }

    const authenticatedResponse = await handleAuthenticatedRoute(request, env, userId, currentUser, path, method);
    if (authenticatedResponse) return authenticatedResponse;

    return errorResponse('Not found', 404);
  } catch (error) {
    console.error('Request error:', error);
    return errorResponse('Internal server error', 500);
  }
}
