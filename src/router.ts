import { Env, DEFAULT_DEV_SECRET } from './types';
import { AuthService } from './services/auth';
import { RateLimitService, getClientIdentifier } from './services/ratelimit';
import { handleCors, errorResponse, jsonResponse } from './utils/response';
import { LIMITS } from './config/limits';

// Identity handlers
import { handleToken, handlePrelogin } from './handlers/identity';

// Account handlers
import { handleRegister, handleGetProfile, handleUpdateProfile, handleSetKeys, handleGetRevisionDate, handleVerifyPassword } from './handlers/accounts';

// Cipher handlers
import { 
  handleGetCiphers, 
  handleGetCipher, 
  handleCreateCipher, 
  handleUpdateCipher, 
  handleDeleteCipher,
  handlePermanentDeleteCipher,
  handleRestoreCipher,
  handlePartialUpdateCipher,
  handleBulkMoveCiphers,
} from './handlers/ciphers';

// Folder handlers
import { 
  handleGetFolders, 
  handleGetFolder, 
  handleCreateFolder, 
  handleUpdateFolder, 
  handleDeleteFolder 
} from './handlers/folders';

// Sync handler
import { handleSync } from './handlers/sync';

// Setup handlers
import { handleSetupPage, handleSetupStatus, handleDisableSetup } from './handlers/setup';
import { handleKnownDevice, handleGetDevices } from './handlers/devices';

// Import handler
import { handleCiphersImport } from './handlers/import';

// Attachment handlers
import {
  handleCreateAttachment,
  handleUploadAttachment,
  handleGetAttachment,
  handleDeleteAttachment,
  handlePublicDownloadAttachment,
} from './handlers/attachments';

function isSameOriginWriteRequest(request: Request): boolean {
  const targetOrigin = new URL(request.url).origin;
  const origin = request.headers.get('Origin');
  if (origin) {
    return origin === targetOrigin;
  }

  const referer = request.headers.get('Referer');
  if (referer) {
    try {
      return new URL(referer).origin === targetOrigin;
    } catch {
      return false;
    }
  }

  // Require browser-origin evidence for setup/register write operations.
  return false;
}

function getNwIconSvg(): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 96 96" role="img" aria-label="NW icon"><rect x="4" y="4" width="88" height="88" rx="20" fill="#111418"/><text x="48" y="60" text-anchor="middle" font-size="36" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif" font-weight="800" letter-spacing="0.5" fill="#FFFFFF">NW</text></svg>`;
}

function handleNwFavicon(): Response {
  return new Response(getNwIconSvg(), {
    status: 200,
    headers: {
      'Content-Type': 'image/svg+xml; charset=utf-8',
      'Cache-Control': `public, max-age=${LIMITS.cache.iconTtlSeconds}`,
    },
  });
}

function isValidIconHostname(hostname: string): boolean {
  if (!hostname) return false;
  if (hostname.length > 253) return false;

  const normalized = hostname.toLowerCase().replace(/\.$/, '');
  // Slightly relaxed domain validation:
  // - keep strict label boundaries (no leading/trailing hyphen)
  // - allow punycode TLD (e.g. xn--...)
  const domainPattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/;
  const ipv4Pattern = /^(?:\d{1,3}\.){3}\d{1,3}$/;

  if (domainPattern.test(normalized)) return true;
  if (!ipv4Pattern.test(normalized)) return false;

  const parts = normalized.split('.');
  return parts.every(p => {
    const n = Number(p);
    return Number.isInteger(n) && n >= 0 && n <= 255;
  });
}

// Icons handler - proxy to Bitwarden's official icon service
async function handleGetIcon(request: Request, env: Env, hostname: string): Promise<Response> {
  try {
    void env;
    const normalizedHostname = hostname.toLowerCase();
    if (!isValidIconHostname(normalizedHostname)) {
      return new Response(null, { status: 204 });
    }

    const cache = caches.default;
    const cacheKey = new Request(`https://nodewarden-icons.local/icons/${normalizedHostname}/icon.png`, { method: 'GET' });
    const cached = await cache.match(cacheKey);
    if (cached) {
      return cached;
    }

    // Use Bitwarden's official icon service
    const iconUrl = `https://icons.bitwarden.net/${normalizedHostname}/icon.png`;
    const resp = await fetch(iconUrl, {
      headers: { 'User-Agent': 'NodeWarden/1.0' },
      redirect: 'follow',
      cf: {
        cacheEverything: true,
        cacheTtl: LIMITS.cache.iconTtlSeconds,
      },
    });

    if (resp.ok) {
      const body = await resp.arrayBuffer();
      const iconResponse = new Response(body, {
        status: 200,
        headers: {
          'Content-Type': resp.headers.get('Content-Type') || 'image/png',
          'Cache-Control': `public, max-age=${LIMITS.cache.iconTtlSeconds}`, // 7 days
        },
      });
      await cache.put(cacheKey, iconResponse.clone());
      return iconResponse;
    }

    return new Response(null, { status: 204 });
  } catch {
    return new Response(null, { status: 204 });
  }
}

export async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // Handle CORS preflight
  if (method === 'OPTIONS') {
    return handleCors(request);
  }

  // Route matching
  try {

    // Setup page (root)
    if (path === '/' && method === 'GET') {
      return handleSetupPage(request, env);
    }

    // Setup status
    if (path === '/setup/status' && method === 'GET') {
      return handleSetupStatus(request, env);
    }

    // Disable setup page (one-way)
    if (path === '/setup/disable' && method === 'POST') {
      if (!isSameOriginWriteRequest(request)) {
        return errorResponse('Forbidden origin', 403);
      }
      return handleDisableSetup(request, env);
    }

    // Browser/devtools probe endpoint
    if (path === '/.well-known/appspecific/com.chrome.devtools.json' && method === 'GET') {
      return new Response('{}', {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
        },
      });
    }

    // Favicon
    if ((path === '/favicon.ico' || path === '/favicon.svg') && method === 'GET') {
      return handleNwFavicon();
    }

    // Icon endpoint - proxy to Bitwarden's icon service (no auth required)
    const iconMatch = path.match(/^\/icons\/([^/]+)\/icon\.png$/i);
    if (iconMatch) {
      const hostname = iconMatch[1];
      return handleGetIcon(request, env, hostname);
    }

    // Public attachment download (no auth header, uses token in query string)
    const publicAttachmentMatch = path.match(/^\/api\/attachments\/([a-f0-9-]+)\/([a-f0-9-]+)$/i);
    if (publicAttachmentMatch && method === 'GET') {
      const cipherId = publicAttachmentMatch[1];
      const attachmentId = publicAttachmentMatch[2];
      return handlePublicDownloadAttachment(request, env, cipherId, attachmentId);
    }

    // Notifications hub (stub - no auth required, return 200 for connection)
    if (path.startsWith('/notifications/')) {
      return new Response(null, { status: 200 });
    }

    // Known device check (no auth required)
    if (path === '/api/devices/knowndevice' && method === 'GET') {
      return handleKnownDevice(request, env);
    }

    // Identity endpoints (no auth required)
    if (path === '/identity/connect/token' && method === 'POST') {
      return handleToken(request, env);
    }

    if (path === '/identity/accounts/prelogin' && method === 'POST') {
      return handlePrelogin(request, env);
    }

    // Config endpoint (no auth required for basic config)
    // Bitwarden clients call GET "/config" (relative to the API base URL).
    // They also tolerate different casing, but their response models use PascalCase.
    const isConfigRequest = (path === '/config' || path === '/api/config') && method === 'GET';
    if (isConfigRequest) {
      const origin = url.origin;
      return jsonResponse({
        // ── Version Strategy (Plan E) ──────────────────────────────────────
        // Bitwarden clients use this version for backwards-compatibility feature gating.
        // Confirmed version-gated features (from client source code):
        //   - Individual cipher key encryption: >= 2024.2.0
        //     (clients/libs/common/src/vault/services/cipher.service.ts: CIPHER_KEY_ENC_MIN_SERVER_VER)
        //     (android/.../FeatureFlagManagerImpl.kt: CIPHER_KEY_ENC_MIN_SERVER_VERSION)
        //   - MasterPasswordUnlockData (mobile): >= 2025.8.0
        //     (documented in Vaultwarden source comments)
        // There is NO global minimum version that blocks all client functionality.
        // Keep this aligned with Vaultwarden's reported version to maintain compatibility.
        // When Vaultwarden bumps their version, update this value accordingly.
        // Vaultwarden source: src/api/core/mod.rs → fn config()
        version: LIMITS.compatibility.bitwardenServerVersion,
        gitHash: 'nodewarden',
        server: null,
        environment: {
          vault: origin,
          api: origin + '/api',
          identity: origin + '/identity',
          notifications: origin + '/notifications',
          sso: '',
        },
        // Feature flags control client behavior. Clients use server-provided values;
        // flags not listed here fall back to DefaultFeatureFlagValue (all false).
        // Only enable flags for features we actually support.
        // Reference: clients/libs/common/src/enums/feature-flag.enum.ts
        featureStates: {
          'duo-redirect': true,
          'email-verification': true,
          'unauth-ui-refresh': true,
        },
        object: 'config',
      });
    }

    // Version endpoint (some clients probe this to validate the server)
    if (path === '/api/version' && method === 'GET') {
      return jsonResponse(LIMITS.compatibility.bitwardenServerVersion);  // Always same value as /config.version
    }

    // Registration endpoint (no auth required, but only works once)
    if (path === '/api/accounts/register' && method === 'POST') {
      if (!isSameOriginWriteRequest(request)) {
        return errorResponse('Forbidden origin', 403);
      }
      return handleRegister(request, env);
    }

    // If JWT_SECRET is not safely configured, block any other endpoints.
    const secret = (env.JWT_SECRET || '').trim();
    if (!secret || secret.length < LIMITS.auth.jwtSecretMinLength || secret === DEFAULT_DEV_SECRET) {
      return errorResponse('Server configuration error: JWT_SECRET is not set or too weak', 500);
    }

    // All other API endpoints require authentication
    const auth = new AuthService(env);
    const authHeader = request.headers.get('Authorization');
    const payload = await auth.verifyAccessToken(authHeader);

    if (!payload) {
      return errorResponse('Unauthorized', 401);
    }

    const userId = payload.sub;
    const clientId = getClientIdentifier(request);

    // Dedicated read rate limiting for heavy sync endpoint.
    if (path === '/api/sync' && method === 'GET') {
      const rateLimit = new RateLimitService(env.DB);
      const rateLimitCheck = await rateLimit.consumeSyncReadBudget(userId + ':' + clientId + ':sync');

      if (!rateLimitCheck.allowed) {
        return new Response(JSON.stringify({
          error: 'Too many requests',
          error_description: `Sync rate limit exceeded. Try again in ${rateLimitCheck.retryAfterSeconds} seconds.`,
        }), {
          status: 429,
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': rateLimitCheck.retryAfterSeconds!.toString(),
            'X-RateLimit-Remaining': '0',
          },
        });
      }
    }

    // API rate limiting only for write operations (keep reads frictionless)
    const isWriteMethod = method === 'POST' || method === 'PUT' || method === 'DELETE' || method === 'PATCH';
    if (isWriteMethod) {
      const rateLimit = new RateLimitService(env.DB);
      const rateLimitCheck = await rateLimit.consumeApiWriteBudget(userId + ':' + clientId + ':write');

      if (!rateLimitCheck.allowed) {
        return new Response(JSON.stringify({
          error: 'Too many requests',
          error_description: `Rate limit exceeded. Try again in ${rateLimitCheck.retryAfterSeconds} seconds.`,
        }), {
          status: 429,
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': rateLimitCheck.retryAfterSeconds!.toString(),
            'X-RateLimit-Remaining': '0',
          },
        });
      }
    }

    // Block account operations that could change password or delete user
    if (method === 'POST' || method === 'PUT' || method === 'DELETE') {
      const blockedAccountPaths = new Set([
        '/api/accounts/password',
        '/api/accounts/change-password',
        '/api/accounts/set-password',
        '/api/accounts/master-password',
        '/api/accounts/delete',
        '/api/accounts/delete-account',
        '/api/accounts/delete-vault',
      ]);
      if (blockedAccountPaths.has(path)) {
        return errorResponse('Not implemented in single-user mode', 501);
      }
    }

    // Account endpoints
    if (path === '/api/accounts/profile') {
      if (method === 'GET') return handleGetProfile(request, env, userId);
      if (method === 'PUT') return handleUpdateProfile(request, env, userId);
    }

    if (path === '/api/accounts/keys' && method === 'POST') {
      return handleSetKeys(request, env, userId);
    }

    // Revision date endpoint
    if (path === '/api/accounts/revision-date' && method === 'GET') {
      return handleGetRevisionDate(request, env, userId);
    }

    // Verify password endpoint
    if (path === '/api/accounts/verify-password' && method === 'POST') {
      return handleVerifyPassword(request, env, userId);
    }

    // Sync endpoint
    if (path === '/api/sync' && method === 'GET') {
      return handleSync(request, env, userId);
    }

    // Cipher endpoints
    if (path === '/api/ciphers' || path === '/api/ciphers/create') {
      if (method === 'GET') return handleGetCiphers(request, env, userId);
      if (method === 'POST') return handleCreateCipher(request, env, userId);
    }

    // Ciphers import endpoint (Bitwarden client format)
    if (path === '/api/ciphers/import' && method === 'POST') {
      return handleCiphersImport(request, env, userId);
    }

    // Bulk cipher operations (only move is allowed)
    if (path === '/api/ciphers/move') {
      if (method === 'POST' || method === 'PUT') {
        return handleBulkMoveCiphers(request, env, userId);
      }
    }

    // Match /api/ciphers/:id patterns
    const cipherMatch = path.match(/^\/api\/ciphers\/([a-f0-9-]+)(\/.*)?$/i);
    if (cipherMatch) {
      const cipherId = cipherMatch[1];
      const subPath = cipherMatch[2] || '';

      if (subPath === '' || subPath === '/') {
        if (method === 'GET') return handleGetCipher(request, env, userId, cipherId);
        if (method === 'PUT' || method === 'POST') return handleUpdateCipher(request, env, userId, cipherId);
        if (method === 'DELETE') return handleDeleteCipher(request, env, userId, cipherId);
      }

      if (subPath === '/delete' && method === 'PUT') {
        return handleDeleteCipher(request, env, userId, cipherId);
      }

      if (subPath === '/delete' && method === 'DELETE') {
        return handlePermanentDeleteCipher(request, env, userId, cipherId);
      }

      if (subPath === '/restore' && method === 'PUT') {
        return handleRestoreCipher(request, env, userId, cipherId);
      }

      if (subPath === '/partial' && (method === 'PUT' || method === 'POST')) {
        return handlePartialUpdateCipher(request, env, userId, cipherId);
      }

      // Share endpoint - just return the cipher (single user mode)
      if (subPath === '/share' && method === 'POST') {
        return handleGetCipher(request, env, userId, cipherId);
      }

      if (subPath === '/details' && method === 'GET') {
        return handleGetCipher(request, env, userId, cipherId);
      }

      // Attachment endpoints
      // POST /api/ciphers/{id}/attachment/v2 - Create attachment metadata
      if (subPath === '/attachment/v2' && method === 'POST') {
        return handleCreateAttachment(request, env, userId, cipherId);
      }

      // Legacy attachment endpoint - also goes to v2 flow
      if (subPath === '/attachment' && method === 'POST') {
        return handleCreateAttachment(request, env, userId, cipherId);
      }

      // Match /api/ciphers/{id}/attachment/{attachmentId}
      const attachmentMatch = subPath.match(/^\/attachment\/([a-f0-9-]+)$/i);
      if (attachmentMatch) {
        const attachmentId = attachmentMatch[1];
        if (method === 'POST') return handleUploadAttachment(request, env, userId, cipherId, attachmentId);
        if (method === 'GET') return handleGetAttachment(request, env, userId, cipherId, attachmentId);
        if (method === 'DELETE') return handleDeleteAttachment(request, env, userId, cipherId, attachmentId);
      }

      // DELETE via POST (legacy)
      const attachmentDeleteMatch = subPath.match(/^\/attachment\/([a-f0-9-]+)\/delete$/i);
      if (attachmentDeleteMatch && method === 'POST') {
        const attachmentId = attachmentDeleteMatch[1];
        return handleDeleteAttachment(request, env, userId, cipherId, attachmentId);
      }
    }

    // Folder endpoints
    if (path === '/api/folders') {
      if (method === 'GET') return handleGetFolders(request, env, userId);
      if (method === 'POST') return handleCreateFolder(request, env, userId);
    }

    // Match /api/folders/:id patterns
    const folderMatch = path.match(/^\/api\/folders\/([a-f0-9-]+)$/i);
    if (folderMatch) {
      const folderId = folderMatch[1];
      if (method === 'GET') return handleGetFolder(request, env, userId, folderId);
      if (method === 'PUT') return handleUpdateFolder(request, env, userId, folderId);
      if (method === 'DELETE') return handleDeleteFolder(request, env, userId, folderId);
    }

    // Auth requests endpoint (stub - we don't support passwordless login)
    if (path.startsWith('/api/auth-requests')) {
      return jsonResponse({ data: [], object: 'list', continuationToken: null });
    }

    // Collections endpoint (stub - no organization support)
    if (path === '/api/collections' || path.startsWith('/api/collections/')) {
      if (method === 'GET') {
        return jsonResponse({ data: [], object: 'list', continuationToken: null });
      }
    }

    // Organizations endpoint (stub - no organization support)
    if (path === '/api/organizations' || path.startsWith('/api/organizations/')) {
      if (method === 'GET') {
        return jsonResponse({ data: [], object: 'list', continuationToken: null });
      }
    }

    // Sends endpoint (stub - not implemented)
    if (path === '/api/sends' || path.startsWith('/api/sends/')) {
      if (method === 'GET') {
        return jsonResponse({ data: [], object: 'list', continuationToken: null });
      }
    }

    // Policies endpoint (stub - not implemented)
    if (path === '/api/policies' || path.startsWith('/api/policies/')) {
      if (method === 'GET') {
        return jsonResponse({ data: [], object: 'list', continuationToken: null });
      }
    }

    // Settings domains endpoint (stub)
    if (path === '/api/settings/domains') {
      if (method === 'GET') {
        return jsonResponse({
          equivalentDomains: [],
          globalEquivalentDomains: [],
          object: 'domains',
        });
      }
      if (method === 'PUT' || method === 'POST') {
        return jsonResponse({
          equivalentDomains: [],
          globalEquivalentDomains: [],
          object: 'domains',
        });
      }
    }

    // Devices endpoint
    if (path === '/api/devices' && method === 'GET') {
      return handleGetDevices(request, env, userId);
    }

    // Not found
    return errorResponse('Not found', 404);

  } catch (error) {
    console.error('Request error:', error);
    return errorResponse('Internal server error', 500);
  }
}
