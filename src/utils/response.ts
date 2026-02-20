import { LIMITS } from '../config/limits';

const CORS_METHODS = 'GET, POST, PUT, DELETE, PATCH, OPTIONS';
const CORS_HEADERS = 'Content-Type, Authorization, Accept, Device-Type, Bitwarden-Client-Name, Bitwarden-Client-Version, X-Request-Email, X-Device-Identifier, X-Device-Name';

function isTrustedClientOrigin(origin: string): boolean {
  // Official browser extension / desktop-webview common origins.
  if (origin === 'null') return true;
  if (origin.startsWith('chrome-extension://')) return true;
  if (origin.startsWith('moz-extension://')) return true;
  if (origin.startsWith('safari-web-extension://')) return true;
  if (origin.startsWith('app://')) return true;
  if (origin.startsWith('capacitor://')) return true;
  if (origin.startsWith('ionic://')) return true;
  return false;
}

function getAllowedOrigin(request: Request): string | null {
  const origin = request.headers.get('Origin');
  if (!origin) return null;

  const targetOrigin = new URL(request.url).origin;
  if (origin === targetOrigin) return origin;
  if (isTrustedClientOrigin(origin)) return origin;
  return null;
}

function buildCorsHeaders(request: Request): Record<string, string> {
  const headers: Record<string, string> = {
    'Access-Control-Allow-Methods': CORS_METHODS,
    'Access-Control-Allow-Headers': CORS_HEADERS,
    'Access-Control-Max-Age': String(LIMITS.cors.preflightMaxAgeSeconds),
  };

  const allowedOrigin = getAllowedOrigin(request);
  if (allowedOrigin) {
    headers['Access-Control-Allow-Origin'] = allowedOrigin;
    headers['Vary'] = 'Origin';
  }

  return headers;
}

export function applyCors(
  request: Request,
  response: Response
): Response {
  const headers = new Headers(response.headers);
  const corsHeaders = buildCorsHeaders(request);
  for (const [k, v] of Object.entries(corsHeaders)) {
    headers.set(k, v);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

// JSON response helper
export function jsonResponse(data: any, status: number = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
  });
}

// Error response helper
export function errorResponse(message: string, status: number = 400): Response {
  return jsonResponse(
    {
      error: message,
      error_description: message,
      ErrorModel: {
        Message: message,
        Object: 'error',
      },
    },
    status
  );
}

// Identity endpoint error response (for /identity/connect/token)
export function identityErrorResponse(message: string, error: string = 'invalid_grant', status: number = 400): Response {
  return jsonResponse(
    {
      error: error,
      error_description: message,
      ErrorModel: {
        Message: message,
        Object: 'error',
      },
    },
    status
  );
}

// Handle CORS preflight
export function handleCors(request: Request): Response {
  const origin = request.headers.get('Origin');
  if (origin) {
    const allowedOrigin = getAllowedOrigin(request);
    if (!allowedOrigin) {
      return new Response(null, { status: 403 });
    }
  }

  return new Response(null, {
    status: 204,
    headers: buildCorsHeaders(request),
  });
}

// HTML response helper
export function htmlResponse(html: string, status: number = 200): Response {
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
    },
  });
}
