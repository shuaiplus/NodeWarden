import { LIMITS } from '../config/limits';

const CORS_METHODS = 'GET, POST, PUT, DELETE, PATCH, OPTIONS';
const DEFAULT_CORS_HEADERS = [
  'Content-Type',
  'Authorization',
  'Accept',
  'Device-Type',
  'Device-Identifier',
  'Device-Name',
  'Bitwarden-Client-Name',
  'Bitwarden-Client-Version',
  'Bitwarden-Package-Type',
  'Is-Prerelease',
  'X-Request-Email',
  'X-Device-Identifier',
  'X-Device-Name',
  'X-NodeWarden-Web-Session',
];

function isExtensionOrigin(origin: string): boolean {
  return (
    origin.startsWith('chrome-extension://')
    || origin.startsWith('moz-extension://')
    || origin.startsWith('safari-web-extension://')
  );
}

function isWildcardCorsPath(path: string): boolean {
  return (
    path.startsWith('/icons/')
    || path === '/config'
    || path === '/api/config'
    || path === '/api/version'
  );
}

function getCorsPolicy(request: Request): { allowOrigin: string | null; allowCredentials: boolean } {
  const url = new URL(request.url);
  const origin = request.headers.get('Origin');
  if (isWildcardCorsPath(url.pathname)) {
    return { allowOrigin: '*', allowCredentials: false };
  }
  if (!origin) {
    return { allowOrigin: null, allowCredentials: false };
  }
  if (origin === url.origin) {
    return { allowOrigin: origin, allowCredentials: true };
  }
  if (isExtensionOrigin(origin)) {
    return { allowOrigin: origin, allowCredentials: false };
  }
  return { allowOrigin: null, allowCredentials: false };
}

function buildCorsHeaders(request: Request): Record<string, string> {
  const requestedHeaders = String(request.headers.get('Access-Control-Request-Headers') || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  const allowHeaders = Array.from(new Set([...DEFAULT_CORS_HEADERS, ...requestedHeaders]));

  const headers: Record<string, string> = {
    'Access-Control-Allow-Methods': CORS_METHODS,
    'Access-Control-Allow-Headers': allowHeaders.join(', '),
    'Access-Control-Expose-Headers': '*',
    'Access-Control-Max-Age': String(LIMITS.cors.preflightMaxAgeSeconds),
  };

  const corsPolicy = getCorsPolicy(request);
  if (corsPolicy.allowOrigin) {
    headers['Access-Control-Allow-Origin'] = corsPolicy.allowOrigin;
    if (corsPolicy.allowCredentials) {
      headers['Access-Control-Allow-Credentials'] = 'true';
    }
    headers['Vary'] = 'Origin, Access-Control-Request-Headers';
  }

  return headers;
}

export function applyCors(
  request: Request,
  response: Response
): Response {
  // WebSocket upgrade responses must be returned untouched.
  const webSocket = (response as Response & { webSocket?: unknown }).webSocket;
  if (response.status === 101 || webSocket) {
    return response;
  }

  const headers = new Headers(response.headers);
  const corsHeaders = buildCorsHeaders(request);
  for (const [k, v] of Object.entries(corsHeaders)) {
    headers.set(k, v);
  }
  // Security headers applied to every response.
  headers.set('X-Frame-Options', 'DENY');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Content-Security-Policy', "frame-ancestors 'none'; img-src 'self' data:");
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
