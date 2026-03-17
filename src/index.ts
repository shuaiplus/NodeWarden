import { Env } from './types';
import { NotificationsHub } from './durable/notifications-hub';
import { handleRequest } from './router';
import { StorageService } from './services/storage';
import { applyCors, jsonResponse } from './utils/response';
import { runScheduledBackupIfDue } from './handlers/backup';
import { buildWebBootstrapResponse } from './router-public';

let dbInitialized = false;
let dbInitError: string | null = null;
let dbInitPromise: Promise<void> | null = null;

function isWorkerHandledPath(path: string): boolean {
  return (
    path.startsWith('/api/') ||
    path.startsWith('/identity/') ||
    path.startsWith('/icons/') ||
    path.startsWith('/notifications/') ||
    path.startsWith('/.well-known/') ||
    path === '/config' ||
    path === '/api/config' ||
    path === '/api/version'
  );
}

function injectBootstrapIntoHtml(html: string, env: Env): string {
  const payload = JSON.stringify(buildWebBootstrapResponse(env)).replace(/</g, '\\u003c');
  const script = `<script>window.__NW_BOOT__=${payload};</script>`;
  if (html.includes('</head>')) {
    return html.replace('</head>', `${script}</head>`);
  }
  return `${script}${html}`;
}

async function maybeServeAsset(request: Request, env: Env): Promise<Response | null> {
  if (!env.ASSETS) return null;
  if (request.method !== 'GET' && request.method !== 'HEAD') return null;
  const url = new URL(request.url);
  if (isWorkerHandledPath(url.pathname)) return null;

  const assetResponse = await env.ASSETS.fetch(request);
  const contentType = String(assetResponse.headers.get('Content-Type') || '').toLowerCase();
  if (request.method === 'GET' && contentType.includes('text/html')) {
    const html = await assetResponse.text();
    const injected = injectBootstrapIntoHtml(html, env);
    return new Response(injected, {
      status: assetResponse.status,
      statusText: assetResponse.statusText,
      headers: assetResponse.headers,
    });
  }
  return assetResponse;
}

async function ensureDatabaseInitialized(env: Env): Promise<void> {
  if (dbInitialized) return;

  if (!dbInitPromise) {
    dbInitPromise = (async () => {
      const storage = new StorageService(env.DB);
      await storage.initializeDatabase();
      dbInitialized = true;
      dbInitError = null;
    })()
      .catch((error: unknown) => {
        console.error('Failed to initialize database:', error);
        dbInitError = error instanceof Error ? error.message : 'Unknown database initialization error';
      })
      .finally(() => {
        dbInitPromise = null;
      });
  }

  await dbInitPromise;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    void ctx;
    const assetResponse = await maybeServeAsset(request, env);
    if (assetResponse) {
      return applyCors(request, assetResponse);
    }

    await ensureDatabaseInitialized(env);
    if (dbInitError) {
      // Log full error server-side, return generic message to client.
      console.error('DB init error (not forwarded to client):', dbInitError);
      const resp = jsonResponse(
        {
          error: 'Database not initialized',
          error_description: 'Database initialization failed. Check server logs for details.',
          ErrorModel: {
            Message: 'Service temporarily unavailable',
            Object: 'error',
          },
        },
        500
      );
      return applyCors(request, resp);
    }

    const resp = await handleRequest(request, env);
    return applyCors(request, resp);
  },

  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    void controller;
    await ensureDatabaseInitialized(env);
    if (dbInitError) {
      console.error('Skipping scheduled backup because DB init failed:', dbInitError);
      return;
    }
    ctx.waitUntil(runScheduledBackupIfDue(env).catch((error) => {
      console.error('Scheduled backup failed:', error);
    }));
  },
};

export { NotificationsHub };
