import { Env } from './types';
import { handleRequest } from './router';
import { StorageService } from './services/storage';
import { applyCors, jsonResponse } from './utils/response';

let dbInitialized = false;
let dbInitError: string | null = null;
let dbInitPromise: Promise<void> | null = null;

function shouldSkipDatabaseInit(request: Request): boolean {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (method === 'OPTIONS') return true;
  if (method === 'GET' && (path === '/favicon.ico' || path === '/favicon.svg')) return true;
  if (method === 'GET' && path === '/.well-known/appspecific/com.chrome.devtools.json') return true;
  if (method === 'GET' && path.startsWith('/icons/')) return true;
  if (path.startsWith('/notifications/')) return true;
  if (method === 'GET' && (path === '/config' || path === '/api/config' || path === '/api/version')) return true;

  return false;
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
    const requiresDatabase = !shouldSkipDatabaseInit(request);

    if (requiresDatabase) {
      await ensureDatabaseInitialized(env);
      if (dbInitError) {
        const resp = jsonResponse(
          {
            error: 'Database not initialized',
            error_description: dbInitError,
            ErrorModel: {
              Message: dbInitError,
              Object: 'error',
            },
          },
          500
        );
        return applyCors(request, resp);
      }
    }

    const resp = await handleRequest(request, env);
    return applyCors(request, resp);
  },
};
