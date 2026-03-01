import { Env } from './types';
import { handleRequest } from './router';
import { StorageService } from './services/storage';
import { applyCors, jsonResponse } from './utils/response';

let dbInitialized = false;
let dbInitError: string | null = null;
let dbInitPromise: Promise<void> | null = null;

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
};
