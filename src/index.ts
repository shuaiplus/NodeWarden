import { Env } from './types';
import { handleRequest } from './router';
import { StorageService } from './services/storage';
import { runScheduledBackup } from './services/backup';

// Per-isolate flag. Each Worker isolate may have its own copy of this flag,
// but initializeDatabase() is idempotent (uses CREATE TABLE IF NOT EXISTS),
// so redundant calls are harmless and fast (single SELECT check).
let dbInitialized = false;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Auto-initialize database on first request
    if (!dbInitialized) {
      try {
        const storage = new StorageService(env.DB);
        await storage.initializeDatabase();
        dbInitialized = true;
      } catch (error) {
        console.error('Failed to initialize database:', error);
        // Continue anyway - the error will surface when actual DB operations are attempted
      }
    }

    return handleRequest(request, env);
  },

  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    void controller;
    ctx.waitUntil(runScheduledBackup(env));
  },
};
