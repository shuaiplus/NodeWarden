import { Env } from '../types';
import { StorageService } from '../services/storage';
import { jsonResponse } from '../utils/response';

// GET /setup/status
export async function handleSetupStatus(request: Request, env: Env): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const registered = (await storage.isRegistered()) || (await storage.getUserCount()) > 0;
  return jsonResponse({ registered });
}
