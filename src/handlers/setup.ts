import { Env, DEFAULT_DEV_SECRET } from '../types';
import { StorageService } from '../services/storage';
import { jsonResponse, htmlResponse } from '../utils/response';
import { renderRegisterPageHTML } from '../setup/pageTemplate';
import { LIMITS } from '../config/limits';

type JwtSecretState = 'missing' | 'default' | 'too_short';

function getJwtSecretState(env: Env): JwtSecretState | null {
  const secret = (env.JWT_SECRET || '').trim();
  if (!secret) return 'missing';
  // Block common "forgot to change" sample value (matches .dev.vars.example)
  if (secret === DEFAULT_DEV_SECRET) return 'default';
  if (secret.length < LIMITS.auth.jwtSecretMinLength) return 'too_short';
  return null;
}

async function handleRegisterPage(request: Request, env: Env, jwtState: JwtSecretState | null): Promise<Response> {
  void request;
  void env;
  return htmlResponse(renderRegisterPageHTML(jwtState));
}

// GET / - Setup page
export async function handleSetupPage(request: Request, env: Env): Promise<Response> {
  const jwtState = getJwtSecretState(env);
  return handleRegisterPage(request, env, jwtState);
}

// GET /setup/status
export async function handleSetupStatus(request: Request, env: Env): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const registered = (await storage.isRegistered()) || (await storage.getUserCount()) > 0;
  return jsonResponse({ registered });
}
