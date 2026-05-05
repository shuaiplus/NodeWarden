import type { Env } from '../types';
import { StorageService } from '../services/storage';
import { getDomainRulesForUser, saveDomainRulesForUser } from '../services/domain-rules';
import { errorResponse, jsonResponse } from '../utils/response';

export async function handleGetDomainRules(_request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const response = await getDomainRulesForUser(storage, userId);
  return jsonResponse(response);
}

export async function handleSetDomainRules(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  try {
    const response = await saveDomainRulesForUser(storage, userId, body);
    return jsonResponse(response);
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Invalid domain rules payload', 400);
  }
}
