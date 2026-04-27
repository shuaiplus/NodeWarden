import type { Env } from '../types';
import { LIMITS } from './limits';

export function getMasterPasswordMinLength(env: Pick<Env, 'MASTER_PASSWORD_MIN_LENGTH'>): number {
  const raw = String(env.MASTER_PASSWORD_MIN_LENGTH || '').trim();
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0
    ? parsed
    : LIMITS.auth.masterPasswordMinLength;
}
