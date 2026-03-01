import { LIMITS } from '../config/limits';

// D1-backed rate limiting.
// Notes:
// - Login attempts are tracked per client IP.
// - API rate is tracked per identifier per fixed window.

// Rate limit configuration
const CONFIG = {
  // Friendly default: short cooldown instead of long lockouts.
  LOGIN_MAX_ATTEMPTS: LIMITS.rateLimit.loginMaxAttempts,
  LOGIN_LOCKOUT_MINUTES: LIMITS.rateLimit.loginLockoutMinutes,

  // Write operations only (POST/PUT/DELETE/PATCH) should use this budget.
  API_WRITE_REQUESTS_PER_MINUTE: LIMITS.rateLimit.apiWriteRequestsPerMinute,
  // Dedicated budget for GET /api/sync reads.
  SYNC_READ_REQUESTS_PER_MINUTE: LIMITS.rateLimit.syncReadRequestsPerMinute,
  // Dedicated budget for GET /api/devices/knowndevice probes.
  KNOWN_DEVICE_REQUESTS_PER_MINUTE: LIMITS.rateLimit.knownDeviceRequestsPerMinute,
  // Dedicated budget for unauthenticated public Send access endpoints.
  PUBLIC_SEND_REQUESTS_PER_MINUTE: LIMITS.rateLimit.publicSendRequestsPerMinute,
  API_WINDOW_SECONDS: LIMITS.rateLimit.apiWindowSeconds,
};

export class RateLimitService {
  private static loginIpTableReady = false;
  private static lastLoginIpCleanupAt = 0;
  private static lastApiWindowCleanupAt = 0;

  private static readonly PERIODIC_CLEANUP_PROBABILITY = LIMITS.rateLimit.cleanupProbability;
  private static readonly LOGIN_IP_CLEANUP_INTERVAL_MS = LIMITS.rateLimit.loginIpCleanupIntervalMs;
  private static readonly API_WINDOW_CLEANUP_INTERVAL_MS = LIMITS.rateLimit.apiWindowCleanupIntervalMs;
  private static readonly LOGIN_IP_RETENTION_MS = LIMITS.rateLimit.loginIpRetentionMs;
  private static readonly API_WINDOW_RETENTION_WINDOWS = LIMITS.rateLimit.apiWindowRetentionWindows;

  constructor(private db: D1Database) {}

  private shouldRunCleanup(lastRunAt: number, intervalMs: number): boolean {
    const now = Date.now();
    if (now - lastRunAt < intervalMs) return false;
    return Math.random() < RateLimitService.PERIODIC_CLEANUP_PROBABILITY;
  }

  private async maybeCleanupLoginAttemptsIp(nowMs: number): Promise<void> {
    if (!this.shouldRunCleanup(RateLimitService.lastLoginIpCleanupAt, RateLimitService.LOGIN_IP_CLEANUP_INTERVAL_MS)) {
      return;
    }

    const cutoff = nowMs - RateLimitService.LOGIN_IP_RETENTION_MS;
    await this.db
      .prepare(
        'DELETE FROM login_attempts_ip WHERE updated_at < ? AND (locked_until IS NULL OR locked_until < ?)'
      )
      .bind(cutoff, nowMs)
      .run();
    RateLimitService.lastLoginIpCleanupAt = nowMs;
  }

  private async maybeCleanupApiWindows(windowStart: number, windowSeconds: number): Promise<void> {
    if (!this.shouldRunCleanup(RateLimitService.lastApiWindowCleanupAt, RateLimitService.API_WINDOW_CLEANUP_INTERVAL_MS)) {
      return;
    }

    const cutoff = windowStart - (windowSeconds * RateLimitService.API_WINDOW_RETENTION_WINDOWS);
    await this.db.prepare('DELETE FROM api_rate_limits WHERE window_start < ?').bind(cutoff).run();
    RateLimitService.lastApiWindowCleanupAt = Date.now();
  }

  private async ensureLoginIpTable(): Promise<void> {
    if (RateLimitService.loginIpTableReady) return;

    await this.db
      .prepare(
        'CREATE TABLE IF NOT EXISTS login_attempts_ip (' +
        'ip TEXT PRIMARY KEY, ' +
        'attempts INTEGER NOT NULL, ' +
        'locked_until INTEGER, ' +
        'updated_at INTEGER NOT NULL' +
        ')'
      )
      .run();

    RateLimitService.loginIpTableReady = true;
  }

  async checkLoginAttempt(ip: string): Promise<{
    allowed: boolean;
    remainingAttempts: number;
    retryAfterSeconds?: number;
  }> {
    await this.ensureLoginIpTable();

    const key = ip.trim() || 'unknown';
    const now = Date.now();
    await this.maybeCleanupLoginAttemptsIp(now);

    const row = await this.db
      .prepare('SELECT attempts, locked_until FROM login_attempts_ip WHERE ip = ?')
      .bind(key)
      .first<{ attempts: number; locked_until: number | null }>();

    if (!row) {
      return { allowed: true, remainingAttempts: CONFIG.LOGIN_MAX_ATTEMPTS };
    }

    if (row.locked_until && row.locked_until > now) {
      return {
        allowed: false,
        remainingAttempts: 0,
        retryAfterSeconds: Math.ceil((row.locked_until - now) / 1000),
      };
    }

    if (row.locked_until && row.locked_until <= now) {
      await this.db.prepare('DELETE FROM login_attempts_ip WHERE ip = ?').bind(key).run();
      return { allowed: true, remainingAttempts: CONFIG.LOGIN_MAX_ATTEMPTS };
    }

    const remainingAttempts = Math.max(0, CONFIG.LOGIN_MAX_ATTEMPTS - (row.attempts || 0));
    return { allowed: true, remainingAttempts };
  }

  async recordFailedLogin(ip: string): Promise<{ locked: boolean; retryAfterSeconds?: number }> {
    await this.ensureLoginIpTable();

    const key = ip.trim() || 'unknown';
    const now = Date.now();
    await this.maybeCleanupLoginAttemptsIp(now);

    // D1 in Workers forbids raw BEGIN/COMMIT statements.
    // Use a single atomic UPSERT to increment attempts.
    // This is concurrency-safe because the row is keyed by IP.
    await this.db
      .prepare(
        'INSERT INTO login_attempts_ip(ip, attempts, locked_until, updated_at) VALUES(?, 1, NULL, ?) ' +
        'ON CONFLICT(ip) DO UPDATE SET attempts = attempts + 1, updated_at = excluded.updated_at'
      )
      .bind(key, now)
      .run();

    const row = await this.db
      .prepare('SELECT attempts FROM login_attempts_ip WHERE ip = ?')
      .bind(key)
      .first<{ attempts: number }>();

    const attempts = row?.attempts || 1;
    if (attempts >= CONFIG.LOGIN_MAX_ATTEMPTS) {
      const lockedUntil = now + CONFIG.LOGIN_LOCKOUT_MINUTES * 60 * 1000;
      await this.db
        .prepare('UPDATE login_attempts_ip SET locked_until = ?, updated_at = ? WHERE ip = ?')
        .bind(lockedUntil, now, key)
        .run();
      return { locked: true, retryAfterSeconds: CONFIG.LOGIN_LOCKOUT_MINUTES * 60 };
    }

    return { locked: false };
  }

  async clearLoginAttempts(ip: string): Promise<void> {
    await this.ensureLoginIpTable();
    const key = ip.trim() || 'unknown';
    await this.db.prepare('DELETE FROM login_attempts_ip WHERE ip = ?').bind(key).run();
  }

  // Atomically consume one budget unit for the current fixed window.
  // Uses SQLite UPSERT-with-WHERE so requests at/over limit do not increment.
  private async consumeFixedWindowBudget(
    identifier: string,
    maxRequests: number,
    windowSeconds: number
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds?: number }> {
    const nowSec = Math.floor(Date.now() / 1000);
    const windowStart = nowSec - (nowSec % windowSeconds);
    const windowEnd = windowStart + windowSeconds;
    await this.maybeCleanupApiWindows(windowStart, windowSeconds);

    const writeResult = await this.db
      .prepare(
        'INSERT INTO api_rate_limits(identifier, window_start, count) VALUES(?, ?, 1) ' +
        'ON CONFLICT(identifier, window_start) DO UPDATE SET count = count + 1 ' +
        'WHERE api_rate_limits.count < ?'
      )
      .bind(identifier, windowStart, maxRequests)
      .run();

    // No changed row means conflict happened and WHERE prevented increment:
    // current count is already at/above configured limit.
    if ((writeResult.meta.changes ?? 0) === 0) {
      return {
        allowed: false,
        remaining: 0,
        retryAfterSeconds: windowEnd - nowSec,
      };
    }

    const row = await this.db
      .prepare('SELECT count FROM api_rate_limits WHERE identifier = ? AND window_start = ?')
      .bind(identifier, windowStart)
      .first<{ count: number }>();

    if (!row) {
      return {
        allowed: true,
        remaining: 0,
      };
    }

    const remaining = Math.max(0, maxRequests - row.count);
    return { allowed: true, remaining };
  }

  // Write budget for POST/PUT/DELETE/PATCH requests.
  async consumeApiWriteBudget(identifier: string): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds?: number }> {
    return this.consumeFixedWindowBudget(
      identifier,
      CONFIG.API_WRITE_REQUESTS_PER_MINUTE,
      CONFIG.API_WINDOW_SECONDS
    );
  }

  // Read budget for GET /api/sync.
  async consumeSyncReadBudget(identifier: string): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds?: number }> {
    return this.consumeFixedWindowBudget(
      identifier,
      CONFIG.SYNC_READ_REQUESTS_PER_MINUTE,
      CONFIG.API_WINDOW_SECONDS
    );
  }

  // Probe budget for GET /api/devices/knowndevice.
  async consumeKnownDeviceProbeBudget(identifier: string): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds?: number }> {
    return this.consumeFixedWindowBudget(
      identifier,
      CONFIG.KNOWN_DEVICE_REQUESTS_PER_MINUTE,
      CONFIG.API_WINDOW_SECONDS
    );
  }

  // Budget for unauthenticated public Send access endpoints.
  async consumePublicSendAccessBudget(identifier: string): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds?: number }> {
    return this.consumeFixedWindowBudget(
      identifier,
      CONFIG.PUBLIC_SEND_REQUESTS_PER_MINUTE,
      CONFIG.API_WINDOW_SECONDS
    );
  }
}

export function getClientIdentifier(request: Request): string {
  const cfIp = request.headers.get('CF-Connecting-IP');
  if (cfIp) return cfIp;

  const forwardedFor = request.headers.get('X-Forwarded-For');
  if (forwardedFor) return forwardedFor.split(',')[0].trim();

  return 'unknown';
}
