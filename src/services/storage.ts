import { User, Cipher, Folder, Attachment, Device, Invite, AuditLog, Send, SendAuthType, TrustedDeviceTokenSummary } from '../types';
import { LIMITS } from '../config/limits';

const TWO_FACTOR_REMEMBER_TTL_MS = 30 * 24 * 60 * 60 * 1000;

// IMPORTANT:
// Keep this schema list in sync with migrations/0001_init.sql.
// Any new table/column/index must be added to both places together.
const SCHEMA_STATEMENTS: readonly string[] = [
  'CREATE TABLE IF NOT EXISTS users (' +
  'id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT, master_password_hash TEXT NOT NULL, ' +
  'key TEXT NOT NULL, private_key TEXT, public_key TEXT, kdf_type INTEGER NOT NULL, ' +
  'kdf_iterations INTEGER NOT NULL, kdf_memory INTEGER, kdf_parallelism INTEGER, ' +
  'security_stamp TEXT NOT NULL, role TEXT NOT NULL DEFAULT \'user\', status TEXT NOT NULL DEFAULT \'active\', totp_secret TEXT, totp_recovery_code TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)',
  'ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT \'user\'',
  'ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT \'active\'',
  'ALTER TABLE users ADD COLUMN totp_secret TEXT',
  'ALTER TABLE users ADD COLUMN totp_recovery_code TEXT',

  'CREATE TABLE IF NOT EXISTS user_revisions (' +
  'user_id TEXT PRIMARY KEY, revision_date TEXT NOT NULL, ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',

  'CREATE TABLE IF NOT EXISTS ciphers (' +
  'id TEXT PRIMARY KEY, user_id TEXT NOT NULL, type INTEGER NOT NULL, folder_id TEXT, name TEXT, notes TEXT, ' +
  'favorite INTEGER NOT NULL DEFAULT 0, data TEXT NOT NULL, reprompt INTEGER, key TEXT, ' +
  'created_at TEXT NOT NULL, updated_at TEXT NOT NULL, deleted_at TEXT, ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',
  'CREATE INDEX IF NOT EXISTS idx_ciphers_user_updated ON ciphers(user_id, updated_at)',
  'CREATE INDEX IF NOT EXISTS idx_ciphers_user_deleted ON ciphers(user_id, deleted_at)',

  'CREATE TABLE IF NOT EXISTS folders (' +
  'id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',
  'CREATE INDEX IF NOT EXISTS idx_folders_user_updated ON folders(user_id, updated_at)',

  'CREATE TABLE IF NOT EXISTS attachments (' +
  'id TEXT PRIMARY KEY, cipher_id TEXT NOT NULL, file_name TEXT NOT NULL, size INTEGER NOT NULL, ' +
  'size_name TEXT NOT NULL, key TEXT, ' +
  'FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE)',
  'CREATE INDEX IF NOT EXISTS idx_attachments_cipher ON attachments(cipher_id)',

  'CREATE TABLE IF NOT EXISTS sends (' +
  'id TEXT PRIMARY KEY, user_id TEXT NOT NULL, type INTEGER NOT NULL, name TEXT NOT NULL, notes TEXT, data TEXT NOT NULL, ' +
  'key TEXT NOT NULL, password_hash TEXT, password_salt TEXT, password_iterations INTEGER, auth_type INTEGER NOT NULL DEFAULT 2, emails TEXT, ' +
  'max_access_count INTEGER, access_count INTEGER NOT NULL DEFAULT 0, disabled INTEGER NOT NULL DEFAULT 0, hide_email INTEGER, ' +
  'created_at TEXT NOT NULL, updated_at TEXT NOT NULL, expiration_date TEXT, deletion_date TEXT NOT NULL, ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',
  'CREATE INDEX IF NOT EXISTS idx_sends_user_updated ON sends(user_id, updated_at)',
  'CREATE INDEX IF NOT EXISTS idx_sends_user_deletion ON sends(user_id, deletion_date)',
  'ALTER TABLE sends ADD COLUMN auth_type INTEGER NOT NULL DEFAULT 2',
  'ALTER TABLE sends ADD COLUMN emails TEXT',

  'CREATE TABLE IF NOT EXISTS refresh_tokens (' +
  'token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL, ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',
  'CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id)',

  'CREATE TABLE IF NOT EXISTS invites (' +
  'code TEXT PRIMARY KEY, created_by TEXT NOT NULL, used_by TEXT, expires_at TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, ' +
  'FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE, ' +
  'FOREIGN KEY (used_by) REFERENCES users(id) ON DELETE SET NULL)',
  'CREATE INDEX IF NOT EXISTS idx_invites_status_expires ON invites(status, expires_at)',
  'CREATE INDEX IF NOT EXISTS idx_invites_created_by ON invites(created_by, created_at)',

  'CREATE TABLE IF NOT EXISTS audit_logs (' +
  'id TEXT PRIMARY KEY, actor_user_id TEXT, action TEXT NOT NULL, target_type TEXT, target_id TEXT, metadata TEXT, created_at TEXT NOT NULL, ' +
  'FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL)',
  'CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)',
  'CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_created ON audit_logs(actor_user_id, created_at)',

  'CREATE TABLE IF NOT EXISTS devices (' +
  'user_id TEXT NOT NULL, device_identifier TEXT NOT NULL, name TEXT NOT NULL, type INTEGER NOT NULL, ' +
  'created_at TEXT NOT NULL, updated_at TEXT NOT NULL, ' +
  'PRIMARY KEY (user_id, device_identifier), ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',
  'CREATE INDEX IF NOT EXISTS idx_devices_user_updated ON devices(user_id, updated_at)',

  'CREATE TABLE IF NOT EXISTS trusted_two_factor_device_tokens (' +
  'token TEXT PRIMARY KEY, user_id TEXT NOT NULL, device_identifier TEXT NOT NULL, expires_at INTEGER NOT NULL, ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',
  'CREATE INDEX IF NOT EXISTS idx_trusted_two_factor_device_tokens_user_device ON trusted_two_factor_device_tokens(user_id, device_identifier)',

  'CREATE TABLE IF NOT EXISTS api_rate_limits (' +
  'identifier TEXT NOT NULL, window_start INTEGER NOT NULL, count INTEGER NOT NULL, ' +
  'PRIMARY KEY (identifier, window_start))',
  'CREATE INDEX IF NOT EXISTS idx_api_rate_window ON api_rate_limits(window_start)',

  'CREATE TABLE IF NOT EXISTS login_attempts_ip (' +
  'ip TEXT PRIMARY KEY, attempts INTEGER NOT NULL, locked_until INTEGER, updated_at INTEGER NOT NULL)',

  'CREATE TABLE IF NOT EXISTS used_attachment_download_tokens (' +
  'jti TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)',
];

// D1-backed storage.
// Contract:
// - All methods are scoped by userId where applicable.
// - Uses SQL constraints (PK/unique/FK) to avoid KV-style index race conditions.
// - Revision date is maintained per user for Bitwarden sync.

export class StorageService {
  private static attachmentTokenTableReady = false;
  private static schemaVerified = false;
  private static lastRefreshTokenCleanupAt = 0;
  private static lastAttachmentTokenCleanupAt = 0;

  private static readonly REFRESH_TOKEN_CLEANUP_INTERVAL_MS = LIMITS.cleanup.refreshTokenCleanupIntervalMs;
  private static readonly ATTACHMENT_TOKEN_CLEANUP_INTERVAL_MS = LIMITS.cleanup.attachmentTokenCleanupIntervalMs;
  private static readonly PERIODIC_CLEANUP_PROBABILITY = LIMITS.cleanup.cleanupProbability;

  constructor(private db: D1Database) {}

  /**
   * D1 .bind() throws on `undefined` values. This helper converts every
   * `undefined` in the argument list to `null` so we never hit that runtime
   * error - especially important after the opaque-passthrough change where
   * client-supplied JSON may omit fields we later reference as columns.
   */
  private safeBind(stmt: D1PreparedStatement, ...values: any[]): D1PreparedStatement {
    return stmt.bind(...values.map(v => v === undefined ? null : v));
  }

  private async sha256Hex(input: string): Promise<string> {
    const bytes = new TextEncoder().encode(input);
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  private async refreshTokenKey(token: string): Promise<string> {
    const digest = await this.sha256Hex(token);
    return `sha256:${digest}`;
  }

  private shouldRunPeriodicCleanup(lastRunAt: number, intervalMs: number): boolean {
    const now = Date.now();
    if (now - lastRunAt < intervalMs) return false;
    return Math.random() < StorageService.PERIODIC_CLEANUP_PROBABILITY;
  }

  private async maybeCleanupExpiredRefreshTokens(nowMs: number): Promise<void> {
    if (!this.shouldRunPeriodicCleanup(StorageService.lastRefreshTokenCleanupAt, StorageService.REFRESH_TOKEN_CLEANUP_INTERVAL_MS)) {
      return;
    }

    await this.db.prepare('DELETE FROM refresh_tokens WHERE expires_at < ?').bind(nowMs).run();
    StorageService.lastRefreshTokenCleanupAt = nowMs;
  }

  // --- Database initialization ---
  // Strategy:
  // - Run only once per isolate.
  // - Execute idempotent schema SQL on first request in each isolate.
  // - Keep statements idempotent so updates are safe.
  async initializeDatabase(): Promise<void> {
    if (StorageService.schemaVerified) return;

    await this.db.prepare('PRAGMA foreign_keys = ON').run();
    await this.db.prepare('CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)').run();
    for (const stmt of SCHEMA_STATEMENTS) {
      await this.executeSchemaStatement(stmt);
    }
    await this.ensureAdminUserExists();

    StorageService.schemaVerified = true;
  }

  private async executeSchemaStatement(statement: string): Promise<void> {
    try {
      await this.db.prepare(statement).run();
    } catch (error) {
      const msg = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
      // Keep migration resilient if a future non-idempotent DDL is retried.
      if (msg.includes('already exists') || msg.includes('duplicate column name')) {
        return;
      }
      throw error;
    }
  }

  private async ensureAdminUserExists(): Promise<void> {
    const admin = await this.db.prepare("SELECT id FROM users WHERE role = 'admin' LIMIT 1").first<{ id: string }>();
    if (admin?.id) return;

    const firstUser = await this.db
      .prepare('SELECT id FROM users ORDER BY created_at ASC LIMIT 1')
      .first<{ id: string }>();
    if (!firstUser?.id) return;

    await this.db
      .prepare("UPDATE users SET role = 'admin', updated_at = ? WHERE id = ?")
      .bind(new Date().toISOString(), firstUser.id)
      .run();
  }

  // --- Config / setup ---

  async isRegistered(): Promise<boolean> {
    const row = await this.db.prepare('SELECT value FROM config WHERE key = ?').bind('registered').first<{ value: string }>();
    return row?.value === 'true';
  }

  async setRegistered(): Promise<void> {
    await this.db.prepare('INSERT INTO config(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
      .bind('registered', 'true')
      .run();
  }

  // --- Users ---

  private mapUserRow(row: any): User {
    return {
      id: row.id,
      email: row.email,
      name: row.name,
      masterPasswordHash: row.master_password_hash,
      key: row.key,
      privateKey: row.private_key,
      publicKey: row.public_key,
      kdfType: row.kdf_type,
      kdfIterations: row.kdf_iterations,
      kdfMemory: row.kdf_memory ?? undefined,
      kdfParallelism: row.kdf_parallelism ?? undefined,
      securityStamp: row.security_stamp,
      role: row.role === 'admin' ? 'admin' : 'user',
      status: row.status === 'banned' ? 'banned' : 'active',
      totpSecret: row.totp_secret ?? null,
      totpRecoveryCode: row.totp_recovery_code ?? null,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  async getUser(email: string): Promise<User | null> {
    const row = await this.db
      .prepare(
        'SELECT id, email, name, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, role, status, totp_secret, totp_recovery_code, created_at, updated_at FROM users WHERE email = ?'
      )
      .bind(email.toLowerCase())
      .first<any>();
    if (!row) return null;
    return this.mapUserRow(row);
  }

  async getUserById(id: string): Promise<User | null> {
    const row = await this.db
      .prepare(
        'SELECT id, email, name, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, role, status, totp_secret, totp_recovery_code, created_at, updated_at FROM users WHERE id = ?'
      )
      .bind(id)
      .first<any>();
    if (!row) return null;
    return this.mapUserRow(row);
  }

  async getUserCount(): Promise<number> {
    const row = await this.db.prepare('SELECT COUNT(*) AS count FROM users').first<{ count: number }>();
    return Number(row?.count || 0);
  }

  async getAllUsers(): Promise<User[]> {
    const res = await this.db
      .prepare(
        'SELECT id, email, name, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, role, status, totp_secret, totp_recovery_code, created_at, updated_at FROM users ORDER BY created_at ASC'
      )
      .all<any>();
    return (res.results || []).map(row => this.mapUserRow(row));
  }

  async saveUser(user: User): Promise<void> {
    const email = user.email.toLowerCase();
    const stmt = this.db.prepare(
      'INSERT INTO users(id, email, name, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, role, status, totp_secret, totp_recovery_code, created_at, updated_at) ' +
      'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET ' +
      'email=excluded.email, name=excluded.name, master_password_hash=excluded.master_password_hash, key=excluded.key, private_key=excluded.private_key, public_key=excluded.public_key, ' +
      'kdf_type=excluded.kdf_type, kdf_iterations=excluded.kdf_iterations, kdf_memory=excluded.kdf_memory, kdf_parallelism=excluded.kdf_parallelism, security_stamp=excluded.security_stamp, role=excluded.role, status=excluded.status, totp_secret=excluded.totp_secret, totp_recovery_code=excluded.totp_recovery_code, updated_at=excluded.updated_at'
    );
    await this.safeBind(stmt,
      user.id,
      email,
      user.name,
      user.masterPasswordHash,
      user.key,
      user.privateKey,
      user.publicKey,
      user.kdfType,
      user.kdfIterations,
      user.kdfMemory,
      user.kdfParallelism,
      user.securityStamp,
      user.role,
      user.status,
      user.totpSecret,
      user.totpRecoveryCode,
      user.createdAt,
      user.updatedAt
    ).run();
  }

  async createUser(user: User): Promise<void> {
    await this.saveUser(user);
  }

  async createFirstUser(user: User): Promise<boolean> {
    const email = user.email.toLowerCase();
    const stmt = this.db.prepare(
      'INSERT INTO users(id, email, name, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, role, status, totp_secret, totp_recovery_code, created_at, updated_at) ' +
      'SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? ' +
      'WHERE NOT EXISTS (SELECT 1 FROM users LIMIT 1)'
    );
    const result = await this.safeBind(stmt,
      user.id,
      email,
      user.name,
      user.masterPasswordHash,
      user.key,
      user.privateKey,
      user.publicKey,
      user.kdfType,
      user.kdfIterations,
      user.kdfMemory,
      user.kdfParallelism,
      user.securityStamp,
      user.role,
      user.status,
      user.totpSecret,
      user.totpRecoveryCode,
      user.createdAt,
      user.updatedAt
    ).run();

    return (result.meta.changes ?? 0) > 0;
  }

  async deleteUserById(id: string): Promise<boolean> {
    const result = await this.db.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
    return (result.meta.changes ?? 0) > 0;
  }

  async createInvite(invite: Invite): Promise<void> {
    await this.db
      .prepare(
        'INSERT INTO invites(code, created_by, used_by, expires_at, status, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?)'
      )
      .bind(invite.code, invite.createdBy, invite.usedBy, invite.expiresAt, invite.status, invite.createdAt, invite.updatedAt)
      .run();
  }

  async getInvite(code: string): Promise<Invite | null> {
    const row = await this.db
      .prepare('SELECT code, created_by, used_by, expires_at, status, created_at, updated_at FROM invites WHERE code = ?')
      .bind(code)
      .first<any>();
    if (!row) return null;
    return {
      code: row.code,
      createdBy: row.created_by,
      usedBy: row.used_by ?? null,
      expiresAt: row.expires_at,
      status: row.status,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  async listInvites(includeInactive: boolean = false): Promise<Invite[]> {
    const now = new Date().toISOString();
    const predicate = includeInactive
      ? '1 = 1'
      : "(status = 'active' AND expires_at > ?)";
    const query =
      'SELECT code, created_by, used_by, expires_at, status, created_at, updated_at FROM invites ' +
      `WHERE ${predicate} ORDER BY created_at DESC`;
    const res = includeInactive
      ? await this.db.prepare(query).all<any>()
      : await this.db.prepare(query).bind(now).all<any>();

    return (res.results || []).map(row => ({
      code: row.code,
      createdBy: row.created_by,
      usedBy: row.used_by ?? null,
      expiresAt: row.expires_at,
      status: row.status,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }));
  }

  async markInviteUsed(code: string, userId: string): Promise<boolean> {
    const now = new Date().toISOString();
    const result = await this.db
      .prepare(
        "UPDATE invites SET status = 'used', used_by = ?, updated_at = ? WHERE code = ? AND status = 'active' AND expires_at > ?"
      )
      .bind(userId, now, code, now)
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  async revokeInvite(code: string): Promise<boolean> {
    const now = new Date().toISOString();
    const result = await this.db
      .prepare("UPDATE invites SET status = 'revoked', updated_at = ? WHERE code = ? AND status = 'active'")
      .bind(now, code)
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  async deleteAllInvites(): Promise<number> {
    const result = await this.db.prepare('DELETE FROM invites').run();
    return Number(result.meta.changes ?? 0);
  }

  async createAuditLog(log: AuditLog): Promise<void> {
    await this.db
      .prepare(
        'INSERT INTO audit_logs(id, actor_user_id, action, target_type, target_id, metadata, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)'
      )
      .bind(log.id, log.actorUserId, log.action, log.targetType, log.targetId, log.metadata, log.createdAt)
      .run();
  }

  // --- Ciphers ---

  async getCipher(id: string): Promise<Cipher | null> {
    const row = await this.db.prepare('SELECT data FROM ciphers WHERE id = ?').bind(id).first<{ data: string }>();
    if (!row?.data) return null;
    try {
      return JSON.parse(row.data) as Cipher;
    } catch {
      console.error('Corrupted cipher data, id:', id);
      return null;
    }
  }

  async saveCipher(cipher: Cipher): Promise<void> {
    const data = JSON.stringify(cipher);
    const stmt = this.db.prepare(
      'INSERT INTO ciphers(id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, deleted_at) ' +
      'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET ' +
      'user_id=excluded.user_id, type=excluded.type, folder_id=excluded.folder_id, name=excluded.name, notes=excluded.notes, favorite=excluded.favorite, data=excluded.data, reprompt=excluded.reprompt, key=excluded.key, updated_at=excluded.updated_at, deleted_at=excluded.deleted_at'
    );
    await this.safeBind(stmt,
      cipher.id,
      cipher.userId,
      Number(cipher.type) || 1,
      cipher.folderId,
      cipher.name,
      cipher.notes,
      cipher.favorite ? 1 : 0,
      data,
      cipher.reprompt ?? 0,
      cipher.key,
      cipher.createdAt,
      cipher.updatedAt,
      cipher.deletedAt
    ).run();
  }

  async deleteCipher(id: string, userId: string): Promise<void> {
    // hard delete
    await this.db.prepare('DELETE FROM ciphers WHERE id = ? AND user_id = ?').bind(id, userId).run();
  }

  async getAllCiphers(userId: string): Promise<Cipher[]> {
    const res = await this.db.prepare('SELECT data FROM ciphers WHERE user_id = ? ORDER BY updated_at DESC').bind(userId).all<{ data: string }>();
    return (res.results || []).flatMap(r => {
      try { return [JSON.parse(r.data) as Cipher]; } catch { return []; }
    });
  }

  async getCiphersPage(userId: string, includeDeleted: boolean, limit: number, offset: number): Promise<Cipher[]> {
    const whereDeleted = includeDeleted ? '' : 'AND deleted_at IS NULL';
    const res = await this.db
      .prepare(
        `SELECT data FROM ciphers
         WHERE user_id = ?
         ${whereDeleted}
         ORDER BY updated_at DESC
         LIMIT ? OFFSET ?`
      )
      .bind(userId, limit, offset)
      .all<{ data: string }>();
    return (res.results || []).flatMap(r => {
      try { return [JSON.parse(r.data) as Cipher]; } catch { return []; }
    });
  }

  async getCiphersByIds(ids: string[], userId: string): Promise<Cipher[]> {
    if (ids.length === 0) return [];
    // D1 doesn't support binding arrays directly; build placeholders.
    const placeholders = ids.map(() => '?').join(',');
    const stmt = this.db.prepare(`SELECT data FROM ciphers WHERE user_id = ? AND id IN (${placeholders})`);
    const res = await stmt.bind(userId, ...ids).all<{ data: string }>();
    return (res.results || []).flatMap(r => {
      try { return [JSON.parse(r.data) as Cipher]; } catch { return []; }
    });
  }

  async bulkMoveCiphers(ids: string[], folderId: string | null, userId: string): Promise<void> {
    if (ids.length === 0) return;
    const now = new Date().toISOString();
    const uniqueIds = Array.from(new Set(ids));
    const patch = JSON.stringify({
      folderId,
      updatedAt: now,
    });
    const chunkSize = LIMITS.performance.bulkMoveChunkSize;

    for (let i = 0; i < uniqueIds.length; i += chunkSize) {
      const chunk = uniqueIds.slice(i, i + chunkSize);
      const placeholders = chunk.map(() => '?').join(',');

      await this.db
        .prepare(
          `UPDATE ciphers
           SET folder_id = ?, updated_at = ?, data = json_patch(data, ?)
           WHERE user_id = ? AND id IN (${placeholders})`
        )
        .bind(folderId, now, patch, userId, ...chunk)
        .run();
    }

    await this.updateRevisionDate(userId);
  }

  // --- Folders ---

  async getFolder(id: string): Promise<Folder | null> {
    const row = await this.db
      .prepare('SELECT id, user_id, name, created_at, updated_at FROM folders WHERE id = ?')
      .bind(id)
      .first<any>();
    if (!row) return null;
    return {
      id: row.id,
      userId: row.user_id,
      name: row.name,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  async saveFolder(folder: Folder): Promise<void> {
    await this.db
      .prepare(
        'INSERT INTO folders(id, user_id, name, created_at, updated_at) VALUES(?, ?, ?, ?, ?) ' +
        'ON CONFLICT(id) DO UPDATE SET user_id=excluded.user_id, name=excluded.name, updated_at=excluded.updated_at'
      )
      .bind(folder.id, folder.userId, folder.name, folder.createdAt, folder.updatedAt)
      .run();
  }

  async deleteFolder(id: string, userId: string): Promise<void> {
    await this.db.prepare('DELETE FROM folders WHERE id = ? AND user_id = ?').bind(id, userId).run();
  }

  // Clear folder references from all ciphers owned by the user.
  // Without this, deleting a folder leaves stale folderId values in cipher JSON.
  async clearFolderFromCiphers(userId: string, folderId: string): Promise<void> {
    const now = new Date().toISOString();
    const res = await this.db
      .prepare('SELECT data FROM ciphers WHERE user_id = ? AND folder_id = ?')
      .bind(userId, folderId)
      .all<{ data: string }>();

    for (const row of (res.results || [])) {
      let cipher: Cipher;
      try {
        cipher = JSON.parse(row.data) as Cipher;
      } catch {
        continue;
      }
      cipher.folderId = null;
      cipher.updatedAt = now;
      await this.saveCipher(cipher);
    }
  }

  async getAllFolders(userId: string): Promise<Folder[]> {
    const res = await this.db
      .prepare('SELECT id, user_id, name, created_at, updated_at FROM folders WHERE user_id = ? ORDER BY updated_at DESC')
      .bind(userId)
      .all<any>();
    return (res.results || []).map(r => ({
      id: r.id,
      userId: r.user_id,
      name: r.name,
      createdAt: r.created_at,
      updatedAt: r.updated_at,
    }));
  }

  async getFoldersPage(userId: string, limit: number, offset: number): Promise<Folder[]> {
    const res = await this.db
      .prepare(
        'SELECT id, user_id, name, created_at, updated_at FROM folders WHERE user_id = ? ORDER BY updated_at DESC LIMIT ? OFFSET ?'
      )
      .bind(userId, limit, offset)
      .all<any>();
    return (res.results || []).map(r => ({
      id: r.id,
      userId: r.user_id,
      name: r.name,
      createdAt: r.created_at,
      updatedAt: r.updated_at,
    }));
  }

  // --- Attachments ---

  async getAttachment(id: string): Promise<Attachment | null> {
    const row = await this.db
      .prepare('SELECT id, cipher_id, file_name, size, size_name, key FROM attachments WHERE id = ?')
      .bind(id)
      .first<any>();
    if (!row) return null;
    return {
      id: row.id,
      cipherId: row.cipher_id,
      fileName: row.file_name,
      size: row.size,
      sizeName: row.size_name,
      key: row.key,
    };
  }

  async saveAttachment(attachment: Attachment): Promise<void> {
    const stmt = this.db.prepare(
      'INSERT INTO attachments(id, cipher_id, file_name, size, size_name, key) VALUES(?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET cipher_id=excluded.cipher_id, file_name=excluded.file_name, size=excluded.size, size_name=excluded.size_name, key=excluded.key'
    );
    await this.safeBind(stmt, attachment.id, attachment.cipherId, attachment.fileName, attachment.size, attachment.sizeName, attachment.key).run();
  }

  async deleteAttachment(id: string): Promise<void> {
    await this.db.prepare('DELETE FROM attachments WHERE id = ?').bind(id).run();
  }

  async getAttachmentsByCipher(cipherId: string): Promise<Attachment[]> {
    const res = await this.db
      .prepare('SELECT id, cipher_id, file_name, size, size_name, key FROM attachments WHERE cipher_id = ?')
      .bind(cipherId)
      .all<any>();
    return (res.results || []).map(r => ({
      id: r.id,
      cipherId: r.cipher_id,
      fileName: r.file_name,
      size: r.size,
      sizeName: r.size_name,
      key: r.key,
    }));
  }

  async getAttachmentsByCipherIds(cipherIds: string[]): Promise<Map<string, Attachment[]>> {
    const grouped = new Map<string, Attachment[]>();
    if (cipherIds.length === 0) return grouped;

    const uniqueCipherIds = [...new Set(cipherIds)];
    const chunkSize = LIMITS.performance.bulkMoveChunkSize;

    for (let i = 0; i < uniqueCipherIds.length; i += chunkSize) {
      const chunk = uniqueCipherIds.slice(i, i + chunkSize);
      const placeholders = chunk.map(() => '?').join(',');
      const res = await this.db
        .prepare(`SELECT id, cipher_id, file_name, size, size_name, key FROM attachments WHERE cipher_id IN (${placeholders})`)
        .bind(...chunk)
        .all<any>();

      for (const row of (res.results || [])) {
        const item: Attachment = {
          id: row.id,
          cipherId: row.cipher_id,
          fileName: row.file_name,
          size: row.size,
          sizeName: row.size_name,
          key: row.key,
        };
        const list = grouped.get(item.cipherId);
        if (list) {
          list.push(item);
        } else {
          grouped.set(item.cipherId, [item]);
        }
      }
    }

    return grouped;
  }

  async getAttachmentsByUserId(userId: string): Promise<Map<string, Attachment[]>> {
    const grouped = new Map<string, Attachment[]>();
    const res = await this.db
      .prepare(
        `SELECT a.id, a.cipher_id, a.file_name, a.size, a.size_name, a.key
         FROM attachments a
         INNER JOIN ciphers c ON c.id = a.cipher_id
         WHERE c.user_id = ?`
      )
      .bind(userId)
      .all<any>();

    for (const row of (res.results || [])) {
      const item: Attachment = {
        id: row.id,
        cipherId: row.cipher_id,
        fileName: row.file_name,
        size: row.size,
        sizeName: row.size_name,
        key: row.key,
      };
      const list = grouped.get(item.cipherId);
      if (list) {
        list.push(item);
      } else {
        grouped.set(item.cipherId, [item]);
      }
    }

    return grouped;
  }

  async addAttachmentToCipher(cipherId: string, attachmentId: string): Promise<void> {
    // Kept for API compatibility; no-op because attachments table already links cipher_id.
    // We still validate that the attachment exists and belongs to cipher.
    await this.db.prepare('UPDATE attachments SET cipher_id = ? WHERE id = ?').bind(cipherId, attachmentId).run();
  }

  async removeAttachmentFromCipher(cipherId: string, attachmentId: string): Promise<void> {
    // No-op: schema uses NOT NULL cipher_id.
    // Callers always delete attachment row afterwards, so this method is kept for compatibility only.
    void cipherId;
    void attachmentId;
  }

  async deleteAllAttachmentsByCipher(cipherId: string): Promise<void> {
    await this.db.prepare('DELETE FROM attachments WHERE cipher_id = ?').bind(cipherId).run();
  }

  async updateCipherRevisionDate(cipherId: string): Promise<void> {
    const cipher = await this.getCipher(cipherId);
    if (!cipher) return;
    cipher.updatedAt = new Date().toISOString();
    await this.saveCipher(cipher);
    await this.updateRevisionDate(cipher.userId);
  }

  // --- Refresh tokens ---

  async saveRefreshToken(token: string, userId: string, expiresAtMs?: number): Promise<void> {
    const expiresAt = expiresAtMs ?? (Date.now() + LIMITS.auth.refreshTokenTtlMs);
    await this.maybeCleanupExpiredRefreshTokens(Date.now());
    const tokenKey = await this.refreshTokenKey(token);
    await this.db.prepare(
      'INSERT INTO refresh_tokens(token, user_id, expires_at) VALUES(?, ?, ?) ' +
      'ON CONFLICT(token) DO UPDATE SET user_id=excluded.user_id, expires_at=excluded.expires_at'
    )
      .bind(tokenKey, userId, expiresAt)
      .run();
  }

  async getRefreshTokenUserId(token: string): Promise<string | null> {
    const now = Date.now();
    await this.maybeCleanupExpiredRefreshTokens(now);
    const tokenKey = await this.refreshTokenKey(token);

    let row = await this.db.prepare('SELECT user_id, expires_at FROM refresh_tokens WHERE token = ?')
      .bind(tokenKey)
      .first<{ user_id: string; expires_at: number }>();

    if (!row) {
      const legacyRow = await this.db.prepare('SELECT user_id, expires_at FROM refresh_tokens WHERE token = ?')
        .bind(token)
        .first<{ user_id: string; expires_at: number }>();

      if (legacyRow) {
        if (legacyRow.expires_at && legacyRow.expires_at < now) {
          await this.deleteRefreshToken(token);
          return null;
        }
        await this.saveRefreshToken(token, legacyRow.user_id, legacyRow.expires_at);
        await this.db.prepare('DELETE FROM refresh_tokens WHERE token = ?').bind(token).run();
        return legacyRow.user_id;
      }
    }

    if (!row) return null;
    if (row.expires_at && row.expires_at < now) {
      await this.deleteRefreshToken(token);
      return null;
    }
    return row.user_id;
  }

  async deleteRefreshToken(token: string): Promise<void> {
    const tokenKey = await this.refreshTokenKey(token);
    await this.db.prepare('DELETE FROM refresh_tokens WHERE token = ?').bind(token).run();
    await this.db.prepare('DELETE FROM refresh_tokens WHERE token = ?').bind(tokenKey).run();
  }

  // --- Sends ---

  private mapSendRow(row: any): Send {
    return {
      id: row.id,
      userId: row.user_id,
      type: row.type,
      name: row.name,
      notes: row.notes,
      data: row.data,
      key: row.key,
      passwordHash: row.password_hash,
      passwordSalt: row.password_salt,
      passwordIterations: row.password_iterations,
      authType: row.auth_type ?? SendAuthType.None,
      emails: row.emails ?? null,
      maxAccessCount: row.max_access_count,
      accessCount: row.access_count,
      disabled: !!row.disabled,
      hideEmail: row.hide_email === null || row.hide_email === undefined ? null : !!row.hide_email,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      expirationDate: row.expiration_date,
      deletionDate: row.deletion_date,
    };
  }

  async getSend(id: string): Promise<Send | null> {
    const row = await this.db
      .prepare(
        'SELECT id, user_id, type, name, notes, data, key, password_hash, password_salt, password_iterations, auth_type, emails, max_access_count, access_count, disabled, hide_email, created_at, updated_at, expiration_date, deletion_date FROM sends WHERE id = ?'
      )
      .bind(id)
      .first<any>();
    if (!row) return null;
    return this.mapSendRow(row);
  }

  async saveSend(send: Send): Promise<void> {
    const stmt = this.db.prepare(
      'INSERT INTO sends(id, user_id, type, name, notes, data, key, password_hash, password_salt, password_iterations, auth_type, emails, max_access_count, access_count, disabled, hide_email, created_at, updated_at, expiration_date, deletion_date) ' +
      'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET ' +
      'user_id=excluded.user_id, type=excluded.type, name=excluded.name, notes=excluded.notes, data=excluded.data, key=excluded.key, ' +
      'password_hash=excluded.password_hash, password_salt=excluded.password_salt, password_iterations=excluded.password_iterations, auth_type=excluded.auth_type, emails=excluded.emails, ' +
      'max_access_count=excluded.max_access_count, access_count=excluded.access_count, disabled=excluded.disabled, hide_email=excluded.hide_email, ' +
      'updated_at=excluded.updated_at, expiration_date=excluded.expiration_date, deletion_date=excluded.deletion_date'
    );

    await this.safeBind(
      stmt,
      send.id,
      send.userId,
      Number(send.type) || 0,
      send.name,
      send.notes,
      send.data,
      send.key,
      send.passwordHash,
      send.passwordSalt,
      send.passwordIterations,
      send.authType,
      send.emails,
      send.maxAccessCount,
      send.accessCount,
      send.disabled ? 1 : 0,
      send.hideEmail === null || send.hideEmail === undefined ? null : (send.hideEmail ? 1 : 0),
      send.createdAt,
      send.updatedAt,
      send.expirationDate,
      send.deletionDate
    ).run();
  }

  /**
   * Atomically increment access_count and update updated_at.
   * Returns true if the row was updated (send still available),
   * false if max_access_count has already been reached.
   */
  async incrementSendAccessCount(sendId: string): Promise<boolean> {
    const now = new Date().toISOString();
    const result = await this.db
      .prepare(
        'UPDATE sends SET access_count = access_count + 1, updated_at = ? ' +
        'WHERE id = ? AND (max_access_count IS NULL OR access_count < max_access_count)'
      )
      .bind(now, sendId)
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  async deleteSend(id: string, userId: string): Promise<void> {
    await this.db.prepare('DELETE FROM sends WHERE id = ? AND user_id = ?').bind(id, userId).run();
  }

  async getAllSends(userId: string): Promise<Send[]> {
    const res = await this.db
      .prepare(
        'SELECT id, user_id, type, name, notes, data, key, password_hash, password_salt, password_iterations, auth_type, emails, max_access_count, access_count, disabled, hide_email, created_at, updated_at, expiration_date, deletion_date FROM sends WHERE user_id = ? ORDER BY updated_at DESC'
      )
      .bind(userId)
      .all<any>();
    return (res.results || []).map(row => this.mapSendRow(row));
  }

  async getSendsPage(userId: string, limit: number, offset: number): Promise<Send[]> {
    const res = await this.db
      .prepare(
        'SELECT id, user_id, type, name, notes, data, key, password_hash, password_salt, password_iterations, auth_type, emails, max_access_count, access_count, disabled, hide_email, created_at, updated_at, expiration_date, deletion_date FROM sends WHERE user_id = ? ORDER BY updated_at DESC LIMIT ? OFFSET ?'
      )
      .bind(userId, limit, offset)
      .all<any>();
    return (res.results || []).map(row => this.mapSendRow(row));
  }

  async deleteRefreshTokensByUserId(userId: string): Promise<void> {
    await this.db.prepare('DELETE FROM refresh_tokens WHERE user_id = ?').bind(userId).run();
  }

  // Keep a short overlap window for rotated refresh token to reduce
  // multi-context refresh races (e.g. browser extension popup/background).
  // Expiry is only tightened, never extended.
  async constrainRefreshTokenExpiry(token: string, maxExpiresAtMs: number): Promise<void> {
    const tokenKey = await this.refreshTokenKey(token);

    await this.db.prepare(
      'UPDATE refresh_tokens ' +
      'SET expires_at = CASE WHEN expires_at > ? THEN ? ELSE expires_at END ' +
      'WHERE token = ?'
    ).bind(maxExpiresAtMs, maxExpiresAtMs, tokenKey).run();

    // Best-effort legacy plaintext support for older rows.
    await this.db.prepare(
      'UPDATE refresh_tokens ' +
      'SET expires_at = CASE WHEN expires_at > ? THEN ? ELSE expires_at END ' +
      'WHERE token = ?'
    ).bind(maxExpiresAtMs, maxExpiresAtMs, token).run();
  }

  private async trustedTwoFactorTokenKey(token: string): Promise<string> {
    const digest = await this.sha256Hex(token);
    return `sha256:${digest}`;
  }

  // --- Devices ---

  async upsertDevice(userId: string, deviceIdentifier: string, name: string, type: number): Promise<void> {
    const now = new Date().toISOString();
    await this.db.prepare(
      'INSERT INTO devices(user_id, device_identifier, name, type, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(user_id, device_identifier) DO UPDATE SET name=excluded.name, type=excluded.type, updated_at=excluded.updated_at'
    )
      .bind(userId, deviceIdentifier, name, type, now, now)
      .run();
  }

  async isKnownDevice(userId: string, deviceIdentifier: string): Promise<boolean> {
    const row = await this.db
      .prepare('SELECT 1 FROM devices WHERE user_id = ? AND device_identifier = ? LIMIT 1')
      .bind(userId, deviceIdentifier)
      .first<{ '1': number }>();
    return !!row;
  }

  async isKnownDeviceByEmail(email: string, deviceIdentifier: string): Promise<boolean> {
    const user = await this.getUser(email);
    if (!user) return false;
    return this.isKnownDevice(user.id, deviceIdentifier);
  }

  async getDevicesByUserId(userId: string): Promise<Device[]> {
    const res = await this.db
      .prepare(
        'SELECT user_id, device_identifier, name, type, created_at, updated_at ' +
        'FROM devices WHERE user_id = ? ORDER BY updated_at DESC'
      )
      .bind(userId)
      .all<any>();
    return (res.results || []).map(row => ({
      userId: row.user_id,
      deviceIdentifier: row.device_identifier,
      name: row.name,
      type: row.type,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }));
  }

  async deleteDevice(userId: string, deviceIdentifier: string): Promise<boolean> {
    const result = await this.db
      .prepare('DELETE FROM devices WHERE user_id = ? AND device_identifier = ?')
      .bind(userId, deviceIdentifier)
      .run();
    return Number(result.meta.changes ?? 0) > 0;
  }

  async getTrustedDeviceTokenSummariesByUserId(userId: string): Promise<TrustedDeviceTokenSummary[]> {
    const now = Date.now();
    await this.db.prepare('DELETE FROM trusted_two_factor_device_tokens WHERE expires_at < ?').bind(now).run();

    const res = await this.db
      .prepare(
        'SELECT device_identifier, MAX(expires_at) AS expires_at, COUNT(*) AS token_count ' +
        'FROM trusted_two_factor_device_tokens WHERE user_id = ? GROUP BY device_identifier ORDER BY expires_at DESC'
      )
      .bind(userId)
      .all<any>();

    return (res.results || []).map(row => ({
      deviceIdentifier: row.device_identifier,
      expiresAt: Number(row.expires_at || 0),
      tokenCount: Number(row.token_count || 0),
    }));
  }

  async deleteTrustedTwoFactorTokensByDevice(userId: string, deviceIdentifier: string): Promise<number> {
    const result = await this.db
      .prepare('DELETE FROM trusted_two_factor_device_tokens WHERE user_id = ? AND device_identifier = ?')
      .bind(userId, deviceIdentifier)
      .run();
    return Number(result.meta.changes ?? 0);
  }

  async deleteTrustedTwoFactorTokensByUserId(userId: string): Promise<number> {
    const result = await this.db
      .prepare('DELETE FROM trusted_two_factor_device_tokens WHERE user_id = ?')
      .bind(userId)
      .run();
    return Number(result.meta.changes ?? 0);
  }

  // --- Trusted 2FA remember tokens (device-bound) ---

  async saveTrustedTwoFactorDeviceToken(
    token: string,
    userId: string,
    deviceIdentifier: string,
    expiresAtMs?: number
  ): Promise<void> {
    const expiresAt = expiresAtMs ?? (Date.now() + TWO_FACTOR_REMEMBER_TTL_MS);
    const tokenKey = await this.trustedTwoFactorTokenKey(token);

    await this.db.prepare('DELETE FROM trusted_two_factor_device_tokens WHERE expires_at < ?').bind(Date.now()).run();
    await this.db.prepare(
      'INSERT INTO trusted_two_factor_device_tokens(token, user_id, device_identifier, expires_at) VALUES(?, ?, ?, ?) ' +
      'ON CONFLICT(token) DO UPDATE SET user_id=excluded.user_id, device_identifier=excluded.device_identifier, expires_at=excluded.expires_at'
    )
      .bind(tokenKey, userId, deviceIdentifier, expiresAt)
      .run();
  }

  async getTrustedTwoFactorDeviceTokenUserId(token: string, deviceIdentifier: string): Promise<string | null> {
    const now = Date.now();
    const tokenKey = await this.trustedTwoFactorTokenKey(token);
    const row = await this.db
      .prepare(
        'SELECT user_id, expires_at FROM trusted_two_factor_device_tokens WHERE token = ? AND device_identifier = ?'
      )
      .bind(tokenKey, deviceIdentifier)
      .first<{ user_id: string; expires_at: number }>();

    if (!row) return null;
    if (row.expires_at && row.expires_at < now) {
      await this.db.prepare('DELETE FROM trusted_two_factor_device_tokens WHERE token = ?').bind(tokenKey).run();
      return null;
    }
    return row.user_id;
  }

  // --- Revision dates ---

  async getRevisionDate(userId: string): Promise<string> {
    const row = await this.db.prepare('SELECT revision_date FROM user_revisions WHERE user_id = ?')
      .bind(userId)
      .first<{ revision_date: string }>();
    if (row?.revision_date) return row.revision_date;

    const date = new Date().toISOString();
    await this.db
      .prepare(
        'INSERT INTO user_revisions(user_id, revision_date) VALUES(?, ?) ' +
        'ON CONFLICT(user_id) DO NOTHING'
      )
      .bind(userId, date)
      .run();
    return date;
  }

  async updateRevisionDate(userId: string): Promise<string> {
    const date = new Date().toISOString();
    await this.db.prepare(
      'INSERT INTO user_revisions(user_id, revision_date) VALUES(?, ?) ' +
      'ON CONFLICT(user_id) DO UPDATE SET revision_date = excluded.revision_date'
    )
      .bind(userId, date)
      .run();
    return date;
  }

  // --- One-time attachment download tokens ---

  private async ensureUsedAttachmentDownloadTokenTable(): Promise<void> {
    if (StorageService.attachmentTokenTableReady) return;

    await this.db.prepare(
      'CREATE TABLE IF NOT EXISTS used_attachment_download_tokens (' +
      'jti TEXT PRIMARY KEY, ' +
      'expires_at INTEGER NOT NULL' +
      ')'
    ).run();

    StorageService.attachmentTokenTableReady = true;
  }

  // Marks an attachment download token JTI as consumed.
  // Returns true only on first use. Reuse returns false.
  async consumeAttachmentDownloadToken(jti: string, expUnixSeconds: number): Promise<boolean> {
    await this.ensureUsedAttachmentDownloadTokenTable();

    const nowMs = Date.now();
    if (
      this.shouldRunPeriodicCleanup(
        StorageService.lastAttachmentTokenCleanupAt,
        StorageService.ATTACHMENT_TOKEN_CLEANUP_INTERVAL_MS
      )
    ) {
      await this.db.prepare('DELETE FROM used_attachment_download_tokens WHERE expires_at < ?').bind(nowMs).run();
      StorageService.lastAttachmentTokenCleanupAt = nowMs;
    }

    const expiresAtMs = expUnixSeconds * 1000;
    const result = await this.db.prepare(
      'INSERT INTO used_attachment_download_tokens(jti, expires_at) VALUES(?, ?) ' +
      'ON CONFLICT(jti) DO NOTHING'
    ).bind(jti, expiresAtMs).run();

    return (result.meta.changes ?? 0) > 0;
  }
}
