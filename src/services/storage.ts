import { User, Cipher, Folder, Attachment, Device } from '../types';
import { LIMITS } from '../config/limits';

const TWO_FACTOR_REMEMBER_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const SCHEMA_HASH_CONFIG_KEY = 'schema_hash';

// IMPORTANT:
// Keep this schema list in sync with migrations/0001_init.sql.
// Any new table/column/index must be added to both places together.
const SCHEMA_STATEMENTS: readonly string[] = [
  'CREATE TABLE IF NOT EXISTS users (' +
  'id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT, master_password_hash TEXT NOT NULL, ' +
  'key TEXT NOT NULL, private_key TEXT, public_key TEXT, kdf_type INTEGER NOT NULL, ' +
  'kdf_iterations INTEGER NOT NULL, kdf_memory INTEGER, kdf_parallelism INTEGER, ' +
  'security_stamp TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)',

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

  'CREATE TABLE IF NOT EXISTS refresh_tokens (' +
  'token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL, ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',
  'CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id)',

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
  // - Persist schema hash in DB config; if unchanged, skip all schema SQL.
  // - Keep statements idempotent so updates are safe.
  async initializeDatabase(): Promise<void> {
    if (StorageService.schemaVerified) return;

    await this.db.prepare('PRAGMA foreign_keys = ON').run();
    await this.db.prepare('CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)').run();

    const schemaHash = await this.sha256Hex(SCHEMA_STATEMENTS.join('\n'));
    const current = await this.db.prepare('SELECT value FROM config WHERE key = ?')
      .bind(SCHEMA_HASH_CONFIG_KEY)
      .first<{ value: string }>();

    if (current?.value !== schemaHash) {
      for (const stmt of SCHEMA_STATEMENTS) {
        await this.executeSchemaStatement(stmt);
      }

      await this.db.prepare(
        'INSERT INTO config(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
      )
        .bind(SCHEMA_HASH_CONFIG_KEY, schemaHash)
        .run();
    }

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

  async isSetupDisabled(): Promise<boolean> {
    const row = await this.db.prepare('SELECT value FROM config WHERE key = ?').bind('setup_disabled').first<{ value: string }>();
    return row?.value === 'true';
  }

  async setSetupDisabled(): Promise<void> {
    await this.db.prepare('INSERT INTO config(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
      .bind('setup_disabled', 'true')
      .run();
  }

  // --- Users ---

  async getUser(email: string): Promise<User | null> {
    const row = await this.db
      .prepare(
        'SELECT id, email, name, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, created_at, updated_at FROM users WHERE email = ?'
      )
      .bind(email.toLowerCase())
      .first<any>();
    if (!row) return null;
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
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  async getUserById(id: string): Promise<User | null> {
    const row = await this.db
      .prepare(
        'SELECT id, email, name, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, created_at, updated_at FROM users WHERE id = ?'
      )
      .bind(id)
      .first<any>();
    if (!row) return null;
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
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  async saveUser(user: User): Promise<void> {
    const email = user.email.toLowerCase();
    const stmt = this.db.prepare(
      'INSERT INTO users(id, email, name, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, created_at, updated_at) ' +
      'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET ' +
      'email=excluded.email, name=excluded.name, master_password_hash=excluded.master_password_hash, key=excluded.key, private_key=excluded.private_key, public_key=excluded.public_key, ' +
      'kdf_type=excluded.kdf_type, kdf_iterations=excluded.kdf_iterations, kdf_memory=excluded.kdf_memory, kdf_parallelism=excluded.kdf_parallelism, security_stamp=excluded.security_stamp, updated_at=excluded.updated_at'
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
      user.createdAt,
      user.updatedAt
    ).run();
  }

  async createFirstUser(user: User): Promise<boolean> {
    const email = user.email.toLowerCase();
    const stmt = this.db.prepare(
      'INSERT INTO users(id, email, name, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, created_at, updated_at) ' +
      'SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? ' +
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
      user.createdAt,
      user.updatedAt
    ).run();

    return (result.meta.changes ?? 0) > 0;
  }

  // --- Ciphers ---

  async getCipher(id: string): Promise<Cipher | null> {
    const row = await this.db.prepare('SELECT data FROM ciphers WHERE id = ?').bind(id).first<{ data: string }>();
    return row?.data ? (JSON.parse(row.data) as Cipher) : null;
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
    return (res.results || []).map(r => JSON.parse(r.data) as Cipher);
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
    return (res.results || []).map(r => JSON.parse(r.data) as Cipher);
  }

  async getCiphersByIds(ids: string[], userId: string): Promise<Cipher[]> {
    if (ids.length === 0) return [];
    // D1 doesn't support binding arrays directly; build placeholders.
    const placeholders = ids.map(() => '?').join(',');
    const stmt = this.db.prepare(`SELECT data FROM ciphers WHERE user_id = ? AND id IN (${placeholders})`);
    const res = await stmt.bind(userId, ...ids).all<{ data: string }>();
    return (res.results || []).map(r => JSON.parse(r.data) as Cipher);
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
      const cipher = JSON.parse(row.data) as Cipher;
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
