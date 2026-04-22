// IMPORTANT:
// Keep this schema list in sync with migrations/0001_init.sql.
// Any new table/column/index must be added to both places together.
const SCHEMA_STATEMENTS: readonly string[] = [
  'CREATE TABLE IF NOT EXISTS users (' +
  'id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT, master_password_hint TEXT, master_password_hash TEXT NOT NULL, ' +
  'key TEXT NOT NULL, private_key TEXT, public_key TEXT, kdf_type INTEGER NOT NULL, ' +
  'kdf_iterations INTEGER NOT NULL, kdf_memory INTEGER, kdf_parallelism INTEGER, ' +
  'security_stamp TEXT NOT NULL, role TEXT NOT NULL DEFAULT \'user\', status TEXT NOT NULL DEFAULT \'active\', verify_devices INTEGER NOT NULL DEFAULT 1, totp_secret TEXT, totp_recovery_code TEXT, api_key TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)',
  'ALTER TABLE users ADD COLUMN master_password_hint TEXT',
  'ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT \'user\'',
  'ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT \'active\'',
  'ALTER TABLE users ADD COLUMN verify_devices INTEGER NOT NULL DEFAULT 1',
  'ALTER TABLE users ADD COLUMN totp_secret TEXT',
  'ALTER TABLE users ADD COLUMN totp_recovery_code TEXT',
  'ALTER TABLE users ADD COLUMN api_key TEXT',

  'CREATE TABLE IF NOT EXISTS user_revisions (' +
  'user_id TEXT PRIMARY KEY, revision_date TEXT NOT NULL, ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',

  'CREATE TABLE IF NOT EXISTS ciphers (' +
  'id TEXT PRIMARY KEY, user_id TEXT NOT NULL, type INTEGER NOT NULL, folder_id TEXT, name TEXT, notes TEXT, ' +
  'favorite INTEGER NOT NULL DEFAULT 0, data TEXT NOT NULL, reprompt INTEGER, key TEXT, ' +
  'created_at TEXT NOT NULL, updated_at TEXT NOT NULL, archived_at TEXT, deleted_at TEXT, ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',
  'ALTER TABLE ciphers ADD COLUMN archived_at TEXT',
  'CREATE INDEX IF NOT EXISTS idx_ciphers_user_updated ON ciphers(user_id, updated_at)',
  'CREATE INDEX IF NOT EXISTS idx_ciphers_user_archived ON ciphers(user_id, archived_at)',
  'CREATE INDEX IF NOT EXISTS idx_ciphers_user_deleted ON ciphers(user_id, deleted_at)',
  'CREATE INDEX IF NOT EXISTS idx_ciphers_user_deleted_updated ON ciphers(user_id, deleted_at, updated_at)',

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
  'CREATE INDEX IF NOT EXISTS idx_sends_user_updated_id ON sends(user_id, updated_at, id)',
  'ALTER TABLE sends ADD COLUMN auth_type INTEGER NOT NULL DEFAULT 2',
  'ALTER TABLE sends ADD COLUMN emails TEXT',

  'CREATE TABLE IF NOT EXISTS refresh_tokens (' +
  'token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL, device_identifier TEXT, device_session_stamp TEXT, ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',
  'CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id)',
  'ALTER TABLE refresh_tokens ADD COLUMN device_identifier TEXT',
  'ALTER TABLE refresh_tokens ADD COLUMN device_session_stamp TEXT',

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
  'user_id TEXT NOT NULL, device_identifier TEXT NOT NULL, name TEXT NOT NULL, type INTEGER NOT NULL, session_stamp TEXT, encrypted_user_key TEXT, encrypted_public_key TEXT, encrypted_private_key TEXT, banned INTEGER NOT NULL DEFAULT 0, banned_at TEXT, device_note TEXT, last_seen_at TEXT, ' +
  'created_at TEXT NOT NULL, updated_at TEXT NOT NULL, ' +
  'PRIMARY KEY (user_id, device_identifier), ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',
  'CREATE INDEX IF NOT EXISTS idx_devices_user_updated ON devices(user_id, updated_at)',
  'ALTER TABLE devices ADD COLUMN session_stamp TEXT',
  'ALTER TABLE devices ADD COLUMN encrypted_user_key TEXT',
  'ALTER TABLE devices ADD COLUMN encrypted_public_key TEXT',
  'ALTER TABLE devices ADD COLUMN encrypted_private_key TEXT',
  'ALTER TABLE devices ADD COLUMN banned INTEGER NOT NULL DEFAULT 0',
  'ALTER TABLE devices ADD COLUMN banned_at TEXT',
  'ALTER TABLE devices ADD COLUMN device_note TEXT',
  'ALTER TABLE devices ADD COLUMN last_seen_at TEXT',
  'CREATE INDEX IF NOT EXISTS idx_devices_user_last_seen ON devices(user_id, last_seen_at)',

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

async function executeSchemaStatement(db: D1Database, statement: string): Promise<void> {
  try {
    await db.prepare(statement).run();
  } catch (error) {
    const msg = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
    if (msg.includes('already exists') || msg.includes('duplicate column name')) {
      return;
    }
    throw error;
  }
}

async function ensureAdminUserExists(db: D1Database): Promise<void> {
  const admin = await db.prepare("SELECT id FROM users WHERE role = 'admin' LIMIT 1").first<{ id: string }>();
  if (admin?.id) return;

  const firstUser = await db
    .prepare('SELECT id FROM users ORDER BY created_at ASC LIMIT 1')
    .first<{ id: string }>();
  if (!firstUser?.id) return;

  await db
    .prepare("UPDATE users SET role = 'admin', updated_at = ? WHERE id = ?")
    .bind(new Date().toISOString(), firstUser.id)
    .run();
}

export async function ensureStorageSchema(db: D1Database): Promise<void> {
  await db.prepare('PRAGMA foreign_keys = ON').run();
  await db.prepare('CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)').run();
  for (const stmt of SCHEMA_STATEMENTS) {
    await executeSchemaStatement(db, stmt);
  }
  await ensureAdminUserExists(db);
}
