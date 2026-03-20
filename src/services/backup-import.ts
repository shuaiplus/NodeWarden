import type { Env } from '../types';
import { StorageService } from './storage';
import { KV_MAX_OBJECT_BYTES, deleteBlobObject, getAttachmentObjectKey, getBlobStorageKind, putBlobObject } from './blob-store';
import { normalizeImportedBackupSettings } from './backup-config';
import {
  type BackupManifestAttachmentBlob,
  type BackupPayload,
  parseBackupArchive,
  validateBackupPayloadContents,
} from './backup-archive';

type SqlRow = Record<string, string | number | null>;

export interface BackupImportResultBody {
  object: 'instance-backup-import';
  imported: {
    config: number;
    users: number;
    userRevisions: number;
    folders: number;
    ciphers: number;
    attachments: number;
    attachmentFiles: number;
  };
  skipped: {
    reason: string | null;
    attachments: number;
    items: Array<{
      kind: 'attachment';
      path: string;
      sizeBytes: number;
    }>;
  };
}

export interface BackupImportExecutionResult {
  result: BackupImportResultBody;
  auditActorUserId: string | null;
}

async function queryRows(db: D1Database, sql: string, ...values: unknown[]): Promise<SqlRow[]> {
  const response = await db.prepare(sql).bind(...values).all<SqlRow>();
  return (response.results || []).map((row) => ({ ...row }));
}

async function ensureImportTargetIsFresh(db: D1Database): Promise<void> {
  const counts = await Promise.all([
    db.prepare('SELECT COUNT(*) AS count FROM ciphers').first<{ count: number }>(),
    db.prepare('SELECT COUNT(*) AS count FROM folders').first<{ count: number }>(),
    db.prepare('SELECT COUNT(*) AS count FROM attachments').first<{ count: number }>(),
    db.prepare('SELECT COUNT(*) AS count FROM sends').first<{ count: number }>(),
  ]);
  const total = counts.reduce((sum, row) => sum + Number(row?.count || 0), 0);
  if (total > 0) {
    throw new Error('Backup import requires a fresh instance with no vault or send data');
  }
}

function buildResetImportTargetStatements(db: D1Database): D1PreparedStatement[] {
  return [
    'DELETE FROM attachments',
    'DELETE FROM ciphers',
    'DELETE FROM folders',
    'DELETE FROM sends',
    'DELETE FROM trusted_two_factor_device_tokens',
    'DELETE FROM devices',
    'DELETE FROM refresh_tokens',
    'DELETE FROM invites',
    'DELETE FROM audit_logs',
    'DELETE FROM user_revisions',
    'DELETE FROM users',
    'DELETE FROM config',
    'DELETE FROM login_attempts_ip',
    'DELETE FROM api_rate_limits',
    'DELETE FROM used_attachment_download_tokens',
  ].map((sql) => db.prepare(sql));
}

async function collectCurrentBlobKeys(db: D1Database): Promise<Set<string>> {
  const keys = new Set<string>();
  const attachmentRows = await queryRows(
    db,
    `SELECT a.id, a.cipher_id
     FROM attachments a
     INNER JOIN ciphers c ON c.id = a.cipher_id`
  );
  for (const row of attachmentRows) {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    if (!cipherId || !attachmentId) continue;
    keys.add(getAttachmentObjectKey(cipherId, attachmentId));
  }
  return keys;
}

const KV_BLOB_SKIP_REASON = 'Cloudflare KV object size limit (25 MB)';
const BLOB_STORAGE_UNAVAILABLE_SKIP_REASON = 'Attachment storage is not configured';
const ATTACHMENT_RESTORE_FAILED_REASON = 'Some attachments could not be restored and were skipped';

interface BackupImportSkipSummary {
  reason: string | null;
  attachments: number;
  items: Array<{
    kind: 'attachment';
    path: string;
    sizeBytes: number;
  }>;
}

interface PreparedBackupImportPayload {
  payload: BackupPayload;
  skipped: BackupImportSkipSummary;
}

interface AttachmentRestoreResult {
  imported: number;
  restoredAttachments: SqlRow[];
  skipped: BackupImportSkipSummary;
}

interface RemoteAttachmentSource {
  hasAttachment(blobName: string): Promise<boolean>;
  loadAttachment(blobName: string): Promise<Uint8Array | null>;
}

function prepareImportPayloadForTarget(env: Env, payload: BackupPayload, files: Record<string, Uint8Array>): PreparedBackupImportPayload {
  const storageKind = getBlobStorageKind(env);
  if (storageKind === 'r2') {
    return {
      payload,
      skipped: {
        reason: null,
        attachments: 0,
        items: [],
      },
    };
  }

  if (storageKind === null) {
    const skippedItems = (payload.db.attachments || []).map((row) => {
      const cipherId = String(row.cipher_id || '').trim();
      const attachmentId = String(row.id || '').trim();
      return {
        kind: 'attachment' as const,
        path: `attachments/${cipherId}/${attachmentId}.bin`,
        sizeBytes: Number(row.size || 0) || 0,
      };
    });

    return {
      payload: {
        ...payload,
        db: {
          ...payload.db,
          attachments: [],
        },
      },
      skipped: {
        reason: skippedItems.length ? BLOB_STORAGE_UNAVAILABLE_SKIP_REASON : null,
        attachments: skippedItems.length,
        items: skippedItems,
      },
    };
  }

  const oversizedAttachmentPaths = new Set<string>();
  const skippedItems: BackupImportSkipSummary['items'] = [];

  for (const entry of Object.keys(files)) {
    if (!entry.endsWith('.bin')) continue;
    const sizeBytes = files[entry].byteLength;
    if (sizeBytes <= KV_MAX_OBJECT_BYTES) continue;
    if (entry.startsWith('attachments/')) {
      oversizedAttachmentPaths.add(entry);
      skippedItems.push({ kind: 'attachment', path: entry, sizeBytes });
    }
  }

  const nextAttachments = (payload.db.attachments || []).filter((row) => {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    if (!cipherId || !attachmentId) return false;
    return !oversizedAttachmentPaths.has(`attachments/${cipherId}/${attachmentId}.bin`);
  });

  const nextPayload: BackupPayload = {
    ...payload,
    db: {
      ...payload.db,
      attachments: nextAttachments,
    },
  };

  const needsKvBlobStorage = nextAttachments.length > 0;

  if (needsKvBlobStorage && !env.ATTACHMENTS_KV) {
    throw new Error('Backup restore requires ATTACHMENTS_KV when using KV blob storage');
  }

  return {
    payload: nextPayload,
    skipped: {
      reason: skippedItems.length ? KV_BLOB_SKIP_REASON : null,
      attachments: skippedItems.length,
      items: skippedItems,
    },
  };
}

function buildInsertStatements(db: D1Database, table: string, columns: string[], rows: SqlRow[], upsert = false): D1PreparedStatement[] {
  if (!rows.length) return [];
  const placeholders = `(${columns.map(() => '?').join(', ')})`;
  const sql = `INSERT ${upsert ? 'OR REPLACE ' : ''}INTO ${table} (${columns.join(', ')}) VALUES ${placeholders}`;
  return rows.map((row) => db.prepare(sql).bind(...columns.map((column) => row[column] ?? null)));
}

async function restoreBlobFiles(env: Env, db: BackupPayload['db'], files: Record<string, Uint8Array>): Promise<AttachmentRestoreResult> {
  const restoredAttachments: SqlRow[] = [];
  const skippedItems: BackupImportSkipSummary['items'] = [];

  for (const row of db.attachments || []) {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    if (!cipherId || !attachmentId) continue;
    const key = `attachments/${cipherId}/${attachmentId}.bin`;
    const bytes = files[key];
    if (!bytes) {
      skippedItems.push({
        kind: 'attachment',
        path: key,
        sizeBytes: Number(row.size || 0) || 0,
      });
      continue;
    }
    try {
      await putBlobObject(env, getAttachmentObjectKey(cipherId, attachmentId), bytes, {
        size: bytes.byteLength,
        contentType: 'application/octet-stream',
      });
      restoredAttachments.push(row);
    } catch {
      skippedItems.push({
        kind: 'attachment',
        path: key,
        sizeBytes: bytes.byteLength,
      });
    }
  }

  return {
    imported: restoredAttachments.length,
    restoredAttachments,
    skipped: {
      reason: skippedItems.length ? ATTACHMENT_RESTORE_FAILED_REASON : null,
      attachments: skippedItems.length,
      items: skippedItems,
    },
  };
}

function buildAttachmentBlobLookup(manifest: BackupPayload['manifest']): Map<string, BackupManifestAttachmentBlob> {
  return new Map(
    (manifest.attachmentBlobs || []).map((item) => [`${item.cipherId}/${item.attachmentId}`, item])
  );
}

async function prepareRemoteAttachmentPayload(
  env: Env,
  payload: BackupPayload,
  files: Record<string, Uint8Array>,
  source: RemoteAttachmentSource
): Promise<PreparedBackupImportPayload> {
  const manifestLookup = buildAttachmentBlobLookup(payload.manifest);
  const storageKind = getBlobStorageKind(env);
  const nextAttachments: SqlRow[] = [];
  const skippedItems: BackupImportSkipSummary['items'] = [];

  for (const row of payload.db.attachments || []) {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    const lookupKey = `${cipherId}/${attachmentId}`;
    const ref = manifestLookup.get(lookupKey);
    const sizeBytes = ref?.sizeBytes || Number(row.size || 0) || 0;
    const path = ref ? `attachments/${ref.blobName}` : `attachments/${lookupKey}`;
    const inlinePath = `attachments/${cipherId}/${attachmentId}.bin`;

    if (files[inlinePath]) {
      nextAttachments.push(row);
      continue;
    }
    if (!ref) {
      skippedItems.push({ kind: 'attachment', path, sizeBytes });
      continue;
    }
    if (storageKind === 'kv' && sizeBytes > KV_MAX_OBJECT_BYTES) {
      skippedItems.push({ kind: 'attachment', path, sizeBytes });
      continue;
    }
    if (storageKind === null) {
      skippedItems.push({ kind: 'attachment', path, sizeBytes });
      continue;
    }
    if (!(await source.hasAttachment(ref.blobName))) {
      skippedItems.push({ kind: 'attachment', path, sizeBytes });
      continue;
    }
    nextAttachments.push(row);
  }

  return {
    payload: {
      ...payload,
      db: {
        ...payload.db,
        attachments: nextAttachments,
      },
    },
    skipped: {
      reason: skippedItems.length ? 'Some remote attachments were unavailable and were skipped' : null,
      attachments: skippedItems.length,
      items: skippedItems,
    },
  };
}

async function removeAttachmentRows(db: D1Database, attachmentRows: SqlRow[]): Promise<void> {
  if (!attachmentRows.length) return;
  const statements = attachmentRows
    .map((row) => {
      const attachmentId = String(row.id || '').trim();
      const cipherId = String(row.cipher_id || '').trim();
      if (!attachmentId || !cipherId) return null;
      return db.prepare('DELETE FROM attachments WHERE id = ? AND cipher_id = ?').bind(attachmentId, cipherId);
    })
    .filter((statement): statement is D1PreparedStatement => !!statement);
  if (!statements.length) return;
  await db.batch(statements);
}

async function restoreRemoteAttachmentFiles(
  env: Env,
  payload: BackupPayload,
  files: Record<string, Uint8Array>,
  source: RemoteAttachmentSource
): Promise<{
  imported: number;
  skipped: BackupImportSkipSummary;
  restoredAttachments: SqlRow[];
}> {
  const manifestLookup = buildAttachmentBlobLookup(payload.manifest);
  const restoredAttachments: SqlRow[] = [];
  const skippedItems: BackupImportSkipSummary['items'] = [];

  for (const row of payload.db.attachments || []) {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    const inlinePath = `attachments/${cipherId}/${attachmentId}.bin`;
    const ref = manifestLookup.get(`${cipherId}/${attachmentId}`);
    if (!ref && !files[inlinePath]) {
      skippedItems.push({
        kind: 'attachment',
        path: `attachments/${cipherId}/${attachmentId}`,
        sizeBytes: Number(row.size || 0) || 0,
      });
      continue;
    }
    const bytes = files[inlinePath] || (ref ? await source.loadAttachment(ref.blobName) : null);
    if (!bytes) {
      skippedItems.push({
        kind: 'attachment',
        path: ref ? `attachments/${ref.blobName}` : inlinePath,
        sizeBytes: ref?.sizeBytes || Number(row.size || 0) || 0,
      });
      continue;
    }
    try {
      await putBlobObject(env, getAttachmentObjectKey(cipherId, attachmentId), bytes, {
        size: bytes.byteLength,
        contentType: 'application/octet-stream',
      });
      restoredAttachments.push(row);
    } catch {
      skippedItems.push({
        kind: 'attachment',
        path: ref ? `attachments/${ref.blobName}` : inlinePath,
        sizeBytes: bytes.byteLength,
      });
    }
  }

  return {
    imported: restoredAttachments.length,
    restoredAttachments,
    skipped: {
      reason: skippedItems.length ? ATTACHMENT_RESTORE_FAILED_REASON : null,
      attachments: skippedItems.length,
      items: skippedItems,
    },
  };
}

async function cleanupOrphanedBlobFiles(env: Env, beforeKeys: Set<string>, afterKeys: Set<string>): Promise<void> {
  const staleKeys = Array.from(beforeKeys).filter((key) => !afterKeys.has(key));
  for (const key of staleKeys) {
    await deleteBlobObject(env, key);
  }
}

async function importBackupRows(db: D1Database, payload: BackupPayload['db']): Promise<void> {
  const statements: D1PreparedStatement[] = [
    ...buildResetImportTargetStatements(db),
    ...buildInsertStatements(db, 'config', ['key', 'value'], payload.config || [], true),
    ...buildInsertStatements(
      db,
      'users',
      ['id', 'email', 'name', 'master_password_hint', 'master_password_hash', 'key', 'private_key', 'public_key', 'kdf_type', 'kdf_iterations', 'kdf_memory', 'kdf_parallelism', 'security_stamp', 'role', 'status', 'totp_secret', 'totp_recovery_code', 'created_at', 'updated_at'],
      payload.users || []
    ),
    ...buildInsertStatements(db, 'user_revisions', ['user_id', 'revision_date'], payload.user_revisions || [], true),
    ...buildInsertStatements(db, 'folders', ['id', 'user_id', 'name', 'created_at', 'updated_at'], payload.folders || []),
    ...buildInsertStatements(
      db,
      'ciphers',
      ['id', 'user_id', 'type', 'folder_id', 'name', 'notes', 'favorite', 'data', 'reprompt', 'key', 'created_at', 'updated_at', 'deleted_at'],
      payload.ciphers || []
    ),
    ...buildInsertStatements(db, 'attachments', ['id', 'cipher_id', 'file_name', 'size', 'size_name', 'key'], payload.attachments || []),
  ];
  await db.batch(statements);
}

export async function importBackupArchiveBytes(
  archiveBytes: Uint8Array,
  env: Env,
  actorUserId: string,
  replaceExisting: boolean
): Promise<BackupImportExecutionResult> {
  const storage = new StorageService(env.DB);
  const parsed = parseBackupArchive(archiveBytes);
  validateBackupPayloadContents(parsed.payload, parsed.files);
  const prepared = prepareImportPayloadForTarget(env, parsed.payload, parsed.files);

  try {
    await ensureImportTargetIsFresh(env.DB);
  } catch (error) {
    if (!replaceExisting) {
      throw error instanceof Error ? error : new Error('Backup import requires a fresh instance');
    }
  }

  const previousBlobKeys = replaceExisting ? await collectCurrentBlobKeys(env.DB) : new Set<string>();
  const { db } = prepared.payload;
  await importBackupRows(env.DB, db);
  await normalizeImportedBackupSettings(storage, env, 'UTC');

  const restored = await restoreBlobFiles(env, db, parsed.files);
  const failedRestoreRows = (db.attachments || []).filter((row) => !restored.restoredAttachments.includes(row));
  await removeAttachmentRows(env.DB, failedRestoreRows);
  if (replaceExisting && previousBlobKeys.size) {
    await cleanupOrphanedBlobFiles(env, previousBlobKeys, await collectCurrentBlobKeys(env.DB));
  }

  await storage.setRegistered();

  return {
    auditActorUserId: (db.users || []).some((row) => String(row.id || '').trim() === actorUserId) ? actorUserId : null,
    result: {
      object: 'instance-backup-import',
      imported: {
        config: (db.config || []).length,
        users: (db.users || []).length,
        userRevisions: (db.user_revisions || []).length,
        folders: (db.folders || []).length,
        ciphers: (db.ciphers || []).length,
        attachments: restored.restoredAttachments.length,
        attachmentFiles: restored.imported,
      },
      skipped: {
        reason: restored.skipped.reason || prepared.skipped.reason,
        attachments: prepared.skipped.attachments + restored.skipped.attachments,
        items: [...prepared.skipped.items, ...restored.skipped.items],
      },
    },
  };
}

export async function importRemoteBackupArchiveBytes(
  archiveBytes: Uint8Array,
  env: Env,
  actorUserId: string,
  replaceExisting: boolean,
  source: RemoteAttachmentSource
): Promise<BackupImportExecutionResult> {
  const storage = new StorageService(env.DB);
  const parsed = parseBackupArchive(archiveBytes, { allowExternalAttachmentBlobs: true });
  const preparedRemote = await prepareRemoteAttachmentPayload(env, parsed.payload, parsed.files, source);
  validateBackupPayloadContents(preparedRemote.payload, parsed.files, { allowExternalAttachmentBlobs: true });

  try {
    await ensureImportTargetIsFresh(env.DB);
  } catch (error) {
    if (!replaceExisting) {
      throw error instanceof Error ? error : new Error('Backup import requires a fresh instance');
    }
  }

  const previousBlobKeys = replaceExisting ? await collectCurrentBlobKeys(env.DB) : new Set<string>();
  const { db } = preparedRemote.payload;
  await importBackupRows(env.DB, db);
  await normalizeImportedBackupSettings(storage, env, 'UTC');

  const restored = await restoreRemoteAttachmentFiles(env, preparedRemote.payload, parsed.files, source);
  const failedRestoreRows = (db.attachments || []).filter((row) => !restored.restoredAttachments.includes(row));
  await removeAttachmentRows(env.DB, failedRestoreRows);

  if (replaceExisting && previousBlobKeys.size) {
    await cleanupOrphanedBlobFiles(env, previousBlobKeys, await collectCurrentBlobKeys(env.DB));
  }

  await storage.setRegistered();

  const finalSkippedItems = [...preparedRemote.skipped.items, ...restored.skipped.items];
  const finalSkippedReason = finalSkippedItems.length
    ? restored.skipped.reason || preparedRemote.skipped.reason
    : null;

  return {
    auditActorUserId: (db.users || []).some((row) => String(row.id || '').trim() === actorUserId) ? actorUserId : null,
    result: {
      object: 'instance-backup-import',
      imported: {
        config: (db.config || []).length,
        users: (db.users || []).length,
        userRevisions: (db.user_revisions || []).length,
        folders: (db.folders || []).length,
        ciphers: (db.ciphers || []).length,
        attachments: restored.restoredAttachments.length,
        attachmentFiles: restored.imported,
      },
      skipped: {
        reason: finalSkippedReason,
        attachments: finalSkippedItems.length,
        items: finalSkippedItems,
      },
    },
  };
}
