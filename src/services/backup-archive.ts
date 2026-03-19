import { zipSync, unzipSync } from 'fflate';
import type { Env } from '../types';
import {
  getAttachmentObjectKey,
  getBlobObject,
  getBlobStorageKind,
  getSendFileObjectKey,
} from './blob-store';

type SqlRow = Record<string, string | number | null>;

const BACKUP_FORMAT_VERSION = 1;
const BACKUP_APP_VERSION = '1.3.0';
// Worker-side backup export must stay well below Cloudflare CPU limits.
// Prefer store-only ZIP entries over heavier compression to keep exports reliable.
const BACKUP_TEXT_COMPRESSION_LEVEL = 1;
const BACKUP_BINARY_COMPRESSION_LEVEL = 1;
const BACKUP_R2_BLOB_READ_CONCURRENCY = 4;
const BACKUP_KV_BLOB_READ_CONCURRENCY = 4;
const BACKUP_R2_BLOB_READ_CHUNK_SIZE = 32;
const BACKUP_KV_BLOB_READ_CHUNK_SIZE = 162;
const MAX_BACKUP_ARCHIVE_BYTES = 32 * 1024 * 1024;
const MAX_BACKUP_ARCHIVE_ENTRY_COUNT = 800;
const MAX_BACKUP_EXTRACTED_BYTES = 64 * 1024 * 1024;
const MAX_BACKUP_DB_JSON_BYTES = 8 * 1024 * 1024;

export interface BackupManifest {
  formatVersion: 1;
  exportedAt: string;
  appVersion: string;
  storageKind: 'r2' | 'kv' | 'local' | null;
  tableCounts: Record<string, number>;
  includes: {
    attachments: boolean;
    sendFiles: boolean;
  };
  blobSummary: {
    attachmentFiles: number;
    sendFiles: number;
    totalBytes: number;
    largestObjectBytes: number;
  };
}

export interface BackupPayload {
  manifest: BackupManifest;
  db: {
    config: SqlRow[];
    users: SqlRow[];
    user_revisions: SqlRow[];
    folders: SqlRow[];
    ciphers: SqlRow[];
    attachments: SqlRow[];
    sends: SqlRow[];
  };
}

export interface BackupArchiveBundle {
  bytes: Uint8Array;
  fileName: string;
  manifest: BackupManifest;
}

interface BackupBlobTask {
  archivePath: string;
  objectKey: string;
  kind: 'attachment' | 'send-file';
  missingMessage: string;
}

interface BackupBlobTaskResult {
  archivePath: string;
  bytes: Uint8Array;
  kind: BackupBlobTask['kind'];
}

export function parseSendFileId(data: string | null): string | null {
  if (!data) return null;
  try {
    const parsed = JSON.parse(data) as Record<string, unknown>;
    return typeof parsed.id === 'string' && parsed.id.trim() ? parsed.id.trim() : null;
  } catch {
    return null;
  }
}

async function queryRows(db: D1Database, sql: string, ...values: unknown[]): Promise<SqlRow[]> {
  const result = await db.prepare(sql).bind(...values).all<SqlRow>();
  return (result.results || []).map((row) => ({ ...row }));
}

async function streamToBytes(stream: ReadableStream | null): Promise<Uint8Array> {
  if (!stream) return new Uint8Array();
  const buffer = await new Response(stream).arrayBuffer();
  return new Uint8Array(buffer);
}

function getBackupBlobReadConcurrency(env: Env): number {
  return getBlobStorageKind(env) === 'kv' ? BACKUP_KV_BLOB_READ_CONCURRENCY : BACKUP_R2_BLOB_READ_CONCURRENCY;
}

function getBackupBlobReadChunkSize(env: Env): number {
  return getBlobStorageKind(env) === 'kv' ? BACKUP_KV_BLOB_READ_CHUNK_SIZE : BACKUP_R2_BLOB_READ_CHUNK_SIZE;
}

async function mapWithConcurrency<T, R>(
  items: readonly T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<R>
): Promise<R[]> {
  if (!items.length) return [];

  const results = new Array<R>(items.length);
  let nextIndex = 0;

  const runWorker = async (): Promise<void> => {
    while (true) {
      const currentIndex = nextIndex;
      nextIndex += 1;
      if (currentIndex >= items.length) return;
      results[currentIndex] = await worker(items[currentIndex], currentIndex);
    }
  };

  const workerCount = Math.max(1, Math.min(concurrency, items.length));
  await Promise.all(Array.from({ length: workerCount }, () => runWorker()));
  return results;
}

async function loadBackupBlobFiles(env: Env, tasks: BackupBlobTask[]): Promise<{
  files: Record<string, Uint8Array>;
  attachmentFiles: number;
  sendFiles: number;
  totalBytes: number;
  largestObjectBytes: number;
}> {
  const files: Record<string, Uint8Array> = {};
  let attachmentFiles = 0;
  let sendFiles = 0;
  let totalBytes = 0;
  let largestObjectBytes = 0;

  const concurrency = getBackupBlobReadConcurrency(env);
  const chunkSize = getBackupBlobReadChunkSize(env);

  for (let offset = 0; offset < tasks.length; offset += chunkSize) {
    const chunk = tasks.slice(offset, offset + chunkSize);
    const loaded = await mapWithConcurrency(chunk, concurrency, async (task) => {
      const object = await getBlobObject(env, task.objectKey);
      if (!object) {
        throw new Error(task.missingMessage);
      }
      return {
        archivePath: task.archivePath,
        bytes: await streamToBytes(object.body),
        kind: task.kind,
      } satisfies BackupBlobTaskResult;
    });

    for (const item of loaded) {
      files[item.archivePath] = item.bytes;
      totalBytes += item.bytes.byteLength;
      largestObjectBytes = Math.max(largestObjectBytes, item.bytes.byteLength);
      if (item.kind === 'attachment') {
        attachmentFiles += 1;
      } else {
        sendFiles += 1;
      }
    }
  }

  return {
    files,
    attachmentFiles,
    sendFiles,
    totalBytes,
    largestObjectBytes,
  };
}

function buildBackupFileName(date: Date = new Date()): string {
  const parts = [
    date.getUTCFullYear().toString().padStart(4, '0'),
    (date.getUTCMonth() + 1).toString().padStart(2, '0'),
    date.getUTCDate().toString().padStart(2, '0'),
    date.getUTCHours().toString().padStart(2, '0'),
    date.getUTCMinutes().toString().padStart(2, '0'),
    date.getUTCSeconds().toString().padStart(2, '0'),
  ];
  return `nodewarden_backup_${parts[0]}${parts[1]}${parts[2]}_${parts[3]}${parts[4]}${parts[5]}.zip`;
}

function validateArchiveSize(bytes: Uint8Array): void {
  if (bytes.byteLength > MAX_BACKUP_ARCHIVE_BYTES) {
    throw new Error(`Backup archive is too large. The current restore limit is ${Math.floor(MAX_BACKUP_ARCHIVE_BYTES / (1024 * 1024))} MiB`);
  }
}

function getRequiredZipEntries(db: BackupPayload['db']): string[] {
  const entries: string[] = [];
  for (const row of db.attachments) {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    if (!cipherId || !attachmentId) continue;
    entries.push(`attachments/${cipherId}/${attachmentId}.bin`);
  }
  for (const row of db.sends) {
    const sendId = String(row.id || '').trim();
    const fileId = parseSendFileId(typeof row.data === 'string' ? row.data : null);
    if (!sendId || !fileId) continue;
    entries.push(`send-files/${sendId}/${fileId}.bin`);
  }
  return entries;
}

function ensureRowArray(value: unknown, table: string): SqlRow[] {
  if (!Array.isArray(value)) {
    throw new Error(`Backup archive table ${table} is invalid`);
  }
  return value as SqlRow[];
}

function createZipEntries(files: Record<string, Uint8Array>): Record<string, Uint8Array | [Uint8Array, { level: 0 | 1 | 6 }]> {
  const entries: Record<string, Uint8Array | [Uint8Array, { level: 0 | 1 | 6 }]> = {};
  for (const [path, bytes] of Object.entries(files)) {
    const isBinaryBlob = path.endsWith('.bin');
    entries[path] = [bytes, { level: isBinaryBlob ? BACKUP_BINARY_COMPRESSION_LEVEL : BACKUP_TEXT_COMPRESSION_LEVEL }];
  }
  return entries;
}

export function parseBackupArchive(bytes: Uint8Array): { payload: BackupPayload; files: Record<string, Uint8Array> } {
  validateArchiveSize(bytes);
  let zipped: Record<string, Uint8Array>;
  try {
    zipped = unzipSync(bytes);
  } catch {
    throw new Error('Invalid backup archive');
  }

  const entryNames = Object.keys(zipped);
  if (entryNames.length > MAX_BACKUP_ARCHIVE_ENTRY_COUNT) {
    throw new Error('Backup archive contains too many files');
  }

  let totalExtractedBytes = 0;
  for (const entry of entryNames) {
    const entryBytes = zipped[entry];
    totalExtractedBytes += entryBytes.byteLength;
    if (entry === 'db.json' && entryBytes.byteLength > MAX_BACKUP_DB_JSON_BYTES) {
      throw new Error('Backup archive database payload is too large');
    }
    if (totalExtractedBytes > MAX_BACKUP_EXTRACTED_BYTES) {
      throw new Error('Backup archive expands beyond the current restore limit');
    }
  }

  const manifestBytes = zipped['manifest.json'];
  const dbBytes = zipped['db.json'];
  if (!manifestBytes || !dbBytes) {
    throw new Error('Backup archive is missing manifest.json or db.json');
  }

  const decoder = new TextDecoder();
  let manifest: BackupManifest;
  let db: BackupPayload['db'];
  try {
    manifest = JSON.parse(decoder.decode(manifestBytes)) as BackupManifest;
    db = JSON.parse(decoder.decode(dbBytes)) as BackupPayload['db'];
  } catch {
    throw new Error('Backup archive contains invalid JSON metadata');
  }

  if (manifest?.formatVersion !== BACKUP_FORMAT_VERSION) {
    throw new Error('Unsupported backup format version');
  }
  if (!db || typeof db !== 'object') {
    throw new Error('Backup archive database payload is invalid');
  }

  const requiredEntries = getRequiredZipEntries(db);
  for (const entry of requiredEntries) {
    if (!zipped[entry]) {
      throw new Error(`Backup archive is missing required file: ${entry}`);
    }
  }

  return {
    payload: { manifest, db },
    files: zipped,
  };
}

export function validateBackupPayloadContents(payload: BackupPayload, files: Record<string, Uint8Array>): void {
  const configRows = ensureRowArray(payload.db.config, 'config');
  const userRows = ensureRowArray(payload.db.users, 'users');
  const revisionRows = ensureRowArray(payload.db.user_revisions, 'user_revisions');
  const folderRows = ensureRowArray(payload.db.folders, 'folders');
  const cipherRows = ensureRowArray(payload.db.ciphers, 'ciphers');
  const attachmentRows = ensureRowArray(payload.db.attachments, 'attachments');
  const sendRows = ensureRowArray(payload.db.sends, 'sends');

  const userIds = new Set<string>();
  for (const row of userRows) {
    const id = String(row.id || '').trim();
    const email = String(row.email || '').trim();
    if (!id || !email) throw new Error('Backup archive contains an invalid user row');
    if (userIds.has(id)) throw new Error(`Backup archive contains duplicate user id: ${id}`);
    userIds.add(id);
  }

  for (const row of configRows) {
    const key = String(row.key || '').trim();
    if (!key) throw new Error('Backup archive contains an invalid config row');
  }

  for (const row of revisionRows) {
    const userId = String(row.user_id || '').trim();
    if (!userId || !userIds.has(userId)) {
      throw new Error(`Backup archive contains a revision for an unknown user: ${userId || '(empty)'}`);
    }
  }

  const folderIds = new Set<string>();
  for (const row of folderRows) {
    const id = String(row.id || '').trim();
    const userId = String(row.user_id || '').trim();
    if (!id || !userIds.has(userId)) throw new Error('Backup archive contains an invalid folder row');
    if (folderIds.has(id)) throw new Error(`Backup archive contains duplicate folder id: ${id}`);
    folderIds.add(id);
  }

  const cipherIds = new Set<string>();
  for (const row of cipherRows) {
    const id = String(row.id || '').trim();
    const userId = String(row.user_id || '').trim();
    const folderId = String(row.folder_id || '').trim();
    if (!id || !userIds.has(userId)) throw new Error('Backup archive contains an invalid cipher row');
    if (folderId && !folderIds.has(folderId)) {
      throw new Error(`Backup archive contains a cipher for an unknown folder: ${folderId}`);
    }
    if (cipherIds.has(id)) throw new Error(`Backup archive contains duplicate cipher id: ${id}`);
    cipherIds.add(id);
  }

  for (const row of attachmentRows) {
    const id = String(row.id || '').trim();
    const cipherId = String(row.cipher_id || '').trim();
    if (!id || !cipherId || !cipherIds.has(cipherId)) {
      throw new Error('Backup archive contains an invalid attachment row');
    }
    if (!files[`attachments/${cipherId}/${id}.bin`]) {
      throw new Error(`Backup archive is missing required file: attachments/${cipherId}/${id}.bin`);
    }
  }

  const sendIds = new Set<string>();
  for (const row of sendRows) {
    const id = String(row.id || '').trim();
    const userId = String(row.user_id || '').trim();
    if (!id || !userIds.has(userId)) throw new Error('Backup archive contains an invalid send row');
    if (sendIds.has(id)) throw new Error(`Backup archive contains duplicate send id: ${id}`);
    sendIds.add(id);
    const fileId = parseSendFileId(typeof row.data === 'string' ? row.data : null);
    if (fileId && !files[`send-files/${id}/${fileId}.bin`]) {
      throw new Error(`Backup archive is missing required file: send-files/${id}/${fileId}.bin`);
    }
  }
}

export async function buildBackupArchive(env: Env, date: Date = new Date()): Promise<BackupArchiveBundle> {
  const encoder = new TextEncoder();
  const [configRows, userRows, revisionRows, folderRows, cipherRows, attachmentRows, sendRows] = await Promise.all([
    queryRows(env.DB, 'SELECT key, value FROM config ORDER BY key ASC'),
    queryRows(env.DB, 'SELECT id, email, name, master_password_hint, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, role, status, totp_secret, totp_recovery_code, created_at, updated_at FROM users ORDER BY created_at ASC'),
    queryRows(env.DB, 'SELECT user_id, revision_date FROM user_revisions ORDER BY user_id ASC'),
    queryRows(env.DB, 'SELECT id, user_id, name, created_at, updated_at FROM folders ORDER BY created_at ASC'),
    queryRows(env.DB, 'SELECT id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, deleted_at FROM ciphers ORDER BY created_at ASC'),
    queryRows(env.DB, 'SELECT id, cipher_id, file_name, size, size_name, key FROM attachments ORDER BY cipher_id ASC, id ASC'),
    queryRows(env.DB, 'SELECT id, user_id, type, name, notes, data, key, password_hash, password_salt, password_iterations, auth_type, emails, max_access_count, access_count, disabled, hide_email, created_at, updated_at, expiration_date, deletion_date FROM sends ORDER BY created_at ASC'),
  ]);

  const manifestBase = {
    formatVersion: BACKUP_FORMAT_VERSION,
    exportedAt: date.toISOString(),
    appVersion: BACKUP_APP_VERSION,
    storageKind: getBlobStorageKind(env),
    tableCounts: {
      config: configRows.length,
      users: userRows.length,
      user_revisions: revisionRows.length,
      folders: folderRows.length,
      ciphers: cipherRows.length,
      attachments: attachmentRows.length,
      sends: sendRows.length,
    },
    includes: {
      attachments: true,
      sendFiles: true,
    },
    blobSummary: {
      attachmentFiles: 0,
      sendFiles: 0,
      totalBytes: 0,
      largestObjectBytes: 0,
    },
  } satisfies BackupManifest;

  const files: Record<string, Uint8Array> = {
    'manifest.json': encoder.encode(JSON.stringify(manifestBase)),
    'db.json': encoder.encode(JSON.stringify({
      config: configRows,
      users: userRows,
      user_revisions: revisionRows,
      folders: folderRows,
      ciphers: cipherRows,
      attachments: attachmentRows,
      sends: sendRows,
    })),
  };

  const blobTasks: BackupBlobTask[] = [];
  for (const row of attachmentRows) {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    if (!cipherId || !attachmentId) continue;
    blobTasks.push({
      archivePath: `attachments/${cipherId}/${attachmentId}.bin`,
      objectKey: getAttachmentObjectKey(cipherId, attachmentId),
      kind: 'attachment',
      missingMessage: `Attachment blob missing for ${cipherId}/${attachmentId}`,
    });
  }

  for (const row of sendRows) {
    const sendId = String(row.id || '').trim();
    const fileId = parseSendFileId(typeof row.data === 'string' ? row.data : null);
    if (!sendId || !fileId) continue;
    blobTasks.push({
      archivePath: `send-files/${sendId}/${fileId}.bin`,
      objectKey: getSendFileObjectKey(sendId, fileId),
      kind: 'send-file',
      missingMessage: `Send file blob missing for ${sendId}/${fileId}`,
    });
  }

  const blobFiles = await loadBackupBlobFiles(env, blobTasks);
  Object.assign(files, blobFiles.files);

  const manifest: BackupManifest = {
    ...manifestBase,
    blobSummary: {
      attachmentFiles: blobFiles.attachmentFiles,
      sendFiles: blobFiles.sendFiles,
      totalBytes: blobFiles.totalBytes,
      largestObjectBytes: blobFiles.largestObjectBytes,
    },
  };
  files['manifest.json'] = encoder.encode(JSON.stringify(manifest));

  return {
    bytes: zipSync(createZipEntries(files)),
    fileName: buildBackupFileName(date),
    manifest,
  };
}
