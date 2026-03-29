import { zipSync, unzipSync } from 'fflate';
import type { Env } from '../types';
import { APP_VERSION } from '../../shared/app-version';
import {
  getAttachmentObjectKey,
  getBlobStorageKind,
} from './blob-store';

type SqlRow = Record<string, string | number | null>;

const BACKUP_FORMAT_VERSION = 1;
const BACKUP_FILE_HASH_PREFIX_LENGTH = 5;
// Worker-side backup export must stay well below Cloudflare CPU limits.
// Prefer store-only ZIP entries over heavier compression to keep exports reliable.
const BACKUP_TEXT_COMPRESSION_LEVEL = 0;
const BACKUP_JSON_INDENT = 2;
const MAX_BACKUP_ARCHIVE_BYTES = 64 * 1024 * 1024;
const MAX_BACKUP_ARCHIVE_ENTRY_COUNT = 10_000;
const MAX_BACKUP_EXTRACTED_BYTES = 64 * 1024 * 1024;
const MAX_BACKUP_DB_JSON_BYTES = 32 * 1024 * 1024;

export interface BackupManifest {
  formatVersion: 1;
  exportedAt: string;
  appVersion: string;
  storageKind: 'r2' | 'kv' | null;
  tableCounts: Record<string, number>;
  includes: {
    attachments: boolean;
  };
  blobSummary: {
    attachmentFiles: number;
    totalBytes: number;
    largestObjectBytes: number;
  };
  attachmentBlobs?: BackupManifestAttachmentBlob[];
}

export interface BackupManifestAttachmentBlob {
  cipherId: string;
  attachmentId: string;
  blobName: string;
  sizeBytes: number;
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
  };
}

export interface BackupArchiveBundle {
  bytes: Uint8Array;
  fileName: string;
  manifest: BackupManifest;
}

export interface BackupFileIntegrityCheckResult {
  hasChecksumPrefix: boolean;
  expectedPrefix: string | null;
  actualPrefix: string;
  matches: boolean;
}

export interface BuildBackupArchiveOptions {
  includeAttachments?: boolean;
  progress?: BackupArchiveBuildProgressReporter;
}

export interface BackupArchiveBuildProgressEvent {
  step: string;
  fileName?: string;
  stageTitle: string;
  stageDetail: string;
  includeAttachments: boolean;
}

export type BackupArchiveBuildProgressReporter = (event: BackupArchiveBuildProgressEvent) => Promise<void>;

async function queryRows(db: D1Database, sql: string, ...values: unknown[]): Promise<SqlRow[]> {
  const result = await db.prepare(sql).bind(...values).all<SqlRow>();
  return (result.results || []).map((row) => ({ ...row }));
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function buildBackupFileName(date: Date = new Date(), checksumPrefix: string | null = null): string {
  const parts = [
    date.getUTCFullYear().toString().padStart(4, '0'),
    (date.getUTCMonth() + 1).toString().padStart(2, '0'),
    date.getUTCDate().toString().padStart(2, '0'),
    date.getUTCHours().toString().padStart(2, '0'),
    date.getUTCMinutes().toString().padStart(2, '0'),
    date.getUTCSeconds().toString().padStart(2, '0'),
  ];
  const suffix = checksumPrefix ? `_${checksumPrefix}` : '';
  return `nodewarden_backup_${parts[0]}${parts[1]}${parts[2]}_${parts[3]}${parts[4]}${parts[5]}${suffix}.zip`;
}

export function extractBackupFileChecksumPrefix(fileName: string): string | null {
  const normalized = String(fileName || '').trim();
  const match = normalized.match(/_([0-9a-f]{5})\.zip$/i);
  return match ? match[1].toLowerCase() : null;
}

export async function inspectBackupArchiveFileNameChecksum(
  bytes: Uint8Array,
  fileName: string
): Promise<BackupFileIntegrityCheckResult> {
  const expectedPrefix = extractBackupFileChecksumPrefix(fileName);
  const actualHash = await sha256Hex(bytes);
  const actualPrefix = actualHash.slice(0, BACKUP_FILE_HASH_PREFIX_LENGTH);
  return {
    hasChecksumPrefix: !!expectedPrefix,
    expectedPrefix,
    actualPrefix,
    matches: !expectedPrefix || actualPrefix === expectedPrefix,
  };
}

export async function verifyBackupArchiveFileNameChecksum(bytes: Uint8Array, fileName: string): Promise<boolean> {
  const result = await inspectBackupArchiveFileNameChecksum(bytes, fileName);
  return result.matches;
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
    entries[path] = [bytes, { level: BACKUP_TEXT_COMPRESSION_LEVEL }];
  }
  return entries;
}

export interface ParseBackupArchiveOptions {
  allowExternalAttachmentBlobs?: boolean;
}

export function parseBackupArchive(
  bytes: Uint8Array,
  options: ParseBackupArchiveOptions = {}
): { payload: BackupPayload; files: Record<string, Uint8Array> } {
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

  const externalAttachmentKeys = new Set<string>(
    options.allowExternalAttachmentBlobs
      ? (manifest.attachmentBlobs || []).map((item) => `attachments/${String(item.cipherId || '').trim()}/${String(item.attachmentId || '').trim()}.bin`)
      : []
  );
  const requiredEntries = getRequiredZipEntries(db).filter((entry) => !externalAttachmentKeys.has(entry));
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

export interface ValidateBackupPayloadOptions {
  allowExternalAttachmentBlobs?: boolean;
}

export function validateBackupPayloadContents(
  payload: BackupPayload,
  files: Record<string, Uint8Array>,
  options: ValidateBackupPayloadOptions = {}
): void {
  const configRows = ensureRowArray(payload.db.config, 'config');
  const userRows = ensureRowArray(payload.db.users, 'users');
  const revisionRows = ensureRowArray(payload.db.user_revisions, 'user_revisions');
  const folderRows = ensureRowArray(payload.db.folders, 'folders');
  const cipherRows = ensureRowArray(payload.db.ciphers, 'ciphers');
  const attachmentRows = ensureRowArray(payload.db.attachments, 'attachments');
  const externalAttachmentKeys = new Set<string>(
    options.allowExternalAttachmentBlobs
      ? (payload.manifest.attachmentBlobs || []).map((item) => `attachments/${String(item.cipherId || '').trim()}/${String(item.attachmentId || '').trim()}.bin`)
      : []
  );

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
    const attachmentPath = `attachments/${cipherId}/${id}.bin`;
    if (!files[attachmentPath] && !externalAttachmentKeys.has(attachmentPath)) {
      throw new Error(`Backup archive is missing required file: attachments/${cipherId}/${id}.bin`);
    }
  }
}

export async function buildBackupArchive(
  env: Env,
  date: Date = new Date(),
  options: BuildBackupArchiveOptions = {}
): Promise<BackupArchiveBundle> {
  const includeAttachments = options.includeAttachments !== false;
  await options.progress?.({
    step: 'collect_data',
    fileName: '',
    stageTitle: 'txt_backup_archive_progress_collect_title',
    stageDetail: includeAttachments
      ? 'txt_backup_archive_progress_collect_with_attachments_detail'
      : 'txt_backup_archive_progress_collect_detail',
    includeAttachments,
  });
  const encoder = new TextEncoder();
  const [configRows, userRows, revisionRows, folderRows, cipherRows, attachmentRows] = await Promise.all([
    queryRows(env.DB, 'SELECT key, value FROM config ORDER BY key ASC'),
    queryRows(env.DB, 'SELECT id, email, name, master_password_hint, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, role, status, verify_devices, totp_secret, totp_recovery_code, created_at, updated_at FROM users ORDER BY created_at ASC'),
    queryRows(env.DB, 'SELECT user_id, revision_date FROM user_revisions ORDER BY user_id ASC'),
    queryRows(env.DB, 'SELECT id, user_id, name, created_at, updated_at FROM folders ORDER BY created_at ASC'),
    queryRows(env.DB, 'SELECT id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at FROM ciphers ORDER BY created_at ASC'),
    queryRows(env.DB, 'SELECT id, cipher_id, file_name, size, size_name, key FROM attachments ORDER BY cipher_id ASC, id ASC'),
  ]);
  const exportedAttachmentRows = includeAttachments ? attachmentRows : [];
  const attachmentBlobs: BackupManifestAttachmentBlob[] = exportedAttachmentRows.map((row) => {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    return {
      cipherId,
      attachmentId,
      blobName: getAttachmentObjectKey(cipherId, attachmentId),
      sizeBytes: Number(row.size || 0) || 0,
    };
  });

  const manifestBase = {
    formatVersion: BACKUP_FORMAT_VERSION,
    exportedAt: date.toISOString(),
    appVersion: APP_VERSION,
    storageKind: getBlobStorageKind(env),
    tableCounts: {
      config: configRows.length,
      users: userRows.length,
      user_revisions: revisionRows.length,
      folders: folderRows.length,
      ciphers: cipherRows.length,
      attachments: exportedAttachmentRows.length,
    },
    includes: {
      attachments: includeAttachments,
    },
    blobSummary: {
      attachmentFiles: attachmentBlobs.length,
      totalBytes: attachmentBlobs.reduce((sum, item) => sum + item.sizeBytes, 0),
      largestObjectBytes: attachmentBlobs.reduce((max, item) => Math.max(max, item.sizeBytes), 0),
    },
    attachmentBlobs: includeAttachments ? attachmentBlobs : [],
  } satisfies BackupManifest;

  const files: Record<string, Uint8Array> = {
    'manifest.json': encoder.encode(JSON.stringify(manifestBase, null, BACKUP_JSON_INDENT)),
    'db.json': encoder.encode(JSON.stringify({
      config: configRows,
      users: userRows,
      user_revisions: revisionRows,
      folders: folderRows,
      ciphers: cipherRows,
      attachments: exportedAttachmentRows,
    }, null, BACKUP_JSON_INDENT)),
  };

  await options.progress?.({
    step: 'package_archive',
    fileName: '',
    stageTitle: 'txt_backup_archive_progress_package_title',
    stageDetail: includeAttachments
      ? 'txt_backup_archive_progress_package_with_attachments_detail'
      : 'txt_backup_archive_progress_package_detail',
    includeAttachments,
  });
  const bytes = zipSync(createZipEntries(files));
  const fileHashPrefix = (await sha256Hex(bytes)).slice(0, BACKUP_FILE_HASH_PREFIX_LENGTH);
  const fileName = buildBackupFileName(date, fileHashPrefix);
  await options.progress?.({
    step: 'archive_ready',
    fileName,
    stageTitle: 'txt_backup_archive_progress_ready_title',
    stageDetail: 'txt_backup_archive_progress_ready_detail',
    includeAttachments,
  });

  return {
    bytes,
    fileName,
    manifest: manifestBase,
  };
}
