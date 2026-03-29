import { t } from '../i18n';
import type {
  BackupDestinationConfig,
  BackupDestinationRecord,
  BackupDestinationType,
  BackupRuntimeState,
  BackupScheduleConfig,
  BackupSettings as AdminBackupSettings,
  E3BackupDestination,
  WebDavBackupDestination,
} from '@shared/backup-schema';
import {
  parseContentDispositionFileName,
  parseErrorMessage,
  parseJson,
  type AuthedFetch,
} from './shared';
import { readResponseBytesWithProgress } from '../download';
import { unzipSync, zipSync } from 'fflate';

export type {
  BackupDestinationConfig,
  BackupDestinationRecord,
  BackupDestinationType,
  BackupRuntimeState,
  BackupScheduleConfig,
  AdminBackupSettings,
  E3BackupDestination,
  WebDavBackupDestination,
};

export interface BackupSettingsPortableWrap {
  userId: string;
  wrappedKey: string;
}

export interface BackupSettingsPortablePayload {
  iv: string;
  ciphertext: string;
  wraps: BackupSettingsPortableWrap[];
}

export interface BackupSettingsRepairStateResponse {
  object: 'backup-settings-repair';
  needsRepair: boolean;
  portable: BackupSettingsPortablePayload | null;
}

export interface AdminBackupRunResponse {
  object: 'backup-run';
  result: {
    fileName: string;
    fileSize: number;
    provider: string;
    remotePath: string;
  };
  settings: AdminBackupSettings;
}

export interface BackupFileIntegrityCheckResult {
  hasChecksumPrefix: boolean;
  expectedPrefix: string | null;
  actualPrefix: string;
  matches: boolean;
}

export interface RemoteBackupIntegrityResponse {
  object: 'backup-remote-integrity';
  destinationId: string;
  path: string;
  fileName: string;
  integrity: BackupFileIntegrityCheckResult;
}

export interface RemoteBackupItem {
  path: string;
  name: string;
  isDirectory: boolean;
  size: number | null;
  modifiedAt: string | null;
}

export interface RemoteBackupBrowserResponse {
  object: 'backup-remote-browser';
  destinationId: string;
  destinationName: string;
  provider: BackupDestinationType;
  currentPath: string;
  parentPath: string | null;
  items: RemoteBackupItem[];
}

export interface AdminBackupImportCounts {
  config: number;
  users: number;
  userRevisions: number;
  folders: number;
  ciphers: number;
  attachments: number;
  attachmentFiles: number;
}

export interface AdminBackupImportSkippedItem {
  kind: 'attachment';
  path: string;
  sizeBytes: number;
}

export interface AdminBackupImportSkipped {
  reason: string | null;
  attachments: number;
  items: AdminBackupImportSkippedItem[];
}

export interface AdminBackupImportResponse {
  object: 'instance-backup-import';
  imported: AdminBackupImportCounts;
  skipped: AdminBackupImportSkipped;
}

export interface AdminBackupExportPayload {
  fileName: string;
  mimeType: string;
  bytes: Uint8Array;
}

export interface BackupExportClientProgressEvent {
  operation: 'backup-export';
  source: 'local';
  step: string;
  fileName: string;
  stageTitle: string;
  stageDetail: string;
  done?: boolean;
  ok?: boolean;
  error?: string | null;
}

interface BackupExportManifestAttachmentBlob {
  cipherId: string;
  attachmentId: string;
  blobName: string;
}

interface BackupExportManifest {
  attachmentBlobs?: BackupExportManifestAttachmentBlob[];
}

const BACKUP_FILE_HASH_PREFIX_LENGTH = 5;

function parseBackupTimestampFromFileName(fileName: string): Date | null {
  const match = String(fileName || '').match(/nodewarden_backup_(\d{8})_(\d{6})(?:_[0-9a-f]{5})?\.zip$/i);
  if (!match) return null;
  const datePart = match[1];
  const timePart = match[2];
  const iso = `${datePart.slice(0, 4)}-${datePart.slice(4, 6)}-${datePart.slice(6, 8)}T${timePart.slice(0, 2)}:${timePart.slice(2, 4)}:${timePart.slice(4, 6)}.000Z`;
  const parsed = new Date(iso);
  return Number.isFinite(parsed.getTime()) ? parsed : null;
}

function buildBackupFileName(date: Date, checksumPrefix: string): string {
  const parts = [
    date.getUTCFullYear().toString().padStart(4, '0'),
    (date.getUTCMonth() + 1).toString().padStart(2, '0'),
    date.getUTCDate().toString().padStart(2, '0'),
    date.getUTCHours().toString().padStart(2, '0'),
    date.getUTCMinutes().toString().padStart(2, '0'),
    date.getUTCSeconds().toString().padStart(2, '0'),
  ];
  return `nodewarden_backup_${parts[0]}${parts[1]}${parts[2]}_${parts[3]}${parts[4]}${parts[5]}_${checksumPrefix}.zip`;
}

async function applyBackupFileIntegrityName(fileName: string, bytes: Uint8Array): Promise<string> {
  const integrity = await verifyBackupFileIntegrity(bytes, fileName);
  const effectiveDate = parseBackupTimestampFromFileName(fileName) || new Date();
  return buildBackupFileName(effectiveDate, integrity.actualPrefix);
}

export async function exportAdminBackup(
  authedFetch: AuthedFetch,
  includeAttachments: boolean = false
): Promise<AdminBackupExportPayload> {
  const resp = await authedFetch('/api/admin/backup/export', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ includeAttachments }),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_backup_export_failed')));

  const mimeType = String(resp.headers.get('Content-Type') || 'application/zip').trim() || 'application/zip';
  const fileName = parseContentDispositionFileName(resp, 'nodewarden_backup.zip');
  const bytes = new Uint8Array(await resp.arrayBuffer());
  return { fileName, mimeType, bytes };
}

export async function downloadAdminBackupAttachmentBlob(
  authedFetch: AuthedFetch,
  blobName: string
): Promise<Uint8Array> {
  const params = new URLSearchParams();
  params.set('blobName', blobName);
  const resp = await authedFetch(`/api/admin/backup/blob?${params.toString()}`, { method: 'GET' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_backup_export_failed')));
  return new Uint8Array(await resp.arrayBuffer());
}

export async function buildCompleteAdminBackupExport(
  authedFetch: AuthedFetch,
  includeAttachments: boolean = false,
  onProgress?: (event: BackupExportClientProgressEvent) => void | Promise<void>
): Promise<AdminBackupExportPayload> {
  const payload = await exportAdminBackup(authedFetch, includeAttachments);
  if (!includeAttachments) {
    await onProgress?.({
      operation: 'backup-export',
      source: 'local',
      step: 'export_client_save',
      fileName: payload.fileName,
      stageTitle: 'txt_backup_export_progress_save_title',
      stageDetail: 'txt_backup_export_progress_save_detail',
    });
    return payload;
  }

  const zipped = unzipSync(payload.bytes);
  const manifestBytes = zipped['manifest.json'];
  if (!manifestBytes) {
    throw new Error(t('txt_backup_export_failed'));
  }

  let manifest: BackupExportManifest;
  try {
    manifest = JSON.parse(new TextDecoder().decode(manifestBytes)) as BackupExportManifest;
  } catch {
    throw new Error(t('txt_backup_export_failed'));
  }

  await onProgress?.({
    operation: 'backup-export',
    source: 'local',
    step: 'export_client_fetch_attachments',
    fileName: payload.fileName,
    stageTitle: 'txt_backup_export_progress_fetch_attachments_title',
    stageDetail: 'txt_backup_export_progress_fetch_attachments_detail',
  });
  for (const attachment of manifest.attachmentBlobs || []) {
    const bytes = await downloadAdminBackupAttachmentBlob(authedFetch, attachment.blobName);
    zipped[`attachments/${attachment.cipherId}/${attachment.attachmentId}.bin`] = bytes;
  }

  await onProgress?.({
    operation: 'backup-export',
    source: 'local',
    step: 'export_client_rebuild',
    fileName: payload.fileName,
    stageTitle: 'txt_backup_export_progress_rebuild_title',
    stageDetail: 'txt_backup_export_progress_rebuild_detail',
  });
  const rebuiltBytes = zipSync(zipped, { level: 0 });
  const rebuiltFileName = await applyBackupFileIntegrityName(payload.fileName, rebuiltBytes);
  await onProgress?.({
    operation: 'backup-export',
    source: 'local',
    step: 'export_client_save',
    fileName: rebuiltFileName,
    stageTitle: 'txt_backup_export_progress_save_title',
    stageDetail: 'txt_backup_export_progress_save_detail',
  });
  return {
    ...payload,
    bytes: rebuiltBytes,
    fileName: rebuiltFileName,
  };
}

export async function getAdminBackupSettings(authedFetch: AuthedFetch): Promise<AdminBackupSettings> {
  const resp = await authedFetch('/api/admin/backup/settings', { method: 'GET' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_backup_settings_load_failed')));
  const body = await parseJson<AdminBackupSettings>(resp);
  if (!Array.isArray(body?.destinations)) throw new Error(t('txt_backup_settings_invalid_response'));
  return body;
}

export async function saveAdminBackupSettings(
  authedFetch: AuthedFetch,
  settings: AdminBackupSettings
): Promise<AdminBackupSettings> {
  const resp = await authedFetch('/api/admin/backup/settings', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_backup_settings_save_failed')));
  const body = await parseJson<AdminBackupSettings>(resp);
  if (!Array.isArray(body?.destinations)) throw new Error(t('txt_backup_settings_invalid_response'));
  return body;
}

export async function getAdminBackupSettingsRepairState(
  authedFetch: AuthedFetch
): Promise<BackupSettingsRepairStateResponse> {
  const resp = await authedFetch('/api/admin/backup/settings/repair', { method: 'GET' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_backup_settings_load_failed')));
  const body = await parseJson<BackupSettingsRepairStateResponse>(resp);
  if (!body || typeof body.needsRepair !== 'boolean') {
    throw new Error(t('txt_backup_settings_invalid_response'));
  }
  return body;
}

export async function repairAdminBackupSettings(
  authedFetch: AuthedFetch,
  settings: AdminBackupSettings
): Promise<AdminBackupSettings> {
  const resp = await authedFetch('/api/admin/backup/settings/repair', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_backup_settings_save_failed')));
  const body = await parseJson<AdminBackupSettings>(resp);
  if (!Array.isArray(body?.destinations)) throw new Error(t('txt_backup_settings_invalid_response'));
  return body;
}

export async function runAdminBackupNow(
  authedFetch: AuthedFetch,
  destinationId?: string | null
): Promise<AdminBackupRunResponse> {
  const resp = await authedFetch('/api/admin/backup/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(destinationId ? { destinationId } : {}),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_backup_remote_run_failed')));
  const body = await parseJson<AdminBackupRunResponse>(resp);
  if (!body?.result || !body?.settings) throw new Error(t('txt_backup_remote_run_invalid_response'));
  return body;
}

export async function listRemoteBackups(
  authedFetch: AuthedFetch,
  destinationId: string,
  path: string = ''
): Promise<RemoteBackupBrowserResponse> {
  const params = new URLSearchParams();
  params.set('destinationId', destinationId);
  if (path) params.set('path', path);
  const query = `?${params.toString()}`;
  const resp = await authedFetch(`/api/admin/backup/remote${query}`, { method: 'GET' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_backup_remote_load_failed')));
  const body = await parseJson<RemoteBackupBrowserResponse>(resp);
  if (!body?.items || typeof body.currentPath !== 'string' || !body.destinationId) throw new Error(t('txt_backup_remote_invalid_response'));
  return body;
}

export async function downloadRemoteBackup(
  authedFetch: AuthedFetch,
  destinationId: string,
  path: string,
  onProgress?: (percent: number | null) => void
): Promise<AdminBackupExportPayload> {
  const params = new URLSearchParams();
  params.set('destinationId', destinationId);
  params.set('path', path);
  const resp = await authedFetch(`/api/admin/backup/remote/download?${params.toString()}`, { method: 'GET' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_backup_remote_download_failed')));
  const mimeType = String(resp.headers.get('Content-Type') || 'application/zip').trim() || 'application/zip';
  const fileName = parseContentDispositionFileName(resp, 'nodewarden_remote_backup.zip');
  const bytes = await readResponseBytesWithProgress(resp, (progress) => onProgress?.(progress.percent));
  return { fileName, mimeType, bytes };
}

export function extractBackupFileChecksumPrefix(fileName: string): string | null {
  const normalized = String(fileName || '').trim();
  const match = normalized.match(/_([0-9a-f]{5})\.zip$/i);
  return match ? match[1].toLowerCase() : null;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function verifyBackupFileIntegrity(bytes: Uint8Array, fileName: string): Promise<BackupFileIntegrityCheckResult> {
  const expectedPrefix = extractBackupFileChecksumPrefix(fileName);
  const actualHash = await sha256Hex(bytes);
  const actualPrefix = actualHash.slice(0, BACKUP_FILE_HASH_PREFIX_LENGTH);
  return {
    hasChecksumPrefix: !!expectedPrefix,
    expectedPrefix,
    actualPrefix,
    matches: !expectedPrefix || expectedPrefix === actualPrefix,
  };
}

export async function deleteRemoteBackup(
  authedFetch: AuthedFetch,
  destinationId: string,
  path: string
): Promise<void> {
  const params = new URLSearchParams();
  params.set('destinationId', destinationId);
  params.set('path', path);
  const resp = await authedFetch(`/api/admin/backup/remote/file?${params.toString()}`, { method: 'DELETE' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_backup_remote_delete_failed')));
}

export async function inspectRemoteBackupIntegrity(
  authedFetch: AuthedFetch,
  destinationId: string,
  path: string
): Promise<RemoteBackupIntegrityResponse> {
  const params = new URLSearchParams();
  params.set('destinationId', destinationId);
  params.set('path', path);
  const resp = await authedFetch(`/api/admin/backup/remote/integrity?${params.toString()}`, { method: 'GET' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_backup_remote_download_failed')));
  const body = await parseJson<RemoteBackupIntegrityResponse>(resp);
  if (!body?.integrity || !body?.fileName) throw new Error(t('txt_backup_remote_invalid_response'));
  return body;
}

export async function restoreRemoteBackup(
  authedFetch: AuthedFetch,
  destinationId: string,
  path: string,
  replaceExisting: boolean = false,
  allowChecksumMismatch: boolean = false
): Promise<AdminBackupImportResponse> {
  const resp = await authedFetch('/api/admin/backup/remote/restore', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ destinationId, path, replaceExisting, allowChecksumMismatch }),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_backup_remote_restore_failed')));
  const body = await parseJson<AdminBackupImportResponse>(resp);
  if (!body?.imported) throw new Error(t('txt_backup_remote_restore_invalid_response'));
  return body;
}

export async function importAdminBackup(
  authedFetch: AuthedFetch,
  file: File,
  replaceExisting: boolean = false,
  allowChecksumMismatch: boolean = false
): Promise<AdminBackupImportResponse> {
  const formData = new FormData();
  formData.set('file', file, file.name || 'nodewarden_backup.zip');
  if (replaceExisting) {
    formData.set('replaceExisting', '1');
  }
  if (allowChecksumMismatch) {
    formData.set('allowChecksumMismatch', '1');
  }

  const resp = await authedFetch('/api/admin/backup/import', {
    method: 'POST',
    body: formData,
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_backup_import_failed')));

  const body = await parseJson<AdminBackupImportResponse>(resp);
  if (!body?.imported) throw new Error(t('txt_backup_import_invalid_response'));
  return body;
}
