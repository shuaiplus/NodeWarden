import type { Env, User } from '../types';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { type BackupArchiveBundle, buildBackupArchive } from '../services/backup-archive';
import {
  type BackupDestinationRecord,
  type BackupSettingsInput,
  BACKUP_SCHEDULER_WINDOW_MINUTES,
  getBackupLocalDateKey,
  getDefaultBackupSettings,
  getBackupSettingsRepairState,
  isBackupDueNow,
  loadBackupSettings,
  normalizeBackupSettingsInput,
  normalizeImportedBackupSettings,
  repairBackupSettings,
  requireBackupDestination,
  saveBackupSettings,
} from '../services/backup-config';
import { type BackupImportExecutionResult, importBackupArchiveBytes, importRemoteBackupArchiveBytes } from '../services/backup-import';
import {
  deleteRemoteBackupFile,
  downloadRemoteBackupFile,
  ensureRemoteRestoreCandidate,
  listRemoteBackupEntries,
  pruneRemoteBackupArchives,
  remoteBackupFileExists,
  uploadRemoteBackupFile,
  uploadBackupArchive,
} from '../services/backup-uploader';
import { StorageService } from '../services/storage';
import { getBlobObject } from '../services/blob-store';

function isAdmin(user: User): boolean {
  return user.role === 'admin' && user.status === 'active';
}

async function writeAuditLog(
  storage: StorageService,
  actorUserId: string | null,
  action: string,
  targetType: string | null,
  targetId: string | null,
  metadata: Record<string, unknown> | null
): Promise<void> {
  await storage.createAuditLog({
    id: generateUUID(),
    actorUserId,
    action,
    targetType,
    targetId,
    metadata: metadata ? JSON.stringify(metadata) : null,
    createdAt: new Date().toISOString(),
  });
}

function getBackupDestinationSummary(destination: BackupDestinationRecord | null): Record<string, unknown> {
  if (!destination) {
    return {
      destinationId: null,
      destinationName: null,
      destinationType: null,
    };
  }
  return {
    destinationId: destination.id,
    destinationName: destination.name,
    destinationType: destination.type,
  };
}

function ensureBackupBlobName(value: string): string {
  const normalized = String(value || '').trim().replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  if (!normalized) {
    throw new Error('Backup attachment blob is required');
  }
  const parts = normalized.split('/').filter(Boolean);
  if (!parts.length || parts.some((part) => part === '.' || part === '..')) {
    throw new Error('Backup attachment blob is invalid');
  }
  return parts.join('/');
}

async function executeConfiguredBackup(
  env: Env,
  storage: StorageService,
  actorUserId: string | null,
  trigger: 'manual' | 'scheduled',
  destinationId?: string | null
): Promise<{ fileName: string; fileSize: number; remotePath: string; provider: string }> {
  const currentSettings = await loadBackupSettings(storage, env, 'UTC');
  const destination = requireBackupDestination(currentSettings, destinationId);

  const now = new Date();
  destination.runtime.lastAttemptAt = now.toISOString();
  destination.runtime.lastAttemptLocalDate = getBackupLocalDateKey(now, destination.schedule.timezone);
  destination.runtime.lastErrorAt = null;
  destination.runtime.lastErrorMessage = null;
  await saveBackupSettings(storage, env, currentSettings);

  try {
    const archive = await buildBackupArchive(env, now, {
      includeAttachments: destination.includeAttachments,
    });
    for (const attachment of archive.manifest.attachmentBlobs || []) {
      const remotePath = `attachments/${attachment.blobName}`;
      if (await remoteBackupFileExists(destination, remotePath)) continue;
      const object = await getBlobObject(env, attachment.blobName);
      if (!object) {
        throw new Error(`Attachment blob missing for ${attachment.blobName}`);
      }
      const bytes = new Uint8Array(await new Response(object.body).arrayBuffer());
      await uploadRemoteBackupFile(destination, remotePath, bytes, {
        contentType: object.contentType,
      });
    }
    const upload = await uploadBackupArchive(destination, archive.bytes, archive.fileName);
    let prunedFileCount = 0;
    let pruneErrorMessage: string | null = null;
    try {
      prunedFileCount = await pruneRemoteBackupArchives(destination, destination.schedule.retentionCount, archive.fileName);
    } catch (error) {
      pruneErrorMessage = error instanceof Error ? error.message : 'Old backup cleanup failed';
    }

    destination.runtime.lastSuccessAt = new Date().toISOString();
    destination.runtime.lastErrorAt = null;
    destination.runtime.lastErrorMessage = null;
    destination.runtime.lastUploadedFileName = archive.fileName;
    destination.runtime.lastUploadedSizeBytes = archive.bytes.byteLength;
    destination.runtime.lastUploadedDestination = upload.remotePath;
    await saveBackupSettings(storage, env, currentSettings);

    await writeAuditLog(storage, actorUserId, `admin.backup.remote.${trigger}`, 'backup', null, {
      ...getBackupDestinationSummary(destination),
      provider: upload.provider,
      remotePath: upload.remotePath,
      fileName: archive.fileName,
      fileBytes: archive.bytes.byteLength,
      prunedFileCount,
      pruneError: pruneErrorMessage,
    });

    return {
      fileName: archive.fileName,
      fileSize: archive.bytes.byteLength,
      remotePath: upload.remotePath,
      provider: upload.provider,
    };
  } catch (error) {
    destination.runtime.lastErrorAt = new Date().toISOString();
    destination.runtime.lastErrorMessage = error instanceof Error ? error.message : 'Backup upload failed';
    await saveBackupSettings(storage, env, currentSettings);

    await writeAuditLog(storage, actorUserId, `admin.backup.remote.${trigger}.failed`, 'backup', null, {
      ...getBackupDestinationSummary(destination),
      error: destination.runtime.lastErrorMessage,
    });
    throw error;
  }
}

function toImportStatusCode(message: string): number {
  const lower = message.toLowerCase();
  if (lower.includes('invalid backup') || lower.includes('invalid json')) return 400;
  if (lower.includes('fresh instance')) return 409;
  if (lower.includes('not configured') || lower.includes('kv')) return 409;
  return 500;
}

async function runImportAndAudit(
  env: Env,
  actorUser: User,
  archiveBytes: Uint8Array,
  replaceExisting: boolean,
  metadata: Record<string, unknown>
): Promise<BackupImportExecutionResult> {
  const storage = new StorageService(env.DB);
  const imported = await importBackupArchiveBytes(archiveBytes, env, actorUser.id, replaceExisting);
  await writeAuditLog(storage, imported.auditActorUserId, 'admin.backup.import', 'backup', null, {
    users: imported.result.imported.users,
    ciphers: imported.result.imported.ciphers,
    attachments: imported.result.imported.attachmentFiles,
    skippedAttachments: imported.result.skipped.attachments,
    skippedReason: imported.result.skipped.reason,
    replaceExisting,
    ...metadata,
  });
  return imported;
}

export async function runScheduledBackupIfDue(env: Env): Promise<void> {
  const storage = new StorageService(env.DB);
  const settings = await loadBackupSettings(storage, env, 'UTC');
  const now = new Date();
  for (const destination of settings.destinations) {
    if (!isBackupDueNow(destination, now, BACKUP_SCHEDULER_WINDOW_MINUTES)) continue;
    await executeConfiguredBackup(env, storage, null, 'scheduled', destination.id);
  }
}

export async function handleGetAdminBackupSettings(request: Request, env: Env, actorUser: User): Promise<Response> {
  void request;
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const storage = new StorageService(env.DB);
  try {
    const settings = await loadBackupSettings(storage, env, 'UTC');
    return jsonResponse(settings);
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup settings could not be loaded', 409);
  }
}

export async function handleUpdateAdminBackupSettings(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  let body: BackupSettingsInput;
  try {
    body = await request.json<BackupSettingsInput>();
  } catch {
    return errorResponse('Backup settings payload is invalid', 400);
  }

  const storage = new StorageService(env.DB);
  let previous;
  try {
    previous = await loadBackupSettings(storage, env, 'UTC');
  } catch {
    previous = getDefaultBackupSettings('UTC');
  }

  let next;
  try {
    next = normalizeBackupSettingsInput(body, previous);
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup settings are invalid', 400);
  }

  await saveBackupSettings(storage, env, next);
  await writeAuditLog(storage, actorUser.id, 'admin.backup.settings.update', 'backup', null, {
    destinationCount: next.destinations.length,
    scheduledDestinationCount: next.destinations.filter((destination) => destination.schedule.enabled).length,
  });
  return jsonResponse(next);
}

export async function handleGetAdminBackupSettingsRepairState(request: Request, env: Env, actorUser: User): Promise<Response> {
  void request;
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const storage = new StorageService(env.DB);
  try {
    const state = await getBackupSettingsRepairState(storage, env, 'UTC');
    return jsonResponse({
      object: 'backup-settings-repair',
      needsRepair: state.needsRepair,
      portable: state.portable,
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup settings repair state could not be loaded', 409);
  }
}

export async function handleRepairAdminBackupSettings(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  let body: BackupSettingsInput;
  try {
    body = await request.json<BackupSettingsInput>();
  } catch {
    return errorResponse('Backup settings repair payload is invalid', 400);
  }

  const storage = new StorageService(env.DB);
  let previous;
  try {
    previous = await loadBackupSettings(storage, env, 'UTC');
  } catch {
    previous = getDefaultBackupSettings('UTC');
  }

  let next;
  try {
    next = normalizeBackupSettingsInput(body, previous);
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup settings repair payload is invalid', 400);
  }

  await repairBackupSettings(storage, env, next);
  await writeAuditLog(storage, actorUser.id, 'admin.backup.settings.repair', 'backup', null, {
    destinationCount: next.destinations.length,
    scheduledDestinationCount: next.destinations.filter((destination) => destination.schedule.enabled).length,
  });
  return jsonResponse(next);
}

export async function handleRunAdminConfiguredBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const storage = new StorageService(env.DB);
  try {
    let body: { destinationId?: string } | null = null;
    try {
      if ((request.headers.get('Content-Type') || '').includes('application/json')) {
        body = await request.json<{ destinationId?: string }>();
      }
    } catch {
      return errorResponse('Backup run payload is invalid', 400);
    }

    const result = await executeConfiguredBackup(env, storage, actorUser.id, 'manual', body?.destinationId || null);
    const settings = await loadBackupSettings(storage, env, 'UTC');
    return jsonResponse({
      object: 'backup-run',
      result: {
        fileName: result.fileName,
        fileSize: result.fileSize,
        provider: result.provider,
        remotePath: result.remotePath,
      },
      settings,
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup run failed', 500);
  }
}

export async function handleListAdminRemoteBackups(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const storage = new StorageService(env.DB);
  try {
    const settings = await loadBackupSettings(storage, env, 'UTC');
    const url = new URL(request.url);
    const destination = requireBackupDestination(settings, url.searchParams.get('destinationId') || null);
    const listing = await listRemoteBackupEntries(destination, url.searchParams.get('path') || '');
    return jsonResponse({
      object: 'backup-remote-browser',
      destinationId: destination.id,
      destinationName: destination.name,
      ...listing,
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Remote backup listing failed', 409);
  }
}

export async function handleDownloadAdminRemoteBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const storage = new StorageService(env.DB);
  try {
    const settings = await loadBackupSettings(storage, env, 'UTC');
    const url = new URL(request.url);
    const path = ensureRemoteRestoreCandidate(url.searchParams.get('path') || '');
    const destination = requireBackupDestination(settings, url.searchParams.get('destinationId') || null);
    const remoteFile = await downloadRemoteBackupFile(destination, path);
    return new Response(remoteFile.bytes, {
      status: 200,
      headers: {
        'Content-Type': remoteFile.contentType || 'application/zip',
        'Content-Disposition': `attachment; filename="${remoteFile.fileName}"`,
        'Cache-Control': 'no-store',
      },
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Remote backup download failed', 409);
  }
}

export async function handleDeleteAdminRemoteBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const storage = new StorageService(env.DB);
  try {
    const settings = await loadBackupSettings(storage, env, 'UTC');
    const url = new URL(request.url);
    const path = ensureRemoteRestoreCandidate(url.searchParams.get('path') || '');
    const destination = requireBackupDestination(settings, url.searchParams.get('destinationId') || null);
    await deleteRemoteBackupFile(destination, path);
    await writeAuditLog(storage, actorUser.id, 'admin.backup.remote.delete', 'backup', null, {
      ...getBackupDestinationSummary(destination),
      remotePath: path,
    });
    return jsonResponse({ object: 'backup-remote-delete', deleted: true, path });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Remote backup delete failed', 409);
  }
}

export async function handleRestoreAdminRemoteBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  let body: { destinationId?: string; path?: string; replaceExisting?: boolean };
  try {
    body = await request.json<{ destinationId?: string; path?: string; replaceExisting?: boolean }>();
  } catch {
    return errorResponse('Remote restore payload is invalid', 400);
  }

  const storage = new StorageService(env.DB);
  try {
    const settings = await loadBackupSettings(storage, env, 'UTC');
    const destination = requireBackupDestination(settings, body.destinationId || null);
    const path = ensureRemoteRestoreCandidate(String(body.path || ''));
    const remoteFile = await downloadRemoteBackupFile(destination, path);
    const imported = await (async () => {
      const storage = new StorageService(env.DB);
      const result = await importRemoteBackupArchiveBytes(
        remoteFile.bytes,
        env,
        actorUser.id,
        !!body.replaceExisting,
        {
          hasAttachment: async (blobName) => remoteBackupFileExists(destination, `attachments/${blobName}`),
          loadAttachment: async (blobName) => {
            const file = await downloadRemoteBackupFile(destination, `attachments/${blobName}`).catch(() => null);
            return file?.bytes || null;
          },
        }
      );
      await writeAuditLog(storage, result.auditActorUserId, 'admin.backup.import', 'backup', null, {
        users: result.result.imported.users,
        ciphers: result.result.imported.ciphers,
        attachments: result.result.imported.attachmentFiles,
        skippedAttachments: result.result.skipped.attachments,
        skippedReason: result.result.skipped.reason,
        replaceExisting: !!body.replaceExisting,
        ...getBackupDestinationSummary(destination),
        remotePath: path,
        bytes: remoteFile.bytes.byteLength,
        trigger: 'remote',
      });
      return result;
    })();
    return jsonResponse(imported.result);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Remote backup restore failed';
    return errorResponse(message, toImportStatusCode(message));
  }
}

export async function handleAdminExportBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const storage = new StorageService(env.DB);
  let body: { includeAttachments?: boolean } | null = null;
  try {
    if ((request.headers.get('Content-Type') || '').includes('application/json')) {
      body = await request.json<{ includeAttachments?: boolean }>();
    }
  } catch {
    return errorResponse('Backup export payload is invalid', 400);
  }
  let archive: BackupArchiveBundle;
  try {
    archive = await buildBackupArchive(env, new Date(), {
      includeAttachments: !!body?.includeAttachments,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Backup export failed';
    return errorResponse(message, message.includes('blob missing') ? 409 : 500);
  }

  await writeAuditLog(storage, actorUser.id, 'admin.backup.export', 'backup', null, {
    users: archive.manifest.tableCounts.users,
    ciphers: archive.manifest.tableCounts.ciphers,
    attachments: archive.manifest.tableCounts.attachments,
    compressedBytes: archive.bytes.byteLength,
    includesAttachments: archive.manifest.includes.attachments,
  });

  return new Response(archive.bytes, {
    status: 200,
    headers: {
      'Content-Type': 'application/zip',
      'Content-Disposition': `attachment; filename="${archive.fileName}"`,
      'Cache-Control': 'no-store',
    },
  });
}

export async function handleDownloadAdminBackupAttachment(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  try {
    const url = new URL(request.url);
    const blobName = ensureBackupBlobName(url.searchParams.get('blobName') || '');
    const object = await getBlobObject(env, blobName);
    if (!object) {
      return errorResponse('Backup attachment blob not found', 404);
    }
    return new Response(object.body, {
      status: 200,
      headers: {
        'Content-Type': object.contentType || 'application/octet-stream',
        'Content-Length': String(object.size),
        'Cache-Control': 'no-store',
      },
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup attachment download failed', 400);
  }
}

export async function handleAdminImportBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  let formData: FormData;
  try {
    formData = await request.formData();
  } catch {
    return errorResponse('Content-Type must be multipart/form-data', 400);
  }

  const file = formData.get('file');
  if (!file || typeof file !== 'object' || !('arrayBuffer' in file)) {
    return errorResponse('Backup file is required', 400);
  }

  const replaceExisting = String(formData.get('replaceExisting') || '').trim() === '1';
  let archiveBytes: Uint8Array;
  try {
    archiveBytes = new Uint8Array(await (file as { arrayBuffer(): Promise<ArrayBuffer> }).arrayBuffer());
  } catch {
    return errorResponse('Unable to read backup file', 400);
  }

  try {
    const imported = await runImportAndAudit(env, actorUser, archiveBytes, replaceExisting, {
      trigger: 'local',
      bytes: archiveBytes.byteLength,
    });
    return jsonResponse(imported.result);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Backup import failed';
    return errorResponse(message, toImportStatusCode(message));
  }
}

export async function seedDefaultBackupSettings(env: Env): Promise<void> {
  const storage = new StorageService(env.DB);
  const current = await storage.getConfigValue('backup.settings.v1');
  if (current) {
    await normalizeImportedBackupSettings(storage, env, 'UTC');
    return;
  }
  await saveBackupSettings(storage, env, getDefaultBackupSettings('UTC'));
}
