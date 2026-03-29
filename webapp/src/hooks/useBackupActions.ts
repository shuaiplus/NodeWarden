import { useMemo } from 'preact/hooks';
import {
  type BackupExportClientProgressEvent,
  buildCompleteAdminBackupExport,
  deleteRemoteBackup,
  downloadRemoteBackup as fetchRemoteBackupPayload,
  getAdminBackupSettings,
  importAdminBackup,
  inspectRemoteBackupIntegrity,
  listRemoteBackups,
  restoreRemoteBackup as restoreRemoteBackupRequest,
  runAdminBackupNow,
  saveAdminBackupSettings,
} from '@/lib/api/backup';
import { downloadBytesAsFile } from '@/lib/download';
import { dispatchBackupProgress } from '@/lib/backup-restore-progress';
import type { AuthedFetch } from '@/lib/api/shared';

interface UseBackupActionsOptions {
  authedFetch: AuthedFetch;
  onImported?: () => void;
  onRestored?: () => void;
}

export default function useBackupActions(options: UseBackupActionsOptions) {
  const { authedFetch, onImported, onRestored } = options;

  return useMemo(
    () => ({
      async exportBackup(includeAttachments: boolean = false) {
        const payload = await buildCompleteAdminBackupExport(
          authedFetch,
          includeAttachments,
          async (event: BackupExportClientProgressEvent) => {
            dispatchBackupProgress(event);
          }
        );
        downloadBytesAsFile(payload.bytes, payload.fileName, payload.mimeType);
        dispatchBackupProgress({
          operation: 'backup-export',
          source: 'local',
          step: 'export_complete',
          fileName: payload.fileName,
          stageTitle: 'txt_backup_export_progress_complete_title',
          stageDetail: 'txt_backup_export_progress_complete_detail',
          done: true,
          ok: true,
        });
      },

      async importBackup(file: File, replaceExisting: boolean = false) {
        const result = await importAdminBackup(authedFetch, file, replaceExisting);
        onImported?.();
        return result;
      },

      async importBackupAllowingChecksumMismatch(file: File, replaceExisting: boolean = false) {
        const result = await importAdminBackup(authedFetch, file, replaceExisting, true);
        onImported?.();
        return result;
      },

      async loadSettings() {
        return getAdminBackupSettings(authedFetch);
      },

      async saveSettings(settings: Parameters<typeof saveAdminBackupSettings>[1]) {
        return saveAdminBackupSettings(authedFetch, settings);
      },

      async runRemoteBackup(destinationId?: string | null) {
        return runAdminBackupNow(authedFetch, destinationId);
      },

      async listRemoteBackups(destinationId: string, path: string) {
        return listRemoteBackups(authedFetch, destinationId, path);
      },

      async downloadRemoteBackup(destinationId: string, path: string, onProgress?: (percent: number | null) => void) {
        const payload = await fetchRemoteBackupPayload(authedFetch, destinationId, path, onProgress);
        downloadBytesAsFile(payload.bytes, payload.fileName, payload.mimeType);
      },

      async inspectRemoteBackup(destinationId: string, path: string) {
        return inspectRemoteBackupIntegrity(authedFetch, destinationId, path);
      },

      async deleteRemoteBackup(destinationId: string, path: string) {
        await deleteRemoteBackup(authedFetch, destinationId, path);
      },

      async restoreRemoteBackup(destinationId: string, path: string, replaceExisting: boolean = false) {
        const result = await restoreRemoteBackupRequest(authedFetch, destinationId, path, replaceExisting);
        onRestored?.();
        return result;
      },

      async restoreRemoteBackupAllowingChecksumMismatch(destinationId: string, path: string, replaceExisting: boolean = false) {
        const result = await restoreRemoteBackupRequest(authedFetch, destinationId, path, replaceExisting, true);
        onRestored?.();
        return result;
      },
    }),
    [authedFetch, onImported, onRestored]
  );
}
