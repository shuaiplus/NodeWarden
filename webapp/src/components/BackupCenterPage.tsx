import { createPortal } from 'preact/compat';
import { useEffect, useRef, useState } from 'preact/hooks';
import ConfirmDialog from '@/components/ConfirmDialog';
import {
  type AdminBackupImportResponse,
  type AdminBackupRunResponse,
  type AdminBackupSettings,
  type BackupFileIntegrityCheckResult,
  type BackupDestinationRecord,
  type BackupDestinationType,
  type RemoteBackupBrowserResponse,
  verifyBackupFileIntegrity,
} from '@/lib/api/backup';
import {
  REMOTE_BROWSER_ITEMS_PER_PAGE,
  compareRemoteItems,
  createDraftBackupSettings,
  createDraftDestinationRecord,
  getDestinationById,
  getFirstVisibleDestinationId,
  getRemoteBrowserCacheKey,
  getVisibleDestinations,
  invalidateRemoteBrowserCacheForDestination,
  isReplaceRequiredError,
  loadPersistedRemoteBrowserState,
  persistRemoteBrowserState,
} from '@/lib/backup-center';
import { BACKUP_PROGRESS_EVENT, type BackupProgressDetail, type BackupProgressOperation } from '@/lib/backup-restore-progress';
import { RECOMMENDED_PROVIDERS, type RecommendedProvider } from '@/lib/backup-recommendations';
import { t } from '@/lib/i18n';
import { BackupDestinationDetail } from './backup-center/BackupDestinationDetail';
import { BackupDestinationSidebar } from './backup-center/BackupDestinationSidebar';
import { BackupOperationsSidebar } from './backup-center/BackupOperationsSidebar';

interface BackupCenterPageProps {
  currentUserId: string | null;
  onExport: (includeAttachments?: boolean) => Promise<void>;
  onImport: (file: File, replaceExisting?: boolean) => Promise<AdminBackupImportResponse>;
  onImportAllowingChecksumMismatch: (file: File, replaceExisting?: boolean) => Promise<AdminBackupImportResponse>;
  onLoadSettings: () => Promise<AdminBackupSettings>;
  onSaveSettings: (settings: AdminBackupSettings) => Promise<AdminBackupSettings>;
  onRunRemoteBackup: (destinationId?: string | null) => Promise<AdminBackupRunResponse>;
  onListRemoteBackups: (destinationId: string, path: string) => Promise<RemoteBackupBrowserResponse>;
  onDownloadRemoteBackup: (destinationId: string, path: string, onProgress?: (percent: number | null) => void) => Promise<void>;
  onInspectRemoteBackup: (destinationId: string, path: string) => Promise<{ object: 'backup-remote-integrity'; destinationId: string; path: string; fileName: string; integrity: BackupFileIntegrityCheckResult }>;
  onDeleteRemoteBackup: (destinationId: string, path: string) => Promise<void>;
  onRestoreRemoteBackup: (destinationId: string, path: string, replaceExisting?: boolean) => Promise<AdminBackupImportResponse>;
  onRestoreRemoteBackupAllowingChecksumMismatch: (destinationId: string, path: string, replaceExisting?: boolean) => Promise<AdminBackupImportResponse>;
  onNotify: (type: 'success' | 'error' | 'warning', text: string) => void;
}

type PendingRestoreIntegrity =
  | { source: 'local'; fileName: string; result: BackupFileIntegrityCheckResult }
  | { source: 'remote'; fileName: string; path: string; result: BackupFileIntegrityCheckResult };

interface BackupProgressPhase {
  titleKey: string;
  detailKey: string;
}

interface BackupProgressState {
  operation: BackupProgressOperation;
  source: 'local' | 'remote' | null;
  includeAttachments: boolean;
  fileLabel: string;
  startedAt: number;
  phaseIndex: number;
  phases: BackupProgressPhase[];
  currentTitleKey: string;
  currentDetailKey: string;
}

const LOCAL_RESTORE_PHASES: BackupProgressPhase[] = [
  { titleKey: 'txt_backup_restore_progress_local_upload_title', detailKey: 'txt_backup_restore_progress_local_upload_detail' },
  { titleKey: 'txt_backup_restore_progress_local_shadow_title', detailKey: 'txt_backup_restore_progress_local_shadow_detail' },
  { titleKey: 'txt_backup_restore_progress_local_data_title', detailKey: 'txt_backup_restore_progress_local_data_detail' },
  { titleKey: 'txt_backup_restore_progress_local_files_title', detailKey: 'txt_backup_restore_progress_local_files_detail' },
  { titleKey: 'txt_backup_restore_progress_local_finalize_title', detailKey: 'txt_backup_restore_progress_local_finalize_detail' },
];

const REMOTE_RESTORE_PHASES: BackupProgressPhase[] = [
  { titleKey: 'txt_backup_restore_progress_remote_fetch_title', detailKey: 'txt_backup_restore_progress_remote_fetch_detail' },
  { titleKey: 'txt_backup_restore_progress_remote_shadow_title', detailKey: 'txt_backup_restore_progress_remote_shadow_detail' },
  { titleKey: 'txt_backup_restore_progress_remote_data_title', detailKey: 'txt_backup_restore_progress_remote_data_detail' },
  { titleKey: 'txt_backup_restore_progress_remote_files_title', detailKey: 'txt_backup_restore_progress_remote_files_detail' },
  { titleKey: 'txt_backup_restore_progress_remote_finalize_title', detailKey: 'txt_backup_restore_progress_remote_finalize_detail' },
];

const EXPORT_PROGRESS_PHASES: BackupProgressPhase[] = [
  { titleKey: 'txt_backup_archive_progress_collect_title', detailKey: 'txt_backup_archive_progress_collect_detail' },
  { titleKey: 'txt_backup_archive_progress_package_title', detailKey: 'txt_backup_archive_progress_package_detail' },
  { titleKey: 'txt_backup_archive_progress_ready_title', detailKey: 'txt_backup_archive_progress_ready_detail' },
  { titleKey: 'txt_backup_export_progress_save_title', detailKey: 'txt_backup_export_progress_save_detail' },
];

const EXPORT_WITH_ATTACHMENTS_PROGRESS_PHASES: BackupProgressPhase[] = [
  { titleKey: 'txt_backup_archive_progress_collect_title', detailKey: 'txt_backup_archive_progress_collect_with_attachments_detail' },
  { titleKey: 'txt_backup_archive_progress_package_title', detailKey: 'txt_backup_archive_progress_package_with_attachments_detail' },
  { titleKey: 'txt_backup_archive_progress_ready_title', detailKey: 'txt_backup_archive_progress_ready_detail' },
  { titleKey: 'txt_backup_export_progress_fetch_attachments_title', detailKey: 'txt_backup_export_progress_fetch_attachments_detail' },
  { titleKey: 'txt_backup_export_progress_rebuild_title', detailKey: 'txt_backup_export_progress_rebuild_detail' },
  { titleKey: 'txt_backup_export_progress_save_title', detailKey: 'txt_backup_export_progress_save_detail' },
];

const REMOTE_RUN_PROGRESS_PHASES: BackupProgressPhase[] = [
  { titleKey: 'txt_backup_remote_run_progress_prepare_title', detailKey: 'txt_backup_remote_run_progress_prepare_detail' },
  { titleKey: 'txt_backup_archive_progress_collect_title', detailKey: 'txt_backup_archive_progress_collect_with_attachments_detail' },
  { titleKey: 'txt_backup_archive_progress_package_title', detailKey: 'txt_backup_archive_progress_package_with_attachments_detail' },
  { titleKey: 'txt_backup_remote_run_progress_sync_attachments_title', detailKey: 'txt_backup_remote_run_progress_sync_attachments_detail' },
  { titleKey: 'txt_backup_remote_run_progress_upload_title', detailKey: 'txt_backup_remote_run_progress_upload_detail' },
  { titleKey: 'txt_backup_remote_run_progress_verify_title', detailKey: 'txt_backup_remote_run_progress_verify_detail' },
  { titleKey: 'txt_backup_remote_run_progress_cleanup_title', detailKey: 'txt_backup_remote_run_progress_cleanup_detail' },
];

function buildSkippedImportMessage(result: AdminBackupImportResponse): string | null {
  const skipped = result.skipped;
  if (!skipped || !skipped.attachments) return null;
  return t('txt_backup_restore_skipped_summary', {
    reason: skipped.reason || t('txt_backup_restore_skipped_reason_default'),
    attachments: String(skipped.attachments),
  });
}

function buildIntegrityStatusMessage(result: BackupFileIntegrityCheckResult, options?: { remote?: boolean }): string {
  if (!result.hasChecksumPrefix) {
    return t(options?.remote ? 'txt_backup_remote_restore_completed_without_checksum' : 'txt_backup_restore_completed_without_checksum');
  }
  return t(options?.remote ? 'txt_backup_remote_restore_completed_verified' : 'txt_backup_restore_completed_verified');
}

function buildIntegrityWarningMessage(entry: PendingRestoreIntegrity): string {
  if (entry.source === 'remote') {
    return t('txt_backup_remote_restore_checksum_warning_message', {
      name: entry.fileName,
      expected: entry.result.expectedPrefix || '-----',
      actual: entry.result.actualPrefix,
    });
  }
  return t('txt_backup_restore_checksum_warning_message', {
    name: entry.fileName,
    expected: entry.result.expectedPrefix || '-----',
    actual: entry.result.actualPrefix,
  });
}

function getBackupProgressPhases(
  operation: BackupProgressOperation,
  source: 'local' | 'remote' | null,
  includeAttachments: boolean
): BackupProgressPhase[] {
  if (operation === 'backup-restore') {
    return source === 'remote' ? REMOTE_RESTORE_PHASES : LOCAL_RESTORE_PHASES;
  }
  if (operation === 'backup-export') {
    return includeAttachments ? EXPORT_WITH_ATTACHMENTS_PROGRESS_PHASES : EXPORT_PROGRESS_PHASES;
  }
  return REMOTE_RUN_PROGRESS_PHASES;
}

function getBackupProgressTitleKey(state: BackupProgressState): string {
  if (state.operation === 'backup-export') return 'txt_backup_export_progress_title';
  if (state.operation === 'backup-remote-run') return 'txt_backup_remote_run_progress_title';
  return state.source === 'remote'
    ? 'txt_backup_restore_progress_remote_title'
    : 'txt_backup_restore_progress_local_title';
}

export default function BackupCenterPage(props: BackupCenterPageProps) {
  const persistedRemoteStateRef = useRef(loadPersistedRemoteBrowserState(props.currentUserId));
  const persistedRemoteState = persistedRemoteStateRef.current;
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const restoreProgressTimerRef = useRef<number | null>(null);
  const restoreProgressPendingRef = useRef<BackupProgressState | null>(null);

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportIncludeAttachments, setExportIncludeAttachments] = useState(false);
  const [importing, setImporting] = useState(false);
  const [loadingSettings, setLoadingSettings] = useState(true);
  const [savingSettings, setSavingSettings] = useState(false);
  const [runningRemoteBackup, setRunningRemoteBackup] = useState(false);
  const [loadingRemoteBrowser, setLoadingRemoteBrowser] = useState(false);
  const [downloadingRemotePath, setDownloadingRemotePath] = useState('');
  const [downloadingRemotePercent, setDownloadingRemotePercent] = useState<number | null>(null);
  const [restoringRemotePath, setRestoringRemotePath] = useState('');
  const [deletingRemotePath, setDeletingRemotePath] = useState('');
  const [localError, setLocalError] = useState('');
  const [restoreProgress, setRestoreProgress] = useState<BackupProgressState | null>(null);
  const [restoreElapsedSeconds, setRestoreElapsedSeconds] = useState(0);
  const [confirmLocalRestoreOpen, setConfirmLocalRestoreOpen] = useState(false);
  const [confirmReplaceOpen, setConfirmReplaceOpen] = useState(false);
  const [confirmRemoteReplaceOpen, setConfirmRemoteReplaceOpen] = useState(false);
  const [confirmIntegrityWarningOpen, setConfirmIntegrityWarningOpen] = useState(false);
  const [confirmDeleteDestinationOpen, setConfirmDeleteDestinationOpen] = useState(false);
  const [confirmRemoteDeleteOpen, setConfirmRemoteDeleteOpen] = useState(false);
  const [pendingRestoreIntegrity, setPendingRestoreIntegrity] = useState<PendingRestoreIntegrity | null>(null);
  const [pendingRemoteRestorePath, setPendingRemoteRestorePath] = useState('');
  const [pendingRemoteDeletePath, setPendingRemoteDeletePath] = useState('');
  const [savedSettings, setSavedSettings] = useState<AdminBackupSettings | null>(null);
  const [settings, setSettings] = useState<AdminBackupSettings>(createDraftBackupSettings);
  const [selectedDestinationId, setSelectedDestinationId] = useState<string | null>(persistedRemoteState.selectedDestinationId);
  const [selectedProviderId, setSelectedProviderId] = useState<string | null>(null);
  const [remoteBrowserCache, setRemoteBrowserCache] = useState<Record<string, RemoteBackupBrowserResponse>>(persistedRemoteState.cache);
  const [remoteBrowserPathByDestination, setRemoteBrowserPathByDestination] = useState<Record<string, string>>(persistedRemoteState.pathByDestination);
  const [remoteBrowserPageByKey, setRemoteBrowserPageByKey] = useState<Record<string, number>>(persistedRemoteState.pageByKey);
  const [showAddChooser, setShowAddChooser] = useState(false);

  const visibleDestinations = getVisibleDestinations(settings);
  const selectedDestination = getDestinationById(settings, selectedDestinationId);
  const savedSelectedDestination = getDestinationById(savedSettings, selectedDestinationId);
  const selectedDestinationIsSaved = !!savedSelectedDestination;
  const disableWhileBusy = exporting || importing || savingSettings || runningRemoteBackup;
  const currentRemoteBrowserPath = savedSelectedDestination ? (remoteBrowserPathByDestination[savedSelectedDestination.id] || '') : '';
  const currentRemoteBrowserKey = savedSelectedDestination ? getRemoteBrowserCacheKey(savedSelectedDestination.id, currentRemoteBrowserPath) : '';
  const remoteBrowser = currentRemoteBrowserKey ? remoteBrowserCache[currentRemoteBrowserKey] || null : null;
  const remoteBrowserItems = remoteBrowser?.items || [];
  const remoteBrowserTotalPages = Math.max(1, Math.ceil(remoteBrowserItems.length / REMOTE_BROWSER_ITEMS_PER_PAGE));
  const currentRemoteBrowserPage = Math.min(remoteBrowserPageByKey[currentRemoteBrowserKey] || 1, remoteBrowserTotalPages);
  const remoteBrowserVisibleItems = remoteBrowserItems.slice(
    (currentRemoteBrowserPage - 1) * REMOTE_BROWSER_ITEMS_PER_PAGE,
    currentRemoteBrowserPage * REMOTE_BROWSER_ITEMS_PER_PAGE
  );

  const selectedRecommendedProvider = RECOMMENDED_PROVIDERS.find((provider) => provider.id === selectedProviderId) || null;
  const recommendedWebDavProviders = RECOMMENDED_PROVIDERS.filter((provider) => provider.protocol === 'webdav');
  const recommendedS3Providers = RECOMMENDED_PROVIDERS.filter((provider) => provider.protocol === 's3');
  const canRunSelectedDestination = !!selectedDestination && selectedDestinationIsSaved;
  const canBrowseSelectedDestination = !!savedSelectedDestination;

  useEffect(() => {
    let cancelled = false;
    setLoadingSettings(true);
    void props.onLoadSettings()
      .then((loaded) => {
        if (cancelled) return;
        setSavedSettings(loaded);
        setSettings(loaded);
        const nextSelectedDestinationId =
          (persistedRemoteState.selectedDestinationId
            && getVisibleDestinations(loaded).some((destination) => destination.id === persistedRemoteState.selectedDestinationId)
            ? persistedRemoteState.selectedDestinationId
            : null)
          || getFirstVisibleDestinationId(loaded);
        setSelectedDestinationId(nextSelectedDestinationId);
        setLocalError('');
      })
      .catch((error) => {
        if (cancelled) return;
        const message = error instanceof Error ? error.message : t('txt_backup_settings_load_failed');
        setLocalError(message);
        props.onNotify('error', message);
      })
      .finally(() => {
        if (!cancelled) setLoadingSettings(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    persistRemoteBrowserState(props.currentUserId, {
      cache: remoteBrowserCache,
      pathByDestination: remoteBrowserPathByDestination,
      pageByKey: remoteBrowserPageByKey,
      selectedDestinationId,
    });
  }, [props.currentUserId, remoteBrowserCache, remoteBrowserPageByKey, remoteBrowserPathByDestination, selectedDestinationId]);

  useEffect(() => {
    if (!restoreProgress) {
      setRestoreElapsedSeconds(0);
      return;
    }
    setRestoreElapsedSeconds(Math.max(0, Math.floor((Date.now() - restoreProgress.startedAt) / 1000)));
    const tickTimer = window.setInterval(() => {
      setRestoreElapsedSeconds(Math.max(0, Math.floor((Date.now() - restoreProgress.startedAt) / 1000)));
    }, 1000);
    return () => window.clearInterval(tickTimer);
  }, [restoreProgress]);

  useEffect(() => {
    const handleProgress = (event: Event) => {
      const detail = (event as CustomEvent<BackupProgressDetail>).detail;
      if (!detail) return;
      const pending = restoreProgressPendingRef.current;
      const operation = detail.operation || pending?.operation || 'backup-restore';
      const source = (detail.source || pending?.source || null) as 'local' | 'remote' | null;
      const includeAttachments = pending?.includeAttachments || false;
      const phases = getBackupProgressPhases(operation, source, includeAttachments);
      const matchedPhaseIndex = phases.findIndex((phase) => phase.titleKey === detail.stageTitle);
      const phaseIndex = matchedPhaseIndex >= 0 ? matchedPhaseIndex : 0;
      const nextState: BackupProgressState = {
        operation,
        source,
        includeAttachments,
        fileLabel: detail.fileName || pending?.fileLabel || '',
        startedAt: pending?.operation === operation
          ? pending.startedAt
          : Date.now(),
        phaseIndex,
        phases,
        currentTitleKey: detail.stageTitle || phases[Math.max(0, phaseIndex)].titleKey,
        currentDetailKey: detail.stageDetail || phases[Math.max(0, phaseIndex)].detailKey,
      };
      restoreProgressPendingRef.current = nextState;
      if (restoreProgressTimerRef.current === null) {
        setRestoreProgress(nextState);
      }
      if (detail.done) {
        window.setTimeout(() => {
          setRestoreProgress((current) => (
            current && current.fileLabel === (detail.fileName || current.fileLabel) ? null : current
          ));
          setRestoreElapsedSeconds(0);
        }, detail.ok === false ? 1200 : 900);
      }
    };
    window.addEventListener(BACKUP_PROGRESS_EVENT, handleProgress as EventListener);
    return () => window.removeEventListener(BACKUP_PROGRESS_EVENT, handleProgress as EventListener);
  }, []);

  function updateSettings(mutator: (current: AdminBackupSettings) => AdminBackupSettings) {
    setSettings((current) => {
      const next = mutator(current);
      if (selectedDestinationId && !next.destinations.some((destination) => destination.id === selectedDestinationId)) {
        setSelectedDestinationId(getFirstVisibleDestinationId(next));
      }
      return next;
    });
  }

  function updateSelectedDestination(mutator: (destination: BackupDestinationRecord) => BackupDestinationRecord) {
    if (!selectedDestinationId) return;
    updateSettings((current) => ({
      ...current,
      destinations: current.destinations.map((destination) => (
        destination.id === selectedDestinationId ? mutator(destination) : destination
      )),
    }));
  }

  async function loadRemoteBrowser(destinationId: string, path: string = '', options?: { force?: boolean }): Promise<void> {
    const cacheKey = getRemoteBrowserCacheKey(destinationId, path);
    setRemoteBrowserPathByDestination((current) => ({ ...current, [destinationId]: path }));
    if (!options?.force && remoteBrowserCache[cacheKey]) return;

    setLoadingRemoteBrowser(true);
    try {
      const browser = await props.onListRemoteBackups(destinationId, path);
      const nextBrowser = {
        ...browser,
        items: browser.items.slice().sort(compareRemoteItems),
      };
      setRemoteBrowserCache((current) => ({ ...current, [cacheKey]: nextBrowser }));
      setRemoteBrowserPageByKey((current) => ({ ...current, [cacheKey]: 1 }));
    } catch (error) {
      const message = error instanceof Error ? error.message : t('txt_backup_remote_load_failed');
      setLocalError(message);
      props.onNotify('error', message);
    } finally {
      setLoadingRemoteBrowser(false);
    }
  }

  function showRemoteBrowserPath(destinationId: string, path: string = ''): void {
    setRemoteBrowserPathByDestination((current) => ({ ...current, [destinationId]: path }));
  }

  function buildSettingsPayloadForSelectedDestination(): AdminBackupSettings {
    if (!selectedDestinationId || !selectedDestination) {
      return savedSettings || { destinations: [] };
    }
    const persistedDestinations = (savedSettings?.destinations || []).filter((destination) => destination.id !== selectedDestinationId);
    return {
      destinations: [...persistedDestinations, selectedDestination],
    };
  }

  function applySavedDestinationToDrafts(saved: AdminBackupSettings, destinationId: string | null) {
    if (!destinationId) {
      setSettings((current) => ({
        destinations: current.destinations.filter((destination) => !savedSettings?.destinations.some((savedDestination) => savedDestination.id === destination.id)),
      }));
      return;
    }
    const savedDestination = getDestinationById(saved, destinationId);
    setSettings((current) => ({
      destinations: current.destinations.map((destination) => (
        destination.id === destinationId && savedDestination ? savedDestination : destination
      )),
    }));
  }

  function resetSelectedFile() {
    setSelectedFile(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  }

  function resetPendingIntegrityWarning() {
    setPendingRestoreIntegrity(null);
    setConfirmIntegrityWarningOpen(false);
  }

  function startRestoreProgress(
    operation: BackupProgressOperation,
    fileLabel: string,
    options?: { source?: 'local' | 'remote' | null; includeAttachments?: boolean; delayMs?: number }
  ) {
    if (restoreProgressTimerRef.current !== null) {
      window.clearTimeout(restoreProgressTimerRef.current);
      restoreProgressTimerRef.current = null;
    }
    setRestoreElapsedSeconds(0);
    const source = options?.source || null;
    const includeAttachments = !!options?.includeAttachments;
    const phases = getBackupProgressPhases(operation, source, includeAttachments);
    restoreProgressPendingRef.current = {
      operation,
      source,
      includeAttachments,
      fileLabel,
      startedAt: Date.now(),
      phaseIndex: 0,
      phases,
      currentTitleKey: phases[0].titleKey,
      currentDetailKey: phases[0].detailKey,
    };
    restoreProgressTimerRef.current = window.setTimeout(() => {
      restoreProgressTimerRef.current = null;
      if (!restoreProgressPendingRef.current) return;
      setRestoreProgress(restoreProgressPendingRef.current);
    }, options?.delayMs ?? 480);
  }

  function clearRestoreProgress() {
    if (restoreProgressTimerRef.current !== null) {
      window.clearTimeout(restoreProgressTimerRef.current);
      restoreProgressTimerRef.current = null;
    }
    restoreProgressPendingRef.current = null;
    setRestoreProgress(null);
    setRestoreElapsedSeconds(0);
  }

  async function inspectLocalBackupFile(file: File): Promise<BackupFileIntegrityCheckResult> {
    const bytes = new Uint8Array(await file.arrayBuffer());
    return verifyBackupFileIntegrity(bytes, file.name || '');
  }

  async function inspectRemoteBackupFile(destinationId: string, path: string): Promise<PendingRestoreIntegrity> {
    const payload = await props.onInspectRemoteBackup(destinationId, path);
    return {
      source: 'remote',
      path,
      fileName: payload.fileName || path.split('/').pop() || path,
      result: payload.integrity,
    };
  }

  function handleAddDestination(type: BackupDestinationType) {
    updateSettings((current) => {
      const nextDestination = createDraftDestinationRecord(type, current.destinations.filter((destination) => destination.type === type).length + 1);
      setSelectedProviderId(null);
      setSelectedDestinationId(nextDestination.id);
      return {
        ...current,
        destinations: [...current.destinations, nextDestination],
      };
    });
    setShowAddChooser(false);
  }

  async function handleDeleteDestination() {
    if (!selectedDestinationId || savingSettings) return;
    const destinationIdToDelete = selectedDestinationId;
    const nextSettings: AdminBackupSettings = {
      destinations: (savedSettings?.destinations || []).filter((destination) => destination.id !== destinationIdToDelete),
    };

    setSavingSettings(true);
    setLocalError('');
    try {
      const saved = await props.onSaveSettings(nextSettings);
      const nextDraftDestinations = settings.destinations.filter((destination) => destination.id !== destinationIdToDelete);
      const nextSelected = getFirstVisibleDestinationId({ destinations: nextDraftDestinations }) || getFirstVisibleDestinationId(saved);
      setSavedSettings(saved);
      setSettings({ destinations: nextDraftDestinations });
      setRemoteBrowserCache((current) => invalidateRemoteBrowserCacheForDestination(
        destinationIdToDelete,
        current,
        remoteBrowserPathByDestination,
        remoteBrowserPageByKey
      ).cache);
      setRemoteBrowserPathByDestination((current) => Object.fromEntries(Object.entries(current).filter(([key]) => key !== destinationIdToDelete)));
      setRemoteBrowserPageByKey((current) => Object.fromEntries(Object.entries(current).filter(([key]) => !key.startsWith(`${destinationIdToDelete}:`))));
      setSelectedDestinationId(nextSelected);
      setConfirmDeleteDestinationOpen(false);
      props.onNotify('success', t('txt_backup_destination_deleted'));
    } catch (error) {
      const message = error instanceof Error ? error.message : t('txt_backup_settings_save_failed');
      setLocalError(message);
      props.onNotify('error', message);
    } finally {
      setSavingSettings(false);
    }
  }

  async function handleExport() {
    setLocalError('');
    setExporting(true);
    try {
      startRestoreProgress('backup-export', t('txt_backup_export'), { source: 'local', includeAttachments: exportIncludeAttachments });
      await props.onExport(exportIncludeAttachments);
      props.onNotify('success', t('txt_backup_export_success'));
    } catch (error) {
      const message = error instanceof Error ? error.message : t('txt_backup_export_failed');
      setLocalError(message);
      props.onNotify('error', message);
      window.setTimeout(() => clearRestoreProgress(), 1200);
    } finally {
      setExporting(false);
    }
  }

  async function runLocalRestore(
    replaceExisting: boolean,
    allowChecksumMismatch: boolean = false,
    knownIntegrity?: BackupFileIntegrityCheckResult
  ) {
    if (!selectedFile) {
      const message = t('txt_backup_file_required');
      setLocalError(message);
      props.onNotify('error', message);
      return;
    }
    setLocalError('');
    setConfirmLocalRestoreOpen(false);
    setConfirmReplaceOpen(false);
    setConfirmIntegrityWarningOpen(false);
    setImporting(true);
    try {
      const integrity = knownIntegrity || await inspectLocalBackupFile(selectedFile);
      startRestoreProgress('backup-restore', selectedFile.name || t('txt_backup_import'), {
        source: 'local',
        delayMs: replaceExisting ? 480 : 1400,
      });
      const result = allowChecksumMismatch
        ? await props.onImportAllowingChecksumMismatch(selectedFile, replaceExisting)
        : await props.onImport(selectedFile, replaceExisting);
      props.onNotify('success', `${buildIntegrityStatusMessage(integrity)} ${t('txt_backup_restore_success_relogin')}`);
      const skippedMessage = buildSkippedImportMessage(result);
      if (skippedMessage) props.onNotify('warning', skippedMessage);
      resetSelectedFile();
      setConfirmLocalRestoreOpen(false);
      setConfirmReplaceOpen(false);
      resetPendingIntegrityWarning();
    } catch (error) {
      if (!replaceExisting && isReplaceRequiredError(error)) {
        clearRestoreProgress();
        setConfirmLocalRestoreOpen(false);
        setConfirmReplaceOpen(true);
        return;
      }
      const message = error instanceof Error ? error.message : t('txt_backup_restore_failed');
      setLocalError(message);
      props.onNotify('error', message);
      window.setTimeout(() => clearRestoreProgress(), 1200);
    } finally {
      setImporting(false);
    }
  }

  async function handleSaveSettings() {
    const payload = buildSettingsPayloadForSelectedDestination();
    const destinationIdToInvalidate = selectedDestinationId;
    setSavingSettings(true);
    setLocalError('');
    try {
      const saved = await props.onSaveSettings(payload);
      const nextSelected =
        (selectedDestinationId && saved.destinations.some((destination) => destination.id === selectedDestinationId) && selectedDestinationId)
        || getFirstVisibleDestinationId(saved)
        || null;
      setSavedSettings(saved);
      applySavedDestinationToDrafts(saved, nextSelected);
      if (destinationIdToInvalidate) {
        setRemoteBrowserCache((current) => Object.fromEntries(Object.entries(current).filter(([key]) => !key.startsWith(`${destinationIdToInvalidate}:`))));
        setRemoteBrowserPathByDestination((current) => Object.fromEntries(Object.entries(current).filter(([key]) => key !== destinationIdToInvalidate)));
        setRemoteBrowserPageByKey((current) => Object.fromEntries(Object.entries(current).filter(([key]) => !key.startsWith(`${destinationIdToInvalidate}:`))));
      }
      setSelectedDestinationId(nextSelected);
      props.onNotify('success', t('txt_backup_settings_saved'));
    } catch (error) {
      const message = error instanceof Error ? error.message : t('txt_backup_settings_save_failed');
      setLocalError(message);
      props.onNotify('error', message);
    } finally {
      setSavingSettings(false);
    }
  }

  function handleToggleSelectedSchedule() {
    if (!selectedDestination) return;
    updateSelectedDestination((destination) => ({
      ...destination,
      schedule: {
        ...destination.schedule,
        enabled: !destination.schedule.enabled,
      },
    }));
  }

  async function handleRunRemoteBackup() {
    if (!selectedDestination) return;
    setRunningRemoteBackup(true);
    setLocalError('');
    try {
      startRestoreProgress('backup-remote-run', selectedDestination.name || t('txt_backup_run_now'), {
        source: 'remote',
        includeAttachments: !!selectedDestination.includeAttachments,
      });
      const result = await props.onRunRemoteBackup(selectedDestination.id);
      setSavedSettings(result.settings);
      setSettings(result.settings);
      setSelectedDestinationId(selectedDestination.id);
      await loadRemoteBrowser(selectedDestination.id, currentRemoteBrowserPath, { force: true });
      props.onNotify('success', t('txt_backup_remote_run_success_verified', { name: result.fileName }));
    } catch (error) {
      const message = error instanceof Error ? error.message : t('txt_backup_remote_run_failed');
      setLocalError(message);
      props.onNotify('error', message);
      window.setTimeout(() => clearRestoreProgress(), 1200);
    } finally {
      setRunningRemoteBackup(false);
    }
  }

  async function handleDownloadRemote(path: string) {
    if (!savedSelectedDestination) return;
    setDownloadingRemotePath(path);
    setDownloadingRemotePercent(null);
    setLocalError('');
    try {
      await props.onDownloadRemoteBackup(savedSelectedDestination.id, path, setDownloadingRemotePercent);
    } catch (error) {
      const message = error instanceof Error ? error.message : t('txt_backup_remote_download_failed');
      setLocalError(message);
      props.onNotify('error', message);
    } finally {
      setDownloadingRemotePath('');
      setDownloadingRemotePercent(null);
    }
  }

  async function handleDeleteRemote(path: string) {
    if (!savedSelectedDestination) return;
    setDeletingRemotePath(path);
    setLocalError('');
    try {
      await props.onDeleteRemoteBackup(savedSelectedDestination.id, path);
      setConfirmRemoteDeleteOpen(false);
      setPendingRemoteDeletePath('');
      await loadRemoteBrowser(savedSelectedDestination.id, currentRemoteBrowserPath, { force: true });
      props.onNotify('success', t('txt_backup_remote_delete_success'));
    } catch (error) {
      const message = error instanceof Error ? error.message : t('txt_backup_remote_delete_failed');
      setLocalError(message);
      props.onNotify('error', message);
    } finally {
      setDeletingRemotePath('');
    }
  }

  async function handleSelectedLocalFile(nextFile: File | null) {
    setSelectedFile(nextFile);
    setLocalError('');
    resetPendingIntegrityWarning();
    setConfirmLocalRestoreOpen(false);
    if (!nextFile) return;

    try {
      const integrity = await inspectLocalBackupFile(nextFile);
      if (!integrity.matches) {
        setPendingRestoreIntegrity({
          source: 'local',
          fileName: nextFile.name,
          result: integrity,
        });
        setConfirmIntegrityWarningOpen(true);
        return;
      }
      setConfirmLocalRestoreOpen(true);
    } catch (error) {
      const message = error instanceof Error ? error.message : t('txt_backup_integrity_check_failed');
      setLocalError(message);
      props.onNotify('error', message);
    }
  }

  async function handlePromptRemoteRestore(path: string) {
    if (!savedSelectedDestination) return;
    setLocalError('');
    resetPendingIntegrityWarning();
    try {
      const integrity = await inspectRemoteBackupFile(savedSelectedDestination.id, path);
      if (!integrity.result.matches) {
        setPendingRestoreIntegrity(integrity);
        setConfirmIntegrityWarningOpen(true);
        return;
      }
      await runRemoteRestore(path, false, false, integrity.result);
    } catch (error) {
      const message = error instanceof Error ? error.message : t('txt_backup_integrity_check_failed');
      setLocalError(message);
      props.onNotify('error', message);
    }
  }

  async function runRemoteRestore(
    path: string,
    replaceExisting: boolean,
    allowChecksumMismatch: boolean = false,
    knownIntegrity?: BackupFileIntegrityCheckResult
  ) {
    if (!savedSelectedDestination) return;
    setConfirmRemoteReplaceOpen(false);
    setConfirmIntegrityWarningOpen(false);
    setRestoringRemotePath(path);
    setLocalError('');
    try {
      const integrity = knownIntegrity ? { result: knownIntegrity } : await inspectRemoteBackupFile(savedSelectedDestination.id, path);
      startRestoreProgress('backup-restore', path.split('/').pop() || path, {
        source: 'remote',
        delayMs: replaceExisting ? 480 : 1400,
      });
      const result = allowChecksumMismatch
        ? await props.onRestoreRemoteBackupAllowingChecksumMismatch(savedSelectedDestination.id, path, replaceExisting)
        : await props.onRestoreRemoteBackup(savedSelectedDestination.id, path, replaceExisting);
      setConfirmRemoteReplaceOpen(false);
      setPendingRemoteRestorePath('');
      props.onNotify('success', `${buildIntegrityStatusMessage(integrity.result, { remote: true })} ${t('txt_backup_restore_success_relogin')}`);
      const skippedMessage = buildSkippedImportMessage(result);
      if (skippedMessage) props.onNotify('warning', skippedMessage);
      resetPendingIntegrityWarning();
    } catch (error) {
      if (!replaceExisting && isReplaceRequiredError(error)) {
        setPendingRemoteRestorePath(path);
        setConfirmRemoteReplaceOpen(true);
        clearRestoreProgress();
        return;
      }
      const message = error instanceof Error ? error.message : t('txt_backup_remote_restore_failed');
      setLocalError(message);
      props.onNotify('error', message);
      window.setTimeout(() => clearRestoreProgress(), 1200);
    } finally {
      setRestoringRemotePath('');
    }
  }

  return (
    <div className="backup-grid">
      <input
        ref={fileInputRef}
        type="file"
        hidden
        accept=".zip,application/zip"
        disabled={disableWhileBusy}
        onChange={(event) => {
          const nextFile = (event.currentTarget as HTMLInputElement).files?.[0] || null;
          void handleSelectedLocalFile(nextFile);
        }}
      />

      <BackupOperationsSidebar
        disableWhileBusy={disableWhileBusy}
        exporting={exporting}
        importing={importing}
        exportIncludeAttachments={exportIncludeAttachments}
        selectedProviderId={selectedProviderId}
        recommendedWebDavProviders={recommendedWebDavProviders}
        recommendedS3Providers={recommendedS3Providers}
        onExport={() => void handleExport()}
        onImport={() => fileInputRef.current?.click()}
        onExportIncludeAttachmentsChange={setExportIncludeAttachments}
        onSelectProvider={(providerId) => setSelectedProviderId(providerId)}
      />

      <BackupDestinationSidebar
        destinations={visibleDestinations}
        selectedDestinationId={selectedDestinationId}
        disableWhileBusy={disableWhileBusy}
        showAddChooser={showAddChooser}
        onSelectDestination={(destinationId) => {
          setSelectedProviderId(null);
          setSelectedDestinationId(destinationId);
        }}
        onToggleAddChooser={() => setShowAddChooser((current) => !current)}
        onAddDestination={handleAddDestination}
      />

      <BackupDestinationDetail
        selectedRecommendedProvider={selectedRecommendedProvider}
        selectedDestination={selectedDestination}
        selectedDestinationIsSaved={selectedDestinationIsSaved}
        canRunSelectedDestination={canRunSelectedDestination}
        canBrowseSelectedDestination={canBrowseSelectedDestination}
        disableWhileBusy={disableWhileBusy}
        loadingSettings={loadingSettings}
        savingSettings={savingSettings}
        runningRemoteBackup={runningRemoteBackup}
        availableTimeZones={selectedDestination?.schedule.timezone ? [selectedDestination.schedule.timezone] : []}
        remoteBrowser={remoteBrowser}
        remoteBrowserVisibleItems={remoteBrowserVisibleItems}
        remoteBrowserCurrentPage={currentRemoteBrowserPage}
        remoteBrowserTotalPages={remoteBrowserTotalPages}
        loadingRemoteBrowser={loadingRemoteBrowser}
        downloadingRemotePath={downloadingRemotePath}
        downloadingRemotePercent={downloadingRemotePercent}
        restoringRemotePath={restoringRemotePath}
        deletingRemotePath={deletingRemotePath}
        onSaveSettings={() => void handleSaveSettings()}
        onToggleSchedule={handleToggleSelectedSchedule}
        onRunRemoteBackup={() => void handleRunRemoteBackup()}
        onPromptDeleteDestination={() => setConfirmDeleteDestinationOpen(true)}
        onUpdateDestination={updateSelectedDestination}
        onRefreshRemoteBrowser={() => {
          if (savedSelectedDestination) {
            void loadRemoteBrowser(savedSelectedDestination.id, currentRemoteBrowserPath, { force: true });
          }
        }}
        onShowRemoteBrowserPath={(path) => {
          if (savedSelectedDestination) showRemoteBrowserPath(savedSelectedDestination.id, path);
        }}
        onDownloadRemoteBackup={(path) => void handleDownloadRemote(path)}
        onRestoreRemoteBackup={(path) => void handlePromptRemoteRestore(path)}
        onPromptDeleteRemoteBackup={(path) => {
          setPendingRemoteDeletePath(path);
          setConfirmRemoteDeleteOpen(true);
        }}
        onChangeRemoteBrowserPage={(page) => {
          if (!currentRemoteBrowserKey) return;
          setRemoteBrowserPageByKey((current) => ({ ...current, [currentRemoteBrowserKey]: page }));
        }}
      />

      {localError ? <div className="local-error">{localError}</div> : null}
      {restoreProgress && typeof document !== 'undefined' ? createPortal((
        <div className="restore-progress-overlay" aria-live="polite">
          <section className="restore-progress-card restore-progress-modal">
          <div className="restore-progress-head">
            <div>
              <div className="restore-progress-kicker">{t('txt_backup_progress_kicker')}</div>
              <h3 className="restore-progress-title">
                {t(getBackupProgressTitleKey(restoreProgress))}
              </h3>
              <p className="restore-progress-subtitle">
                {t('txt_backup_progress_subject', { name: restoreProgress.fileLabel })}
              </p>
            </div>
            <div className="restore-progress-elapsed">
              {t('txt_backup_restore_progress_elapsed', { seconds: String(restoreElapsedSeconds) })}
            </div>
          </div>
          <div className="restore-progress-meter">
            <span
              className="restore-progress-meter-bar"
              style={{
                width: `${((restoreProgress.phaseIndex + 1) / restoreProgress.phases.length) * 100}%`,
              }}
            />
          </div>
          <div className="restore-progress-current">
            <strong>{t(restoreProgress.currentTitleKey)}</strong>
            <p>{t(restoreProgress.currentDetailKey)}</p>
          </div>
          <ol className="restore-progress-list">
            {restoreProgress.phases.map((phase, index) => {
              const status = index < restoreProgress.phaseIndex ? 'done' : index === restoreProgress.phaseIndex ? 'active' : 'pending';
              return (
                <li key={phase.titleKey} className={`restore-progress-item ${status}`}>
                  <span className="restore-progress-dot" />
                  <span className="restore-progress-item-text">{t(phase.titleKey)}</span>
                </li>
              );
            })}
          </ol>
          </section>
        </div>
      ), document.body) : null}

      <ConfirmDialog
        open={confirmLocalRestoreOpen}
        title={t('txt_backup_import')}
        message={selectedFile ? t('txt_backup_selected_file_name', { name: selectedFile.name }) : t('txt_backup_restore_note')}
        confirmText={t('txt_backup_import')}
        cancelText={t('txt_cancel')}
        danger
        onConfirm={() => void runLocalRestore(false)}
        onCancel={() => {
          setConfirmLocalRestoreOpen(false);
          resetSelectedFile();
          resetPendingIntegrityWarning();
        }}
      />

      <ConfirmDialog
        open={confirmReplaceOpen}
        title={t('txt_backup_replace_confirm_title')}
        message={t('txt_backup_replace_confirm_message')}
        confirmText={importing ? t('txt_backup_restoring') : t('txt_backup_clear_and_restore')}
        cancelText={t('txt_cancel')}
        confirmDisabled={importing}
        cancelDisabled={importing}
        danger
        onConfirm={() => void runLocalRestore(
          true,
          pendingRestoreIntegrity?.source === 'local',
          pendingRestoreIntegrity?.source === 'local' ? pendingRestoreIntegrity.result : undefined
        )}
        onCancel={() => {
          if (importing) return;
          setConfirmReplaceOpen(false);
          resetSelectedFile();
          resetPendingIntegrityWarning();
        }}
      />

      <ConfirmDialog
        open={confirmRemoteReplaceOpen}
        title={t('txt_backup_replace_confirm_title')}
        message={t('txt_backup_replace_confirm_message')}
        confirmText={restoringRemotePath ? t('txt_backup_restoring') : t('txt_backup_clear_and_restore')}
        cancelText={t('txt_cancel')}
        confirmDisabled={!!restoringRemotePath}
        cancelDisabled={!!restoringRemotePath}
        danger
        onConfirm={() => void runRemoteRestore(
          pendingRemoteRestorePath,
          true,
          pendingRestoreIntegrity?.source === 'remote' && pendingRestoreIntegrity.path === pendingRemoteRestorePath,
          pendingRestoreIntegrity?.source === 'remote' && pendingRestoreIntegrity.path === pendingRemoteRestorePath
            ? pendingRestoreIntegrity.result
            : undefined
        )}
        onCancel={() => {
          if (restoringRemotePath) return;
          setConfirmRemoteReplaceOpen(false);
          setPendingRemoteRestorePath('');
          resetPendingIntegrityWarning();
        }}
      />

      <ConfirmDialog
        open={confirmIntegrityWarningOpen}
        title={t('txt_backup_restore_checksum_warning_title')}
        message={pendingRestoreIntegrity ? buildIntegrityWarningMessage(pendingRestoreIntegrity) : t('txt_backup_restore_checksum_warning_message_fallback')}
        variant="warning"
        confirmText={t('txt_backup_restore_checksum_warning_confirm')}
        cancelText={t('txt_cancel')}
        danger
        onConfirm={() => {
          if (!pendingRestoreIntegrity) return;
          setConfirmIntegrityWarningOpen(false);
          if (pendingRestoreIntegrity.source === 'local') {
            void runLocalRestore(false, true, pendingRestoreIntegrity.result);
            return;
          }
          void runRemoteRestore(pendingRestoreIntegrity.path, false, true, pendingRestoreIntegrity.result);
        }}
        onCancel={() => {
          if (importing || restoringRemotePath) return;
          resetPendingIntegrityWarning();
          setPendingRemoteRestorePath('');
          setConfirmLocalRestoreOpen(false);
          resetSelectedFile();
        }}
      />

      <ConfirmDialog
        open={confirmRemoteDeleteOpen}
        title={t('txt_delete')}
        message={t('txt_backup_remote_delete_confirm_message', { name: pendingRemoteDeletePath.split('/').pop() || pendingRemoteDeletePath })}
        confirmText={t('txt_delete')}
        cancelText={t('txt_cancel')}
        danger
        onConfirm={() => void handleDeleteRemote(pendingRemoteDeletePath)}
        onCancel={() => {
          if (deletingRemotePath) return;
          setConfirmRemoteDeleteOpen(false);
          setPendingRemoteDeletePath('');
        }}
      />

      <ConfirmDialog
        open={confirmDeleteDestinationOpen}
        title={t('txt_delete')}
        message={t('txt_backup_delete_destination_confirm_message', {
          name: selectedDestination?.name || t('txt_backup_delete_destination'),
        })}
        confirmText={t('txt_delete')}
        cancelText={t('txt_cancel')}
        danger
        onConfirm={() => void handleDeleteDestination()}
        onCancel={() => {
          if (savingSettings) return;
          setConfirmDeleteDestinationOpen(false);
        }}
      />
    </div>
  );
}
