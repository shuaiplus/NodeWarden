import { useEffect, useRef, useState } from 'preact/hooks';
import ConfirmDialog from '@/components/ConfirmDialog';
import {
  type AdminBackupImportResponse,
  type AdminBackupRunResponse,
  type AdminBackupSettings,
  type BackupDestinationRecord,
  type BackupDestinationType,
  type RemoteBackupBrowserResponse,
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
import { RECOMMENDED_PROVIDERS, type RecommendedProvider } from '@/lib/backup-recommendations';
import { t } from '@/lib/i18n';
import { BackupDestinationDetail } from './backup-center/BackupDestinationDetail';
import { BackupDestinationSidebar } from './backup-center/BackupDestinationSidebar';
import { BackupOperationsSidebar } from './backup-center/BackupOperationsSidebar';

interface BackupCenterPageProps {
  currentUserId: string | null;
  onExport: (includeAttachments?: boolean) => Promise<void>;
  onImport: (file: File, replaceExisting?: boolean) => Promise<AdminBackupImportResponse>;
  onLoadSettings: () => Promise<AdminBackupSettings>;
  onSaveSettings: (settings: AdminBackupSettings) => Promise<AdminBackupSettings>;
  onRunRemoteBackup: (destinationId?: string | null) => Promise<AdminBackupRunResponse>;
  onListRemoteBackups: (destinationId: string, path: string) => Promise<RemoteBackupBrowserResponse>;
  onDownloadRemoteBackup: (destinationId: string, path: string, onProgress?: (percent: number | null) => void) => Promise<void>;
  onDeleteRemoteBackup: (destinationId: string, path: string) => Promise<void>;
  onRestoreRemoteBackup: (destinationId: string, path: string, replaceExisting?: boolean) => Promise<AdminBackupImportResponse>;
  onNotify: (type: 'success' | 'error' | 'warning', text: string) => void;
}

function buildSkippedImportMessage(result: AdminBackupImportResponse): string | null {
  const skipped = result.skipped;
  if (!skipped || !skipped.attachments) return null;
  return t('txt_backup_restore_skipped_summary', {
    reason: skipped.reason || t('txt_backup_restore_skipped_reason_default'),
    attachments: String(skipped.attachments),
  });
}

export default function BackupCenterPage(props: BackupCenterPageProps) {
  const persistedRemoteStateRef = useRef(loadPersistedRemoteBrowserState(props.currentUserId));
  const persistedRemoteState = persistedRemoteStateRef.current;
  const fileInputRef = useRef<HTMLInputElement | null>(null);

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
  const [remoteRestoreStatusText, setRemoteRestoreStatusText] = useState('');
  const [deletingRemotePath, setDeletingRemotePath] = useState('');
  const [localError, setLocalError] = useState('');
  const [confirmLocalRestoreOpen, setConfirmLocalRestoreOpen] = useState(false);
  const [confirmReplaceOpen, setConfirmReplaceOpen] = useState(false);
  const [confirmRemoteReplaceOpen, setConfirmRemoteReplaceOpen] = useState(false);
  const [confirmDeleteDestinationOpen, setConfirmDeleteDestinationOpen] = useState(false);
  const [confirmRemoteDeleteOpen, setConfirmRemoteDeleteOpen] = useState(false);
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
      await props.onExport(exportIncludeAttachments);
      props.onNotify('success', t('txt_backup_export_success'));
    } catch (error) {
      const message = error instanceof Error ? error.message : t('txt_backup_export_failed');
      setLocalError(message);
      props.onNotify('error', message);
    } finally {
      setExporting(false);
    }
  }

  async function runLocalRestore(replaceExisting: boolean) {
    if (!selectedFile) {
      const message = t('txt_backup_file_required');
      setLocalError(message);
      props.onNotify('error', message);
      return;
    }
    setLocalError('');
    setImporting(true);
    try {
      const result = await props.onImport(selectedFile, replaceExisting);
      props.onNotify('success', t('txt_backup_restore_success_relogin'));
      const skippedMessage = buildSkippedImportMessage(result);
      if (skippedMessage) props.onNotify('warning', skippedMessage);
      resetSelectedFile();
      setConfirmLocalRestoreOpen(false);
      setConfirmReplaceOpen(false);
    } catch (error) {
      if (!replaceExisting && isReplaceRequiredError(error)) {
        setConfirmLocalRestoreOpen(false);
        setConfirmReplaceOpen(true);
        return;
      }
      const message = error instanceof Error ? error.message : t('txt_backup_restore_failed');
      setLocalError(message);
      props.onNotify('error', message);
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
      const result = await props.onRunRemoteBackup(selectedDestination.id);
      setSavedSettings(result.settings);
      setSettings(result.settings);
      setSelectedDestinationId(selectedDestination.id);
      await loadRemoteBrowser(selectedDestination.id, currentRemoteBrowserPath, { force: true });
      props.onNotify('success', t('txt_backup_remote_run_success'));
    } catch (error) {
      const message = error instanceof Error ? error.message : t('txt_backup_remote_run_failed');
      setLocalError(message);
      props.onNotify('error', message);
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

  async function runRemoteRestore(path: string, replaceExisting: boolean) {
    if (!savedSelectedDestination) return;
    setRestoringRemotePath(path);
    setRemoteRestoreStatusText(replaceExisting ? t('txt_backup_remote_restore_stage_replace') : t('txt_backup_remote_restore_stage_prepare'));
    setLocalError('');
    try {
      const result = await props.onRestoreRemoteBackup(savedSelectedDestination.id, path, replaceExisting);
      setConfirmRemoteReplaceOpen(false);
      setPendingRemoteRestorePath('');
      setRemoteRestoreStatusText('');
      props.onNotify('success', t('txt_backup_restore_success_relogin'));
      const skippedMessage = buildSkippedImportMessage(result);
      if (skippedMessage) props.onNotify('warning', skippedMessage);
    } catch (error) {
      if (!replaceExisting && isReplaceRequiredError(error)) {
        setPendingRemoteRestorePath(path);
        setConfirmRemoteReplaceOpen(true);
        setRemoteRestoreStatusText('');
        return;
      }
      const message = error instanceof Error ? error.message : t('txt_backup_remote_restore_failed');
      setRemoteRestoreStatusText('');
      setLocalError(message);
      props.onNotify('error', message);
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
          setSelectedFile(nextFile);
          setLocalError('');
          if (nextFile) setConfirmLocalRestoreOpen(true);
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
        onRestoreRemoteBackup={(path) => void runRemoteRestore(path, false)}
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
      {!localError && remoteRestoreStatusText ? <div className="status-ok">{remoteRestoreStatusText}</div> : null}

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
        onConfirm={() => void runLocalRestore(true)}
        onCancel={() => {
          if (importing) return;
          setConfirmReplaceOpen(false);
          resetSelectedFile();
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
        onConfirm={() => void runRemoteRestore(pendingRemoteRestorePath, true)}
        onCancel={() => {
          if (restoringRemotePath) return;
          setConfirmRemoteReplaceOpen(false);
          setPendingRemoteRestorePath('');
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
