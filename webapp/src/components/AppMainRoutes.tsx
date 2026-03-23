import { lazy, Suspense } from 'preact/compat';
import { useEffect } from 'preact/hooks';
import { Link, Route, Switch } from 'wouter';
import { ArrowUpDown, Cloud, LogOut, Settings as SettingsIcon, Shield, ShieldUser } from 'lucide-preact';
import type { ImportAttachmentFile, ImportResultSummary } from '@/components/ImportPage';
import type { AdminBackupImportResponse, AdminBackupRunResponse, AdminBackupSettings, RemoteBackupBrowserResponse } from '@/lib/api/backup';
import type { CiphersImportPayload } from '@/lib/api/vault';
import { t } from '@/lib/i18n';
import type { AdminInvite, AdminUser, AuthorizedDevice, Cipher, Folder as VaultFolder, Profile, Send, SendDraft, SessionState, VaultDraft } from '@/lib/types';
import type { ExportRequest } from '@/lib/export-formats';

const SendsPage = lazy(() => import('@/components/SendsPage'));
const TotpCodesPage = lazy(() => import('@/components/TotpCodesPage'));
const VaultPage = lazy(() => import('@/components/VaultPage'));
const SettingsPage = lazy(() => import('@/components/SettingsPage'));
const SecurityDevicesPage = lazy(() => import('@/components/SecurityDevicesPage'));
const AdminPage = lazy(() => import('@/components/AdminPage'));
const BackupCenterPage = lazy(() => import('@/components/BackupCenterPage'));
const ImportPage = lazy(() => import('@/components/ImportPage'));

function RouteContentFallback() {
  return <div className="loading-screen">{t('txt_loading_nodewarden')}</div>;
}

function LegacyBackupRedirect(props: { onNavigate: (path: string) => void }) {
  useEffect(() => {
    props.onNavigate('/backup');
  }, [props]);
  return null;
}

export interface AppMainRoutesProps {
  profile: Profile | null;
  session: SessionState | null;
  mobileLayout: boolean;
  importRoute: string;
  settingsHomeRoute: string;
  settingsAccountRoute: string;
  decryptedCiphers: Cipher[];
  decryptedFolders: VaultFolder[];
  decryptedSends: Send[];
  ciphersLoading: boolean;
  foldersLoading: boolean;
  sendsLoading: boolean;
  users: AdminUser[];
  invites: AdminInvite[];
  totpEnabled: boolean;
  authorizedDevices: AuthorizedDevice[];
  authorizedDevicesLoading: boolean;
  onNavigate: (path: string) => void;
  onLogout: () => void;
  onNotify: (type: 'success' | 'error' | 'warning', text: string) => void;
  onImport: (
    payload: CiphersImportPayload,
    options: { folderMode: 'original' | 'none' | 'target'; targetFolderId: string | null },
    attachments?: ImportAttachmentFile[]
  ) => Promise<ImportResultSummary>;
  onImportEncryptedRaw: (
    payload: CiphersImportPayload,
    options: { folderMode: 'original' | 'none' | 'target'; targetFolderId: string | null },
    attachments?: ImportAttachmentFile[]
  ) => Promise<ImportResultSummary>;
  onExport: (request: ExportRequest) => Promise<void>;
  onCreateVaultItem: (draft: VaultDraft, attachments?: File[]) => Promise<void>;
  onUpdateVaultItem: (cipher: Cipher, draft: VaultDraft, options?: { addFiles?: File[]; removeAttachmentIds?: string[] }) => Promise<void>;
  onDeleteVaultItem: (cipher: Cipher) => Promise<void>;
  onArchiveVaultItem: (cipher: Cipher) => Promise<void>;
  onUnarchiveVaultItem: (cipher: Cipher) => Promise<void>;
  onBulkDeleteVaultItems: (ids: string[]) => Promise<void>;
  onBulkPermanentDeleteVaultItems: (ids: string[]) => Promise<void>;
  onBulkRestoreVaultItems: (ids: string[]) => Promise<void>;
  onBulkArchiveVaultItems: (ids: string[]) => Promise<void>;
  onBulkUnarchiveVaultItems: (ids: string[]) => Promise<void>;
  onBulkMoveVaultItems: (ids: string[], folderId: string | null) => Promise<void>;
  onVerifyMasterPassword: (email: string, password: string) => Promise<void>;
  onCreateFolder: (name: string) => Promise<void>;
  onDeleteFolder: (folderId: string) => Promise<void>;
  onBulkDeleteFolders: (folderIds: string[]) => Promise<void>;
  onDownloadVaultAttachment: (cipher: Cipher, attachmentId: string) => Promise<void>;
  downloadingAttachmentKey: string;
  attachmentDownloadPercent: number | null;
  uploadingAttachmentName: string;
  attachmentUploadPercent: number | null;
  onRefreshVault: () => Promise<void>;
  onCreateSend: (draft: SendDraft, autoCopyLink: boolean) => Promise<void>;
  onUpdateSend: (send: Send, draft: SendDraft, autoCopyLink: boolean) => Promise<void>;
  onDeleteSend: (send: Send) => Promise<void>;
  onBulkDeleteSends: (ids: string[]) => Promise<void>;
  uploadingSendFileName: string;
  sendUploadPercent: number | null;
  onChangePassword: (currentPassword: string, nextPassword: string, nextPassword2: string) => Promise<void>;
  onSavePasswordHint: (masterPasswordHint: string) => Promise<void>;
  onEnableTotp: (secret: string, token: string) => Promise<void>;
  onOpenDisableTotp: () => void;
  onGetRecoveryCode: (masterPassword: string) => Promise<string>;
  onRefreshAuthorizedDevices: () => Promise<void>;
  onRevokeDeviceTrust: (device: AuthorizedDevice) => void;
  onRemoveDevice: (device: AuthorizedDevice) => void;
  onRevokeAllDeviceTrust: () => void;
  onRemoveAllDevices: () => void;
  onCreateInvite: (hours: number) => Promise<void>;
  onRefreshAdmin: () => void;
  onDeleteAllInvites: () => Promise<void>;
  onToggleUserStatus: (userId: string, status: 'active' | 'banned') => Promise<void>;
  onDeleteUser: (userId: string) => Promise<void>;
  onRevokeInvite: (code: string) => Promise<void>;
  onExportBackup: (includeAttachments?: boolean) => Promise<void>;
  onImportBackup: (file: File, replaceExisting?: boolean) => Promise<AdminBackupImportResponse>;
  onLoadBackupSettings: () => Promise<AdminBackupSettings>;
  onSaveBackupSettings: (settings: AdminBackupSettings) => Promise<AdminBackupSettings>;
  onRunRemoteBackup: (destinationId?: string | null) => Promise<AdminBackupRunResponse>;
  onListRemoteBackups: (destinationId: string, path: string) => Promise<RemoteBackupBrowserResponse>;
  onDownloadRemoteBackup: (destinationId: string, path: string, onProgress?: (percent: number | null) => void) => Promise<void>;
  onDeleteRemoteBackup: (destinationId: string, path: string) => Promise<void>;
  onRestoreRemoteBackup: (destinationId: string, path: string, replaceExisting?: boolean) => Promise<AdminBackupImportResponse>;
}

export default function AppMainRoutes(props: AppMainRoutesProps) {
  const importRoutePaths = [props.importRoute, '/tools/import', '/tools/import-export', '/tools/import-data', '/import', '/import-export'] as const;
  const importPageContent = (
    <Suspense fallback={<RouteContentFallback />}>
      <ImportPage
        onImport={props.onImport}
        onImportEncryptedRaw={props.onImportEncryptedRaw}
        accountKeys={props.session?.symEncKey && props.session?.symMacKey ? { encB64: props.session.symEncKey, macB64: props.session.symMacKey } : null}
        onNotify={props.onNotify}
        folders={props.decryptedFolders}
        onExport={props.onExport}
      />
    </Suspense>
  );

  const renderImportPageRoute = () => (
    <div className="stack">
      {props.mobileLayout && (
        <div className="mobile-settings-subhead">
          <button type="button" className="btn btn-secondary small mobile-settings-back" onClick={() => props.onNavigate(props.settingsHomeRoute)}>
            <span className="btn-icon" aria-hidden="true">{"<"}</span>
            {t('txt_back')}
          </button>
        </div>
      )}
      {importPageContent}
    </div>
  );

  return (
    <Switch>
      <Route path="/sends">
        <Suspense fallback={<RouteContentFallback />}>
          <SendsPage
            sends={props.decryptedSends}
            loading={props.sendsLoading}
            onRefresh={props.onRefreshVault}
            onCreate={props.onCreateSend}
            onUpdate={props.onUpdateSend}
            onDelete={props.onDeleteSend}
            onBulkDelete={props.onBulkDeleteSends}
            uploadingSendFileName={props.uploadingSendFileName}
            sendUploadPercent={props.sendUploadPercent}
            onNotify={props.onNotify}
          />
        </Suspense>
      </Route>
      <Route path="/vault/totp">
        <Suspense fallback={<RouteContentFallback />}>
          <TotpCodesPage ciphers={props.decryptedCiphers} loading={props.ciphersLoading} onNotify={props.onNotify} />
        </Suspense>
      </Route>
      <Route path="/vault">
        <Suspense fallback={<RouteContentFallback />}>
          <VaultPage
            ciphers={props.decryptedCiphers}
            folders={props.decryptedFolders}
            loading={props.ciphersLoading || props.foldersLoading}
            emailForReprompt={props.profile?.email || props.session?.email || ''}
            onRefresh={props.onRefreshVault}
            onCreate={props.onCreateVaultItem}
            onUpdate={props.onUpdateVaultItem}
            onDelete={props.onDeleteVaultItem}
            onArchive={props.onArchiveVaultItem}
            onUnarchive={props.onUnarchiveVaultItem}
            onBulkDelete={props.onBulkDeleteVaultItems}
            onBulkPermanentDelete={props.onBulkPermanentDeleteVaultItems}
            onBulkRestore={props.onBulkRestoreVaultItems}
            onBulkArchive={props.onBulkArchiveVaultItems}
            onBulkUnarchive={props.onBulkUnarchiveVaultItems}
            onBulkMove={props.onBulkMoveVaultItems}
            onVerifyMasterPassword={props.onVerifyMasterPassword}
            onNotify={props.onNotify}
            onCreateFolder={props.onCreateFolder}
            onDeleteFolder={props.onDeleteFolder}
            onBulkDeleteFolders={props.onBulkDeleteFolders}
            onDownloadAttachment={props.onDownloadVaultAttachment}
            downloadingAttachmentKey={props.downloadingAttachmentKey}
            attachmentDownloadPercent={props.attachmentDownloadPercent}
            uploadingAttachmentName={props.uploadingAttachmentName}
            attachmentUploadPercent={props.attachmentUploadPercent}
          />
        </Suspense>
      </Route>
      <Route path={props.settingsAccountRoute}>
        {props.profile && (
          <div className="stack">
            {props.mobileLayout && (
              <div className="mobile-settings-subhead">
                <button type="button" className="btn btn-secondary small mobile-settings-back" onClick={() => props.onNavigate(props.settingsHomeRoute)}>
                  <span className="btn-icon" aria-hidden="true">{"<"}</span>
                  {t('txt_back')}
                </button>
              </div>
            )}
            <Suspense fallback={<RouteContentFallback />}>
              <SettingsPage
                profile={props.profile}
                totpEnabled={props.totpEnabled}
                onChangePassword={props.onChangePassword}
                onSavePasswordHint={props.onSavePasswordHint}
                onEnableTotp={props.onEnableTotp}
                onOpenDisableTotp={props.onOpenDisableTotp}
                onGetRecoveryCode={props.onGetRecoveryCode}
                onNotify={props.onNotify}
              />
            </Suspense>
          </div>
        )}
      </Route>
      <Route path="/settings">
        {props.profile && (
          <section className="card mobile-settings-card">
            <div className="mobile-settings-links">
              <Link href={props.settingsAccountRoute} className="mobile-settings-link">
                <SettingsIcon size={18} />
                <span>{t('nav_account_settings')}</span>
              </Link>
              <Link href="/security/devices" className="mobile-settings-link">
                <Shield size={18} />
                <span>{t('nav_device_management')}</span>
              </Link>
              <Link href={props.importRoute} className="mobile-settings-link">
                <ArrowUpDown size={18} />
                <span>{t('nav_import_export')}</span>
              </Link>
              {props.profile.role === 'admin' && (
                <Link href="/admin" className="mobile-settings-link">
                  <ShieldUser size={18} />
                  <span>{t('nav_admin_panel')}</span>
                </Link>
              )}
              {props.profile.role === 'admin' && (
                <Link href="/backup" className="mobile-settings-link">
                  <Cloud size={18} />
                  <span>{t('nav_backup_strategy')}</span>
                </Link>
              )}
            </div>
            <button type="button" className="btn btn-secondary mobile-settings-logout" onClick={props.onLogout}>
              <LogOut size={14} className="btn-icon" />
              {t('txt_sign_out')}
            </button>
          </section>
        )}
      </Route>
      <Route path="/security/devices">
        <div className="stack">
          {props.mobileLayout && (
            <div className="mobile-settings-subhead">
              <button type="button" className="btn btn-secondary small mobile-settings-back" onClick={() => props.onNavigate(props.settingsHomeRoute)}>
                <span className="btn-icon" aria-hidden="true">{"<"}</span>
                {t('txt_back')}
              </button>
            </div>
          )}
          <Suspense fallback={<RouteContentFallback />}>
            <SecurityDevicesPage
              devices={props.authorizedDevices}
              loading={props.authorizedDevicesLoading}
              onRefresh={() => void props.onRefreshAuthorizedDevices()}
              onRevokeTrust={props.onRevokeDeviceTrust}
              onRemoveDevice={props.onRemoveDevice}
              onRevokeAll={props.onRevokeAllDeviceTrust}
              onRemoveAll={props.onRemoveAllDevices}
            />
          </Suspense>
        </div>
      </Route>
      <Route path="/admin">
        <div className="stack">
          {props.mobileLayout && (
            <div className="mobile-settings-subhead">
              <button type="button" className="btn btn-secondary small mobile-settings-back" onClick={() => props.onNavigate(props.settingsHomeRoute)}>
                <span className="btn-icon" aria-hidden="true">{"<"}</span>
                {t('txt_back')}
              </button>
            </div>
          )}
          <Suspense fallback={<RouteContentFallback />}>
            <AdminPage
              currentUserId={props.profile?.id || ''}
              users={props.users}
              invites={props.invites}
              onRefresh={props.onRefreshAdmin}
              onCreateInvite={props.onCreateInvite}
              onDeleteAllInvites={props.onDeleteAllInvites}
              onToggleUserStatus={props.onToggleUserStatus}
              onDeleteUser={props.onDeleteUser}
              onRevokeInvite={props.onRevokeInvite}
            />
          </Suspense>
        </div>
      </Route>
      {importRoutePaths.map((path) => (
        <Route key={path} path={path}>
          {renderImportPageRoute()}
        </Route>
      ))}
      <Route path="/help">
        <LegacyBackupRedirect onNavigate={props.onNavigate} />
      </Route>
      <Route path="/backup">
        {props.profile?.role === 'admin' ? (
          <div className="stack">
            {props.mobileLayout && (
              <div className="mobile-settings-subhead">
                <button type="button" className="btn btn-secondary small mobile-settings-back" onClick={() => props.onNavigate(props.settingsHomeRoute)}>
                  <span className="btn-icon" aria-hidden="true">{"<"}</span>
                  {t('txt_back')}
                </button>
              </div>
            )}
            <Suspense fallback={<RouteContentFallback />}>
              <BackupCenterPage
                currentUserId={props.profile?.id || null}
                onExport={props.onExportBackup}
                onImport={props.onImportBackup}
                onLoadSettings={props.onLoadBackupSettings}
                onListRemoteBackups={props.onListRemoteBackups}
                onDownloadRemoteBackup={props.onDownloadRemoteBackup}
                onDeleteRemoteBackup={props.onDeleteRemoteBackup}
                onRestoreRemoteBackup={props.onRestoreRemoteBackup}
                onSaveSettings={props.onSaveBackupSettings}
                onRunRemoteBackup={props.onRunRemoteBackup}
                onNotify={props.onNotify}
              />
            </Suspense>
          </div>
        ) : null}
      </Route>
    </Switch>
  );
}
