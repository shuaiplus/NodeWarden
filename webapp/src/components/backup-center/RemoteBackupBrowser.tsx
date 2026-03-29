import { Download, FileArchive, FolderOpen, RefreshCw, RotateCcw, Trash2 } from 'lucide-preact';
import type { RemoteBackupBrowserResponse } from '@/lib/api/backup';
import { formatBytes, formatDateTime, isZipCandidate } from '@/lib/backup-center';
import { t } from '@/lib/i18n';

interface RemoteBackupBrowserProps {
  canBrowse: boolean;
  destinationIsSaved: boolean;
  disableWhileBusy: boolean;
  loadingRemoteBrowser: boolean;
  remoteBrowser: RemoteBackupBrowserResponse | null;
  visibleItems: RemoteBackupBrowserResponse['items'];
  currentPage: number;
  totalPages: number;
  downloadingRemotePath: string;
  downloadingRemotePercent: number | null;
  restoringRemotePath: string;
  deletingRemotePath: string;
  onRefresh: () => void;
  onShowPath: (path: string) => void;
  onDownload: (path: string) => void;
  onRestore: (path: string) => void;
  onPromptDelete: (path: string) => void;
  onChangePage: (page: number) => void;
}

export function RemoteBackupBrowser(props: RemoteBackupBrowserProps) {
  const getDownloadLabel = (path: string) => {
    if (props.downloadingRemotePath !== path) return t('txt_backup_remote_download');
    return props.downloadingRemotePercent == null
      ? t('txt_downloading')
      : t('txt_downloading_percent', { percent: props.downloadingRemotePercent });
  };

  return (
    <>
      <div className="backup-divider" />

      <div className="section-head">
        <h3>{t('txt_backup_remote_title')}</h3>
        {props.canBrowse ? (
          <div className="actions">
            <button type="button" className="btn btn-secondary small" disabled={props.loadingRemoteBrowser || props.disableWhileBusy} onClick={props.onRefresh}>
              <RefreshCw size={14} className="btn-icon" />
              {t('txt_backup_remote_refresh')}
            </button>
          </div>
        ) : null}
      </div>

      {!props.destinationIsSaved ? (
        <div className="backup-browser-empty">{t('txt_backup_remote_save_first')}</div>
      ) : !props.remoteBrowser ? (
        <div className="backup-browser-empty">{t('txt_backup_remote_cached_empty')}</div>
      ) : (
        <>
          <div className="backup-browser-path">
            <strong>{t('txt_backup_remote_current_path')}</strong>
            <span>{props.remoteBrowser.currentPath ? `/${props.remoteBrowser.currentPath}` : '/'}</span>
          </div>

          <div className="actions backup-browser-nav">
            <button type="button" className="btn btn-secondary small" disabled={props.loadingRemoteBrowser || props.disableWhileBusy} onClick={() => props.onShowPath('')}>
              <FolderOpen size={14} className="btn-icon" />
              {t('txt_backup_remote_root')}
            </button>
            <button
              type="button"
              className="btn btn-secondary small"
              disabled={props.loadingRemoteBrowser || props.disableWhileBusy || props.remoteBrowser.parentPath === null}
              onClick={() => props.onShowPath(props.remoteBrowser?.parentPath || '')}
            >
              <RotateCcw size={14} className="btn-icon" />
              {t('txt_backup_remote_up')}
            </button>
          </div>

          {props.loadingRemoteBrowser ? (
            <div className="backup-browser-empty">{t('txt_backup_remote_loading')}</div>
          ) : props.remoteBrowser.items.length ? (
            <>
              <div className="backup-browser-list">
                {props.visibleItems.map((item) => (
                  <div key={`${item.isDirectory ? 'd' : 'f'}:${item.path}`} className="backup-browser-row">
                    <button
                      type="button"
                      className={`backup-browser-entry ${item.isDirectory ? 'dir' : 'file'}`}
                      onClick={() => {
                        if (item.isDirectory) props.onShowPath(item.path);
                      }}
                    >
                      {item.isDirectory ? <FolderOpen size={16} className="btn-icon" /> : <FileArchive size={16} className="btn-icon" />}
                      <span className="backup-browser-name">{item.name}</span>
                    </button>
                    <div className="backup-browser-meta">
                      <span>{item.modifiedAt ? formatDateTime(item.modifiedAt) : t('txt_backup_remote_unknown_time')}</span>
                      <span>{item.isDirectory ? t('txt_backup_remote_folder') : formatBytes(item.size)}</span>
                    </div>
                    <div className="actions backup-browser-actions">
                      {item.isDirectory ? (
                        <button type="button" className="btn btn-secondary small" onClick={() => props.onShowPath(item.path)}>
                          <FolderOpen size={14} className="btn-icon" />
                          {t('txt_backup_remote_open')}
                        </button>
                      ) : isZipCandidate(item) ? (
                        <>
                          <button type="button" className="btn btn-secondary small" disabled={props.disableWhileBusy || props.downloadingRemotePath === item.path} onClick={() => props.onDownload(item.path)}>
                            <Download size={14} className="btn-icon" />
                            {getDownloadLabel(item.path)}
                          </button>
                          <button type="button" className="btn btn-primary small" disabled={props.disableWhileBusy || props.restoringRemotePath === item.path} onClick={() => props.onRestore(item.path)}>
                            <RotateCcw size={14} className="btn-icon" />
                            {props.restoringRemotePath === item.path ? t('txt_backup_restoring') : t('txt_backup_remote_restore')}
                          </button>
                          <button type="button" className="btn btn-danger small" disabled={props.disableWhileBusy || props.deletingRemotePath === item.path} onClick={() => props.onPromptDelete(item.path)}>
                            <Trash2 size={14} className="btn-icon" />
                            {props.deletingRemotePath === item.path ? t('txt_backup_remote_deleting') : t('txt_delete')}
                          </button>
                        </>
                      ) : null}
                    </div>
                  </div>
                ))}
              </div>
              {props.totalPages > 1 ? (
                <div className="backup-browser-pagination">
                  <button type="button" className="btn btn-secondary small" disabled={props.currentPage <= 1} onClick={() => props.onChangePage(props.currentPage - 1)}>
                    {t('txt_prev')}
                  </button>
                  <span className="backup-browser-page-indicator">
                    {props.currentPage} / {props.totalPages}
                  </span>
                  <button type="button" className="btn btn-secondary small" disabled={props.currentPage >= props.totalPages} onClick={() => props.onChangePage(props.currentPage + 1)}>
                    {t('txt_next')}
                  </button>
                </div>
              ) : null}
            </>
          ) : (
            <div className="backup-browser-empty">{t('txt_backup_remote_empty')}</div>
          )}
        </>
      )}
    </>
  );
}
