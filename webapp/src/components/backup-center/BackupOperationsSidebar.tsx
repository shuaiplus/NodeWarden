import { Download, FileUp } from 'lucide-preact';
import type { RecommendedProvider } from '@/lib/backup-recommendations';
import { hasLinkedStorages } from '@/lib/backup-recommendations';
import { t } from '@/lib/i18n';
import { BackupIncludeAttachmentsField } from './BackupIncludeAttachmentsField';

interface BackupOperationsSidebarProps {
  disableWhileBusy: boolean;
  exporting: boolean;
  importing: boolean;
  exportIncludeAttachments: boolean;
  selectedProviderId: string | null;
  recommendedWebDavProviders: RecommendedProvider[];
  recommendedS3Providers: RecommendedProvider[];
  onExport: () => void;
  onImport: () => void;
  onExportIncludeAttachmentsChange: (checked: boolean) => void;
  onSelectProvider: (providerId: string) => void;
}

export function BackupOperationsSidebar(props: BackupOperationsSidebarProps) {
  return (
    <aside className="backup-operations-sidebar">
      <div className="section-head">
        <h3>{t('txt_backup_manual')}</h3>
      </div>
      <div className="backup-actions-stack">
        <button type="button" className="btn btn-primary" disabled={props.disableWhileBusy} onClick={props.onExport}>
          <Download size={14} className="btn-icon" />
          {props.exporting ? t('txt_backup_exporting') : t('txt_backup_export')}
        </button>
        <BackupIncludeAttachmentsField
          checked={props.exportIncludeAttachments}
          disabled={props.disableWhileBusy}
          showHelp={false}
          onChange={props.onExportIncludeAttachmentsChange}
        />
        <button type="button" className="btn btn-secondary" disabled={props.disableWhileBusy} onClick={props.onImport}>
          <FileUp size={14} className="btn-icon" />
          {props.importing ? t('txt_backup_restoring') : t('txt_backup_import')}
        </button>
      </div>

      <div className="backup-divider" />

      <div className="section-head">
        <h3>{t('txt_backup_recommend_title')}</h3>
      </div>
      <div className="backup-recommendation-group">
        <h4 className="backup-recommendation-group-title">{t('txt_backup_recommend_group_webdav')}</h4>
        <div className="backup-recommendation-list">
          {props.recommendedWebDavProviders.map((provider) => (
            <button
              key={provider.id}
              type="button"
              className={`backup-destination-item ${props.selectedProviderId === provider.id ? 'active' : ''}`}
              onClick={() => props.onSelectProvider(provider.id)}
            >
              <span className="backup-recommendation-row">
                <span className="backup-destination-name">{provider.name}</span>
                <span className="backup-destination-meta">{provider.capacity}</span>
              </span>
              {hasLinkedStorages(provider) && provider.linkedStorages.length ? (
                <span className="backup-recommendation-linked">
                  {provider.linkedStorages.map((storage) => (
                    <span key={`${provider.id}-${storage.name}`} className="backup-recommendation-linked-item">
                      <span>{storage.name}</span>
                      <span>{storage.capacity}</span>
                    </span>
                  ))}
                </span>
              ) : null}
            </button>
          ))}
        </div>
      </div>
      <div className="backup-recommendation-group">
        <h4 className="backup-recommendation-group-title">{t('txt_backup_recommend_group_s3')}</h4>
        {props.recommendedS3Providers.length ? (
          <div className="backup-recommendation-list">
            {props.recommendedS3Providers.map((provider) => (
              <button
                key={provider.id}
                type="button"
                className={`backup-destination-item ${props.selectedProviderId === provider.id ? 'active' : ''}`}
                onClick={() => props.onSelectProvider(provider.id)}
              >
                <span className="backup-recommendation-row">
                  <span className="backup-destination-name">{provider.name}</span>
                  <span className="backup-destination-meta">{provider.capacity}</span>
                </span>
              </button>
            ))}
          </div>
        ) : (
          <div className="backup-browser-empty">{t('txt_backup_recommend_empty')}</div>
        )}
      </div>
    </aside>
  );
}
