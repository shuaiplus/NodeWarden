import { ArrowUpDown } from 'lucide-preact';
import { t } from '@/lib/i18n';

export default function ImportExportPage() {
  return (
    <div className="stack">
      <section className="card">
        <h3>{t('import_export_title')}</h3>
        <div className="empty" style={{ minHeight: 180 }}>
          <div style={{ textAlign: 'center' }}>
            <ArrowUpDown size={34} style={{ color: '#64748b', marginBottom: 8 }} />
            <div>{t('import_export_under_construction')}</div>
          </div>
        </div>
      </section>
    </div>
  );
}

