import { Cloud } from 'lucide-preact';
import { t } from '@/lib/i18n';

export default function HelpPage() {
  return (
    <div className="stack">
      <section className="card">
        <h3>{t('backup_strategy_title')}</h3>
        <div className="empty" style={{ minHeight: 180 }}>
          <div style={{ textAlign: 'center' }}>
            <Cloud size={34} style={{ color: '#64748b', marginBottom: 8 }} />
            <div>{t('backup_strategy_under_construction')}</div>
          </div>
        </div>
      </section>
    </div>
  );
}
