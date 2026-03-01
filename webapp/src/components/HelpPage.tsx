import { Construction } from 'lucide-preact';
import { t } from '@/lib/i18n';

export default function HelpPage() {
  return (
    <div className="stack">
      <section className="card">
        <h3>{t('support_title')}</h3>
        <div className="empty" style={{ minHeight: 180 }}>
          <div style={{ textAlign: 'center' }}>
            <Construction size={34} style={{ color: '#64748b', marginBottom: 8 }} />
            <div>{t('support_under_construction')}</div>
          </div>
        </div>
      </section>
    </div>
  );
}
