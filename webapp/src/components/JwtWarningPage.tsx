import { useMemo, useState } from 'preact/hooks';
import { AlertTriangle, Copy, RefreshCw } from 'lucide-preact';
import StandalonePageFrame from '@/components/StandalonePageFrame';
import { t } from '@/lib/i18n';

interface JwtWarningPageProps {
  reason: 'missing' | 'default' | 'too_short';
  minLength: number;
}

export default function JwtWarningPage(props: JwtWarningPageProps) {
  const [seed, setSeed] = useState(0);
  const [copyHint, setCopyHint] = useState('');

  const generatedSecret = useMemo(() => generateJwtSecret(32), [seed]);

  const title =
    props.reason === 'missing'
      ? t('txt_jwt_title_missing')
      : props.reason === 'default'
        ? t('txt_jwt_title_default')
        : t('txt_jwt_title_too_short');

  const isMissing = props.reason === 'missing';
  const fixTitle = isMissing ? t('txt_jwt_how_to_fix_add') : t('txt_jwt_how_to_fix_replace');
  const fixStep1 = isMissing ? t('txt_jwt_add_step_1') : t('txt_jwt_replace_step_1', { min: props.minLength });
  const fixStep2 = isMissing ? t('txt_jwt_add_step_2') : t('txt_jwt_replace_step_2');
  const fixStep3 = isMissing ? t('txt_jwt_add_step_3') : t('txt_jwt_replace_step_3');

  return (
    <div className="auth-page">
      <StandalonePageFrame title={title}>
        <div className="jwt-warning-head">
          <AlertTriangle size={20} />
          <strong>{t('txt_jwt_warning_subtitle')}</strong>
        </div>

        <div className="jwt-warning-box">
          <div className="jwt-warning-label">{fixTitle}</div>
          <ol className="jwt-warning-list">
            <li>{fixStep1}</li>
            <li>{fixStep2}</li>
            <li>{fixStep3}</li>
          </ol>

          <div className="jwt-generator">
            <div className="jwt-warning-label">{t('txt_random_secret_generator')}</div>
            <input className="input input-readonly" readOnly value={generatedSecret} />
            <div className="jwt-generator-actions">
              <button type="button" className="btn btn-primary" onClick={() => setSeed((v) => v + 1)}>
                <RefreshCw size={15} className="btn-icon" />
                {t('txt_regenerate')}
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={async () => {
                  await navigator.clipboard.writeText(generatedSecret);
                  setCopyHint(t('txt_copied'));
                  window.setTimeout(() => setCopyHint(''), 1500);
                }}
              >
                <Copy size={15} className="btn-icon" />
                {t('txt_copy')}
              </button>
              {copyHint && <span className="jwt-copy-hint">{copyHint}</span>}
            </div>
          </div>
        </div>
      </StandalonePageFrame>
    </div>
  );
}

function generateJwtSecret(length: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let out = '';
  for (let i = 0; i < length; i += 1) {
    out += chars[bytes[i] % chars.length];
  }
  return out;
}
