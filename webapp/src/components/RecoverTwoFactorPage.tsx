import { useState } from 'preact/hooks';
import { Eye, EyeOff, Send, X } from 'lucide-preact';
import StandalonePageFrame from '@/components/StandalonePageFrame';
import { t } from '@/lib/i18n';

interface RecoverTwoFactorPageProps {
  values: { email: string; password: string; recoveryCode: string };
  onChange: (next: { email: string; password: string; recoveryCode: string }) => void;
  onSubmit: () => void;
  onCancel: () => void;
}

export default function RecoverTwoFactorPage(props: RecoverTwoFactorPageProps) {
  const [showPassword, setShowPassword] = useState(false);

  return (
    <div className="auth-page">
      <StandalonePageFrame title={t('txt_recover_two_step_login')}>
        <p className="muted standalone-muted">{t('txt_use_your_one_time_recovery_code_to_disable_two_step_verification')}</p>

        <label className="field">
          <span>{t('txt_email')}</span>
          <input
            className="input"
            type="email"
            value={props.values.email}
            onInput={(e) => props.onChange({ ...props.values, email: (e.currentTarget as HTMLInputElement).value })}
          />
        </label>

        <label className="field">
          <span>{t('txt_master_password')}</span>
          <div className="password-wrap">
            <input
              className="input"
              type={showPassword ? 'text' : 'password'}
              value={props.values.password}
              onInput={(e) => props.onChange({ ...props.values, password: (e.currentTarget as HTMLInputElement).value })}
            />
            <button type="button" className="eye-btn" onClick={() => setShowPassword((v) => !v)}>
              {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>
        </label>

        <label className="field">
          <span>{t('txt_recovery_code')}</span>
          <input
            className="input"
            value={props.values.recoveryCode}
            onInput={(e) => props.onChange({ ...props.values, recoveryCode: (e.currentTarget as HTMLInputElement).value.toUpperCase() })}
          />
        </label>

        <div className="field-grid">
          <button type="button" className="btn btn-primary" onClick={props.onSubmit}>
            <Send size={14} className="btn-icon" />
            {t('txt_submit')}
          </button>
          <button type="button" className="btn btn-secondary" onClick={props.onCancel}>
            <X size={14} className="btn-icon" />
            {t('txt_cancel')}
          </button>
        </div>
      </StandalonePageFrame>
    </div>
  );
}
