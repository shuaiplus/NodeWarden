import { useState } from 'preact/hooks';
import { ArrowLeft, Eye, EyeOff, LogIn, LogOut, Unlock, UserPlus } from 'lucide-preact';
import StandalonePageFrame from '@/components/StandalonePageFrame';
import { t } from '@/lib/i18n';

interface LoginValues {
  email: string;
  password: string;
}

interface RegisterValues {
  name: string;
  email: string;
  password: string;
  password2: string;
  inviteCode: string;
}

interface AuthViewsProps {
  mode: 'login' | 'register' | 'locked';
  loginValues: LoginValues;
  registerValues: RegisterValues;
  unlockPassword: string;
  emailForLock: string;
  onChangeLogin: (next: LoginValues) => void;
  onChangeRegister: (next: RegisterValues) => void;
  onChangeUnlock: (password: string) => void;
  onSubmitLogin: () => void;
  onSubmitRegister: () => void;
  onSubmitUnlock: () => void;
  onGotoLogin: () => void;
  onGotoRegister: () => void;
  onLogout: () => void;
}

function PasswordField(props: {
  label: string;
  value: string;
  onInput: (v: string) => void;
  autoFocus?: boolean;
}) {
  const [show, setShow] = useState(false);
  return (
    <label className="field">
      <span>{props.label}</span>
      <div className="password-wrap">
        <input
          className="input"
          type={show ? 'text' : 'password'}
          value={props.value}
          onInput={(e) => props.onInput((e.currentTarget as HTMLInputElement).value)}
          autoFocus={props.autoFocus}
        />
        <button type="button" className="eye-btn" onClick={() => setShow((v) => !v)}>
          {show ? <EyeOff size={16} /> : <Eye size={16} />}
        </button>
      </div>
    </label>
  );
}

export default function AuthViews(props: AuthViewsProps) {
  if (props.mode === 'locked') {
    return (
      <div className="auth-page">
        <StandalonePageFrame title={t('txt_unlock_vault')}>
          <p className="muted standalone-muted">{props.emailForLock}</p>
          <PasswordField
            label={t('txt_master_password')}
            value={props.unlockPassword}
            autoFocus
            onInput={props.onChangeUnlock}
          />
          <button type="button" className="btn btn-primary full" onClick={props.onSubmitUnlock}>
            <Unlock size={16} className="btn-icon" />
            {t('txt_unlock')}
          </button>
          <div className="or">{t('txt_or')}</div>
          <button type="button" className="btn btn-secondary full" onClick={props.onLogout}>
            <LogOut size={16} className="btn-icon" />
            {t('txt_log_out')}
          </button>
        </StandalonePageFrame>
      </div>
    );
  }

  if (props.mode === 'register') {
    return (
      <div className="auth-page">
        <StandalonePageFrame title={t('txt_create_account')}>
          <label className="field">
            <span>{t('txt_name')}</span>
            <input
              className="input"
              value={props.registerValues.name}
              onInput={(e) =>
                props.onChangeRegister({ ...props.registerValues, name: (e.currentTarget as HTMLInputElement).value })
              }
            />
          </label>
          <label className="field">
            <span>{t('txt_email')}</span>
            <input
              className="input"
              type="email"
              value={props.registerValues.email}
              onInput={(e) =>
                props.onChangeRegister({ ...props.registerValues, email: (e.currentTarget as HTMLInputElement).value })
              }
            />
          </label>
          <PasswordField
            label={t('txt_master_password')}
            value={props.registerValues.password}
            onInput={(v) => props.onChangeRegister({ ...props.registerValues, password: v })}
          />
          <PasswordField
            label={t('txt_confirm_master_password')}
            value={props.registerValues.password2}
            onInput={(v) => props.onChangeRegister({ ...props.registerValues, password2: v })}
          />
          <label className="field">
            <span>{t('txt_invite_code_optional')}</span>
            <input
              className="input"
              value={props.registerValues.inviteCode}
              onInput={(e) =>
                props.onChangeRegister({ ...props.registerValues, inviteCode: (e.currentTarget as HTMLInputElement).value })
              }
            />
          </label>
          <button type="button" className="btn btn-primary full" onClick={props.onSubmitRegister}>
            <UserPlus size={16} className="btn-icon" />
            {t('txt_create_account')}
          </button>
          <div className="or">{t('txt_or')}</div>
          <button type="button" className="btn btn-secondary full" onClick={props.onGotoLogin}>
            <ArrowLeft size={16} className="btn-icon" />
            {t('txt_back_to_login')}
          </button>
        </StandalonePageFrame>
      </div>
    );
  }

  return (
    <div className="auth-page">
      <StandalonePageFrame title={t('txt_log_in')}>
        <label className="field">
          <span>{t('txt_email')}</span>
          <input
            className="input"
            type="email"
            value={props.loginValues.email}
            onInput={(e) => props.onChangeLogin({ ...props.loginValues, email: (e.currentTarget as HTMLInputElement).value })}
          />
        </label>
        <PasswordField
          label={t('txt_master_password')}
          value={props.loginValues.password}
          onInput={(v) => props.onChangeLogin({ ...props.loginValues, password: v })}
          autoFocus
        />
        <button type="button" className="btn btn-primary full" onClick={props.onSubmitLogin}>
          <LogIn size={16} className="btn-icon" />
          {t('txt_log_in')}
        </button>
        <div className="or">{t('txt_or')}</div>
        <button type="button" className="btn btn-secondary full" onClick={props.onGotoRegister}>
          <UserPlus size={16} className="btn-icon" />
          {t('txt_create_account')}
        </button>
      </StandalonePageFrame>
    </div>
  );
}
