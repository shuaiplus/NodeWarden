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
  passwordHint: string;
  inviteCode: string;
}

interface AuthViewsProps {
  mode: 'login' | 'register' | 'locked';
  pendingAction: 'login' | 'register' | 'unlock' | null;
  unlockReady: boolean;
  unlockPreparing: boolean;
  loginValues: LoginValues;
  registerValues: RegisterValues;
  unlockPassword: string;
  emailForLock: string;
  loginHintLoading: boolean;
  onChangeLogin: (next: LoginValues) => void;
  onChangeRegister: (next: RegisterValues) => void;
  onChangeUnlock: (password: string) => void;
  onSubmitLogin: () => void;
  onSubmitRegister: () => void;
  onSubmitUnlock: () => void;
  onGotoLogin: () => void;
  onGotoRegister: () => void;
  onLogout: () => void;
  onTogglePasswordHint: () => void;
  onShowLockedPasswordHint: () => void;
}

function PasswordField(props: {
  label: string;
  value: string;
  onInput: (v: string) => void;
  autoFocus?: boolean;
  autoComplete?: string;
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
          autoComplete={props.autoComplete}
        />
        <button type="button" className="eye-btn" onClick={() => setShow((v) => !v)}>
          {show ? <EyeOff size={16} /> : <Eye size={16} />}
        </button>
      </div>
    </label>
  );
}

export default function AuthViews(props: AuthViewsProps) {
  const loginBusy = props.pendingAction === 'login';
  const registerBusy = props.pendingAction === 'register';
  const unlockBusy = props.pendingAction === 'unlock';

  if (props.mode === 'locked') {
    return (
      <div className="auth-page">
        <StandalonePageFrame title={t('txt_unlock_vault')}>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              props.onSubmitUnlock();
            }}
          >
            <p className="muted standalone-muted">{props.emailForLock}</p>
            <input type="text" value={props.emailForLock} autoComplete="username" readOnly hidden tabIndex={-1} aria-hidden="true" />
            <PasswordField
              label={t('txt_master_password')}
              value={props.unlockPassword}
              autoFocus
              autoComplete="current-password"
              onInput={props.onChangeUnlock}
            />
            <div className="auth-support-row">
              <span />
              <button
                type="button"
                className="auth-link-btn"
                onClick={props.onShowLockedPasswordHint}
                disabled={unlockBusy || props.unlockPreparing}
              >
                {t('txt_show_password_hint')}
              </button>
            </div>
            {props.unlockPreparing ? (
              <p className="muted standalone-muted">{t('txt_loading')}</p>
            ) : null}
            <button type="submit" className="btn btn-primary full" disabled={unlockBusy || props.unlockPreparing || !props.unlockReady}>
              <Unlock size={16} className="btn-icon" />
              {unlockBusy ? t('txt_unlocking') : props.unlockPreparing ? t('txt_loading') : t('txt_unlock')}
            </button>
            <div className="or">{t('txt_or')}</div>
            <button type="button" className="btn btn-secondary full" onClick={props.onLogout} disabled={unlockBusy}>
              <LogOut size={16} className="btn-icon" />
              {t('txt_log_out')}
            </button>
          </form>
        </StandalonePageFrame>
      </div>
    );
  }

  if (props.mode === 'register') {
    return (
      <div className="auth-page">
        <StandalonePageFrame title={t('txt_create_account')}>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              props.onSubmitRegister();
            }}
          >
            <label className="field">
              <span>{t('txt_name')}</span>
              <input
                className="input"
                value={props.registerValues.name}
                autoComplete="name"
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
                autoComplete="email"
                onInput={(e) =>
                  props.onChangeRegister({ ...props.registerValues, email: (e.currentTarget as HTMLInputElement).value })
                }
              />
            </label>
            <PasswordField
              label={t('txt_master_password')}
              value={props.registerValues.password}
              autoComplete="new-password"
              onInput={(v) => props.onChangeRegister({ ...props.registerValues, password: v })}
            />
            <PasswordField
              label={t('txt_confirm_master_password')}
              value={props.registerValues.password2}
              autoComplete="new-password"
              onInput={(v) => props.onChangeRegister({ ...props.registerValues, password2: v })}
            />
            <label className="field">
              <span>{t('txt_password_hint_optional')}</span>
              <input
                className="input"
                maxLength={120}
                value={props.registerValues.passwordHint}
                placeholder={t('txt_password_hint_register_placeholder')}
                onInput={(e) =>
                  props.onChangeRegister({ ...props.registerValues, passwordHint: (e.currentTarget as HTMLInputElement).value })
                }
              />
            </label>
            <label className="field">
              <span>{t('txt_invite_code_optional')}</span>
              <input
                className="input"
                value={props.registerValues.inviteCode}
                autoComplete="off"
                onInput={(e) =>
                  props.onChangeRegister({ ...props.registerValues, inviteCode: (e.currentTarget as HTMLInputElement).value })
                }
              />
            </label>
            <button type="submit" className="btn btn-primary full" disabled={registerBusy}>
              <UserPlus size={16} className="btn-icon" />
              {registerBusy ? t('txt_registering') : t('txt_create_account')}
            </button>
            <div className="or">{t('txt_or')}</div>
            <button type="button" className="btn btn-secondary full" onClick={props.onGotoLogin} disabled={registerBusy}>
              <ArrowLeft size={16} className="btn-icon" />
              {t('txt_back_to_login')}
            </button>
          </form>
        </StandalonePageFrame>
      </div>
    );
  }

  return (
    <div className="auth-page">
      <StandalonePageFrame title={t('txt_log_in')}>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            props.onSubmitLogin();
          }}
        >
          <label className="field">
            <span>{t('txt_email')}</span>
            <input
              className="input"
              type="email"
              value={props.loginValues.email}
              autoComplete="username"
              onInput={(e) => props.onChangeLogin({ ...props.loginValues, email: (e.currentTarget as HTMLInputElement).value })}
            />
          </label>
          <PasswordField
            label={t('txt_master_password')}
            value={props.loginValues.password}
            autoComplete="current-password"
            onInput={(v) => props.onChangeLogin({ ...props.loginValues, password: v })}
            autoFocus
          />
          <div className="auth-support-row">
            <span />
            <button
              type="button"
              className="auth-link-btn"
              onClick={props.onTogglePasswordHint}
              disabled={loginBusy || !props.loginValues.email.trim()}
            >
              {props.loginHintLoading
                ? t('txt_loading_password_hint')
                : t('txt_show_password_hint')}
            </button>
          </div>
          <button type="submit" className="btn btn-primary full" disabled={loginBusy}>
            <LogIn size={16} className="btn-icon" />
            {loginBusy ? t('txt_logging_in') : t('txt_log_in')}
          </button>
          <div className="or">{t('txt_or')}</div>
          <button type="button" className="btn btn-secondary full" onClick={props.onGotoRegister} disabled={loginBusy}>
            <UserPlus size={16} className="btn-icon" />
            {t('txt_create_account')}
          </button>
        </form>
      </StandalonePageFrame>
    </div>
  );
}
