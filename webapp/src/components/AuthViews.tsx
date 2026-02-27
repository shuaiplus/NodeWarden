import { useState } from 'preact/hooks';

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
          {show ? 'Hide' : 'Show'}
        </button>
      </div>
    </label>
  );
}

export default function AuthViews(props: AuthViewsProps) {
  if (props.mode === 'locked') {
    return (
      <div className="auth-page">
        <div className="auth-card">
          <h1>Unlock Vault</h1>
          <p className="muted">{props.emailForLock}</p>
          <PasswordField
            label="Master Password"
            value={props.unlockPassword}
            autoFocus
            onInput={props.onChangeUnlock}
          />
          <button type="button" className="btn btn-primary full" onClick={props.onSubmitUnlock}>
            Unlock
          </button>
          <div className="or">or</div>
          <button type="button" className="btn btn-secondary full" onClick={props.onLogout}>
            Log Out
          </button>
        </div>
      </div>
    );
  }

  if (props.mode === 'register') {
    return (
      <div className="auth-page">
        <div className="auth-card">
          <h1>Create Account</h1>
          <p className="muted">NodeWarden</p>
          <label className="field">
            <span>Name</span>
            <input
              className="input"
              value={props.registerValues.name}
              onInput={(e) =>
                props.onChangeRegister({ ...props.registerValues, name: (e.currentTarget as HTMLInputElement).value })
              }
            />
          </label>
          <label className="field">
            <span>Email</span>
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
            label="Master Password"
            value={props.registerValues.password}
            onInput={(v) => props.onChangeRegister({ ...props.registerValues, password: v })}
          />
          <PasswordField
            label="Confirm Master Password"
            value={props.registerValues.password2}
            onInput={(v) => props.onChangeRegister({ ...props.registerValues, password2: v })}
          />
          <label className="field">
            <span>Invite Code (Optional)</span>
            <input
              className="input"
              value={props.registerValues.inviteCode}
              onInput={(e) =>
                props.onChangeRegister({ ...props.registerValues, inviteCode: (e.currentTarget as HTMLInputElement).value })
              }
            />
          </label>
          <button type="button" className="btn btn-primary full" onClick={props.onSubmitRegister}>
            Create Account
          </button>
          <div className="or">or</div>
          <button type="button" className="btn btn-secondary full" onClick={props.onGotoLogin}>
            Back To Login
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        <h1>Log In</h1>
        <p className="muted">NodeWarden</p>
        <label className="field">
          <span>Email</span>
          <input
            className="input"
            type="email"
            value={props.loginValues.email}
            onInput={(e) => props.onChangeLogin({ ...props.loginValues, email: (e.currentTarget as HTMLInputElement).value })}
          />
        </label>
        <PasswordField
          label="Master Password"
          value={props.loginValues.password}
          onInput={(v) => props.onChangeLogin({ ...props.loginValues, password: v })}
          autoFocus
        />
        <button type="button" className="btn btn-primary full" onClick={props.onSubmitLogin}>
          Log In
        </button>
        <div className="or">or</div>
        <button type="button" className="btn btn-secondary full" onClick={props.onGotoRegister}>
          Create Account
        </button>
      </div>
    </div>
  );
}
