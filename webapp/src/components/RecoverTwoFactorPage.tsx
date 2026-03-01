import { useState } from 'preact/hooks';
import { Eye, EyeOff } from 'lucide-preact';

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
      <div className="auth-card">
        <h1>Recover Two-step Login</h1>
        <p className="muted">Sign in with your one-time recovery code to disable two-step verification.</p>

        <label className="field">
          <span>Email</span>
          <input
            className="input"
            type="email"
            value={props.values.email}
            onInput={(e) => props.onChange({ ...props.values, email: (e.currentTarget as HTMLInputElement).value })}
          />
        </label>

        <label className="field">
          <span>Master Password</span>
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
          <span>Recovery Code</span>
          <input
            className="input"
            value={props.values.recoveryCode}
            onInput={(e) => props.onChange({ ...props.values, recoveryCode: (e.currentTarget as HTMLInputElement).value.toUpperCase() })}
          />
        </label>

        <div className="field-grid">
          <button type="button" className="btn btn-primary" onClick={props.onSubmit}>
            Submit
          </button>
          <button type="button" className="btn btn-secondary" onClick={props.onCancel}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
