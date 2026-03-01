import { useEffect, useMemo, useState } from 'preact/hooks';
import { Clipboard, RefreshCw, ShieldCheck, ShieldOff } from 'lucide-preact';
import qrcode from 'qrcode-generator';
import type { Profile } from '@/lib/types';

interface SettingsPageProps {
  profile: Profile;
  totpEnabled: boolean;
  onSaveProfile: (name: string, email: string) => Promise<void>;
  onChangePassword: (currentPassword: string, nextPassword: string, nextPassword2: string) => Promise<void>;
  onEnableTotp: (secret: string, token: string) => Promise<void>;
  onOpenDisableTotp: () => void;
  onGetRecoveryCode: (masterPassword: string) => Promise<string>;
  onNotify?: (type: 'success' | 'error', text: string) => void;
}

function randomBase32Secret(length: number): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const random = crypto.getRandomValues(new Uint8Array(length));
  let out = '';
  for (const x of random) out += alphabet[x % alphabet.length];
  return out;
}

function buildOtpUri(email: string, secret: string): string {
  const issuer = 'NodeWarden';
  return `otpauth://totp/${encodeURIComponent(`${issuer}:${email}`)}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

export default function SettingsPage(props: SettingsPageProps) {
  const totpSecretStorageKey = `nodewarden.totp.secret.${props.profile.id}`;
  const [name, setName] = useState(props.profile.name || '');
  const [email, setEmail] = useState(props.profile.email || '');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newPassword2, setNewPassword2] = useState('');
  const [secret, setSecret] = useState(() => localStorage.getItem(totpSecretStorageKey) || randomBase32Secret(32));
  const [token, setToken] = useState('');
  const [totpLocked, setTotpLocked] = useState(props.totpEnabled);
  const [recoveryMasterPassword, setRecoveryMasterPassword] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');

  useEffect(() => {
    if (!props.totpEnabled) {
      setTotpLocked(false);
      return;
    }
    setTotpLocked(true);
  }, [props.totpEnabled]);

  const qrSvg = useMemo(() => {
    const qr = qrcode(0, 'M');
    qr.addData(buildOtpUri(email || props.profile.email, secret));
    qr.make();
    return qr.createSvgTag({ scalable: true, margin: 0 });
  }, [email, props.profile.email, secret]);

  async function enableTotp(): Promise<void> {
    await props.onEnableTotp(secret, token);
    localStorage.setItem(totpSecretStorageKey, secret);
    setTotpLocked(true);
  }

  async function loadRecoveryCode(): Promise<void> {
    const code = await props.onGetRecoveryCode(recoveryMasterPassword);
    setRecoveryCode(code);
    props.onNotify?.('success', 'Recovery code loaded');
  }

  return (
    <div className="stack">
      <section className="card">
        <h3>Profile</h3>
        <div className="field-grid">
          <label className="field">
            <span>Name</span>
            <input className="input" value={name} onInput={(e) => setName((e.currentTarget as HTMLInputElement).value)} />
          </label>
          <label className="field">
            <span>Email</span>
            <input
              className="input"
              type="email"
              value={email}
              onInput={(e) => setEmail((e.currentTarget as HTMLInputElement).value)}
            />
          </label>
        </div>
        <button type="button" className="btn btn-primary" onClick={() => void props.onSaveProfile(name, email)}>
          Save Profile
        </button>
      </section>

      <section className="card">
        <h3>Change Master Password</h3>
        <label className="field">
          <span>Current Password</span>
          <input
            className="input"
            type="password"
            value={currentPassword}
            onInput={(e) => setCurrentPassword((e.currentTarget as HTMLInputElement).value)}
          />
        </label>
        <div className="field-grid">
          <label className="field">
            <span>New Password</span>
            <input className="input" type="password" value={newPassword} onInput={(e) => setNewPassword((e.currentTarget as HTMLInputElement).value)} />
          </label>
          <label className="field">
            <span>Confirm Password</span>
            <input className="input" type="password" value={newPassword2} onInput={(e) => setNewPassword2((e.currentTarget as HTMLInputElement).value)} />
          </label>
        </div>
        <button
          type="button"
          className="btn btn-danger"
          onClick={() => void props.onChangePassword(currentPassword, newPassword, newPassword2)}
        >
          Change Password
        </button>
      </section>

      <section className="card">
        <div className="settings-twofactor-grid">
          <div className="settings-subcard">
            <h3>TOTP</h3>
            {totpLocked && <div className="status-ok">TOTP is enabled for this account.</div>}
            <div className="totp-grid">
              <div className="totp-qr" dangerouslySetInnerHTML={{ __html: qrSvg }} />
              <div>
                <div>
                  <label className="field">
                    <span>Authenticator Key</span>
                    <input className="input" value={secret} disabled={totpLocked} onInput={(e) => setSecret((e.currentTarget as HTMLInputElement).value.toUpperCase())} />
                  </label>
                  <label className="field">
                    <span>Verification Code</span>
                    <input className="input" value={token} disabled={totpLocked} onInput={(e) => setToken((e.currentTarget as HTMLInputElement).value)} />
                  </label>
                  <div className="actions">
                    <button type="button" className="btn btn-primary" disabled={totpLocked} onClick={() => void enableTotp()}>
                      <ShieldCheck size={14} className="btn-icon" />
                      {totpLocked ? 'Enabled' : 'Enable TOTP'}
                    </button>
                    <button type="button" className="btn btn-secondary" disabled={totpLocked} onClick={() => setSecret(randomBase32Secret(32))}>
                      <RefreshCw size={14} className="btn-icon" />
                      Regenerate
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary"
                      disabled={totpLocked}
                      onClick={() => {
                        void navigator.clipboard.writeText(secret);
                        props.onNotify?.('success', 'Secret copied');
                      }}
                    >
                      <Clipboard size={14} className="btn-icon" />
                      Copy Secret
                    </button>
                  </div>
                </div>
              </div>
            </div>
            <button type="button" className="btn btn-danger" disabled={!totpLocked} onClick={props.onOpenDisableTotp}>
              <ShieldOff size={14} className="btn-icon" />
              Disable TOTP
            </button>
          </div>

          <div className="settings-subcard">
            <h3>Recovery Code</h3>
            <p className="muted-inline" style={{ marginBottom: 8 }}>
              This is a one-time code. After it is used, a new code is generated automatically.
            </p>
            <label className="field">
              <span>Master Password</span>
              <input
                className="input"
                type="password"
                value={recoveryMasterPassword}
                onInput={(e) => setRecoveryMasterPassword((e.currentTarget as HTMLInputElement).value)}
              />
            </label>
            <div className="actions">
              <button type="button" className="btn btn-secondary" onClick={() => void loadRecoveryCode()}>
                View Recovery Code
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                disabled={!recoveryCode}
                onClick={() => {
                  void navigator.clipboard.writeText(recoveryCode);
                  props.onNotify?.('success', 'Recovery code copied');
                }}
              >
                Copy Code
              </button>
            </div>
            {recoveryCode && (
              <div className="card" style={{ marginTop: 10, marginBottom: 0 }}>
                <div style={{ fontWeight: 800, letterSpacing: '0.08em' }}>{recoveryCode}</div>
              </div>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}
