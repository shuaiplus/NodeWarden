import { useMemo, useState } from 'preact/hooks';
import qrcode from 'qrcode-generator';
import type { Profile } from '@/lib/types';

interface SettingsPageProps {
  profile: Profile;
  onSaveProfile: (name: string, email: string) => Promise<void>;
  onChangePassword: (currentPassword: string, nextPassword: string, nextPassword2: string) => Promise<void>;
  onEnableTotp: (secret: string, token: string) => Promise<void>;
  onOpenDisableTotp: () => void;
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
  const [name, setName] = useState(props.profile.name || '');
  const [email, setEmail] = useState(props.profile.email || '');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newPassword2, setNewPassword2] = useState('');
  const [secret, setSecret] = useState(randomBase32Secret(32));
  const [token, setToken] = useState('');

  const qrSvg = useMemo(() => {
    const qr = qrcode(0, 'M');
    qr.addData(buildOtpUri(email || props.profile.email, secret));
    qr.make();
    return qr.createSvgTag({ scalable: true, margin: 0 });
  }, [email, props.profile.email, secret]);

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
        <h3>TOTP</h3>
        <div className="totp-grid">
          <div className="totp-qr" dangerouslySetInnerHTML={{ __html: qrSvg }} />
          <div>
            <label className="field">
              <span>Authenticator Key</span>
              <input className="input" value={secret} onInput={(e) => setSecret((e.currentTarget as HTMLInputElement).value.toUpperCase())} />
            </label>
            <label className="field">
              <span>Verification Code</span>
              <input className="input" value={token} onInput={(e) => setToken((e.currentTarget as HTMLInputElement).value)} />
            </label>
            <div className="actions">
              <button type="button" className="btn btn-primary" onClick={() => void props.onEnableTotp(secret, token)}>
                Enable TOTP
              </button>
              <button type="button" className="btn btn-secondary" onClick={() => setSecret(randomBase32Secret(32))}>
                Regenerate
              </button>
              <button type="button" className="btn btn-secondary" onClick={() => navigator.clipboard.writeText(secret)}>
                Copy Secret
              </button>
            </div>
          </div>
        </div>
        <button type="button" className="btn btn-danger" onClick={props.onOpenDisableTotp}>
          Disable TOTP
        </button>
      </section>
    </div>
  );
}
