import { useEffect, useMemo, useState } from 'preact/hooks';
import { Clipboard, KeyRound, RefreshCw, Save, ShieldCheck, ShieldOff } from 'lucide-preact';
import qrcode from 'qrcode-generator';
import type { Profile } from '@/lib/types';
import { t } from '@/lib/i18n';

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
    props.onNotify?.('success', t('txt_recovery_code_loaded'));
  }

  return (
    <div className="stack">
      <section className="card">
        <h3>{t('txt_profile')}</h3>
        <div className="field-grid">
          <label className="field">
            <span>{t('txt_name')}</span>
            <input className="input" value={name} onInput={(e) => setName((e.currentTarget as HTMLInputElement).value)} />
          </label>
          <label className="field">
            <span>{t('txt_email')}</span>
            <input
              className="input"
              type="email"
              value={email}
              onInput={(e) => setEmail((e.currentTarget as HTMLInputElement).value)}
            />
          </label>
        </div>
        <button type="button" className="btn btn-primary" onClick={() => void props.onSaveProfile(name, email)}>
          <Save size={14} className="btn-icon" />
          {t('txt_save_profile')}
        </button>
      </section>

      <section className="card">
        <h3>{t('txt_change_master_password')}</h3>
        <label className="field">
          <span>{t('txt_current_password')}</span>
          <input
            className="input"
            type="password"
            value={currentPassword}
            onInput={(e) => setCurrentPassword((e.currentTarget as HTMLInputElement).value)}
          />
        </label>
        <div className="field-grid">
          <label className="field">
            <span>{t('txt_new_password')}</span>
            <input className="input" type="password" value={newPassword} onInput={(e) => setNewPassword((e.currentTarget as HTMLInputElement).value)} />
          </label>
          <label className="field">
            <span>{t('txt_confirm_password')}</span>
            <input className="input" type="password" value={newPassword2} onInput={(e) => setNewPassword2((e.currentTarget as HTMLInputElement).value)} />
          </label>
        </div>
        <button
          type="button"
          className="btn btn-danger"
          onClick={() => void props.onChangePassword(currentPassword, newPassword, newPassword2)}
        >
          <KeyRound size={14} className="btn-icon" />
          {t('txt_change_password')}
        </button>
      </section>

      <section className="card">
        <div className="settings-twofactor-grid">
          <div className="settings-subcard">
            <h3>{t('txt_totp')}</h3>
            {totpLocked && <div className="status-ok">{t('txt_totp_is_enabled_for_this_account')}</div>}
            <div className="totp-grid">
              <div className="totp-qr" dangerouslySetInnerHTML={{ __html: qrSvg }} />
              <div>
                <div>
                  <label className="field">
                    <span>{t('txt_authenticator_key')}</span>
                    <input className="input" value={secret} disabled={totpLocked} onInput={(e) => setSecret((e.currentTarget as HTMLInputElement).value.toUpperCase())} />
                  </label>
                  <label className="field">
                    <span>{t('txt_verification_code')}</span>
                    <input className="input" value={token} disabled={totpLocked} onInput={(e) => setToken((e.currentTarget as HTMLInputElement).value)} />
                  </label>
                  <div className="actions">
                    <button type="button" className="btn btn-primary" disabled={totpLocked} onClick={() => void enableTotp()}>
                      <ShieldCheck size={14} className="btn-icon" />
                      {totpLocked ? t('txt_enabled') : t('txt_enable_totp')}
                    </button>
                    <button type="button" className="btn btn-secondary" disabled={totpLocked} onClick={() => setSecret(randomBase32Secret(32))}>
                      <RefreshCw size={14} className="btn-icon" />
                      {t('txt_regenerate')}
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary"
                      disabled={totpLocked}
                      onClick={() => {
                        void navigator.clipboard.writeText(secret);
                        props.onNotify?.('success', t('txt_secret_copied'));
                      }}
                    >
                      <Clipboard size={14} className="btn-icon" />
                      {t('txt_copy_secret')}
                    </button>
                  </div>
                </div>
              </div>
            </div>
            <button type="button" className="btn btn-danger" disabled={!totpLocked} onClick={props.onOpenDisableTotp}>
              <ShieldOff size={14} className="btn-icon" />
              {t('txt_disable_totp')}
            </button>
          </div>

          <div className="settings-subcard">
            <h3>{t('txt_recovery_code')}</h3>
            <p className="muted-inline" style={{ marginBottom: 8 }}>
              {t('txt_this_is_a_one_time_code_after_it_is_used_a_new_code_is_generated_automatically')}
            </p>
            <label className="field">
              <span>{t('txt_master_password')}</span>
              <input
                className="input"
                type="password"
                value={recoveryMasterPassword}
                onInput={(e) => setRecoveryMasterPassword((e.currentTarget as HTMLInputElement).value)}
              />
            </label>
            <div className="actions">
              <button type="button" className="btn btn-secondary" onClick={() => void loadRecoveryCode()}>
                <ShieldCheck size={14} className="btn-icon" />
                {t('txt_view_recovery_code')}
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                disabled={!recoveryCode}
                onClick={() => {
                  void navigator.clipboard.writeText(recoveryCode);
                  props.onNotify?.('success', t('txt_recovery_code_copied'));
                }}
              >
                {t('txt_copy_code')}
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
