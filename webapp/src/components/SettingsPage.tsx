import { useEffect, useMemo, useState } from 'preact/hooks';
import { Clipboard, KeyRound, RefreshCw, ShieldCheck, ShieldOff } from 'lucide-preact';
import { copyTextToClipboard } from '@/lib/clipboard';
import qrcode from 'qrcode-generator';
import type { Profile } from '@/lib/types';
import { t } from '@/lib/i18n';
import ConfirmDialog from '@/components/ConfirmDialog';

interface SettingsPageProps {
  profile: Profile;
  totpEnabled: boolean;
  onChangePassword: (currentPassword: string, nextPassword: string, nextPassword2: string) => Promise<void>;
  onSavePasswordHint: (masterPasswordHint: string) => Promise<void>;
  onEnableTotp: (secret: string, token: string) => Promise<void>;
  onOpenDisableTotp: () => void;
  onGetRecoveryCode: (masterPassword: string) => Promise<string>;
  onNotify?: (type: 'success' | 'error', text: string) => void;
  passkeys: Array<{ id: string; name: string; creationDate: string; lastUsedDate: string | null }>;
  onCreatePasskey: (name: string) => Promise<void>;
  onRenamePasskey: (id: string, name: string) => Promise<void>;
  onDeletePasskey: (id: string) => Promise<void>;
}

function randomBase32Secret(length: number): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let out = '';
  const maxUnbiasedByte = Math.floor(256 / alphabet.length) * alphabet.length;
  while (out.length < length) {
    const random = crypto.getRandomValues(new Uint8Array(length));
    for (const x of random) {
      if (x >= maxUnbiasedByte) continue;
      out += alphabet[x % alphabet.length];
      if (out.length >= length) break;
    }
  }
  return out;
}

function buildOtpUri(email: string, secret: string): string {
  const issuer = 'NodeWarden';
  return `otpauth://totp/${encodeURIComponent(`${issuer}:${email}`)}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

export default function SettingsPage(props: SettingsPageProps) {
  const totpSecretStorageKey = `nodewarden.totp.secret.${props.profile.id}`;
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newPassword2, setNewPassword2] = useState('');
  const [passwordHint, setPasswordHint] = useState(props.profile.masterPasswordHint || '');
  const [secret, setSecret] = useState(() => localStorage.getItem(totpSecretStorageKey) || randomBase32Secret(32));
  const [token, setToken] = useState('');
  const [totpLocked, setTotpLocked] = useState(props.totpEnabled);
  const [recoveryMasterPassword, setRecoveryMasterPassword] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [passkeyName, setPasskeyName] = useState('');
  const [renamePasskey, setRenamePasskey] = useState<{ id: string; name: string } | null>(null);
  const [renamePasskeyName, setRenamePasskeyName] = useState('');
  const [deletePasskey, setDeletePasskey] = useState<{ id: string; name: string } | null>(null);

  useEffect(() => {
    if (!props.totpEnabled) {
      setTotpLocked(false);
      return;
    }
    setTotpLocked(true);
  }, [props.totpEnabled]);

  useEffect(() => {
    setPasswordHint(props.profile.masterPasswordHint || '');
  }, [props.profile.masterPasswordHint]);

  const qrDataUrl = useMemo(() => {
    const qr = qrcode(0, 'M');
    qr.addData(buildOtpUri(props.profile.email, secret));
    qr.make();
    // Keep a visible quiet zone so authenticator apps can scan reliably in both themes.
    const svg = qr.createSvgTag({ scalable: true, margin: 4 });
    return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
  }, [props.profile.email, secret]);

  async function enableTotp(): Promise<void> {
    try {
      await props.onEnableTotp(secret, token);
      // Secret is now stored on the server; remove plaintext copy from localStorage.
      localStorage.removeItem(totpSecretStorageKey);
      setTotpLocked(true);
    } catch {
      // Keep inputs editable after a failed attempt.
    }
  }

  async function loadRecoveryCode(): Promise<void> {
    const code = await props.onGetRecoveryCode(recoveryMasterPassword);
    setRecoveryCode(code);
    props.onNotify?.('success', t('txt_recovery_code_loaded'));
  }

  function formatDateTime(value: string | null | undefined): string {
    if (!value) return t('txt_dash');
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return value;
    return parsed.toLocaleString();
  }

  async function confirmRenamePasskey(): Promise<void> {
    if (!renamePasskey) return;
    const nextName = renamePasskeyName.trim();
    if (!nextName) return;
    await props.onRenamePasskey(renamePasskey.id, nextName);
    setRenamePasskey(null);
    setRenamePasskeyName('');
  }

  async function confirmDeletePasskey(): Promise<void> {
    if (!deletePasskey) return;
    await props.onDeletePasskey(deletePasskey.id);
    setDeletePasskey(null);
  }

  return (
    <div className="stack">
      <section className="card">
        <h3>{t('txt_profile')}</h3>
        <label className="field">
          <span>{t('txt_password_hint_optional')}</span>
          <input
            className="input"
            maxLength={120}
            value={passwordHint}
            placeholder={t('txt_password_hint_placeholder')}
            onInput={(e) => setPasswordHint((e.currentTarget as HTMLInputElement).value)}
          />
          <div className="field-help">{t('txt_password_hint_register_help')}</div>
        </label>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => void props.onSavePasswordHint(passwordHint)}
        >
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
        <h3>Passkey</h3>
        <div className="field-grid">
          <label className="field">
            <span>名称</span>
            <input className="input" value={passkeyName} onInput={(e) => setPasskeyName((e.currentTarget as HTMLInputElement).value)} placeholder="例如：MacBook Touch ID" />
          </label>
          <div className="field" style={{ alignSelf: 'end' }}>
            <button type="button" className="btn btn-primary" disabled={!passkeyName.trim()} onClick={() => void props.onCreatePasskey(passkeyName.trim()).then(() => setPasskeyName(''))}>
              创建 Passkey
            </button>
          </div>
        </div>
        <p className="muted-inline" style={{ marginBottom: 8 }}>最多 5 个，支持重命名和删除。</p>
        <div className="stack" style={{ gap: 6 }}>
          {props.passkeys.map((item) => (
            <div
              key={item.id}
              style={{
                display: 'flex',
                gap: 8,
                alignItems: 'center',
                border: '1px solid var(--line)',
                borderRadius: 10,
                padding: '10px 12px',
                flexWrap: 'wrap',
              }}
            >
              <strong>{item.name}</strong>
              <span style={{ marginLeft: 'auto', fontSize: 12, opacity: 0.72 }}>
                创建于 {formatDateTime(item.creationDate)}
              </span>
              <button
                type="button"
                className="btn btn-secondary small"
                onClick={() => {
                  setRenamePasskey({ id: item.id, name: item.name });
                  setRenamePasskeyName(item.name);
                }}
              >
                {t('txt_edit')}
              </button>
              <button
                type="button"
                className="btn btn-danger small"
                onClick={() => setDeletePasskey({ id: item.id, name: item.name })}
              >
                删除
              </button>
            </div>
          ))}
          {!props.passkeys.length && <div className="empty">暂无 Passkey</div>}
        </div>
      </section>

      <ConfirmDialog
        open={!!renamePasskey}
        title={t('txt_edit')}
        message={t('txt_enter_a_folder_name')}
        confirmText={t('txt_save')}
        cancelText={t('txt_cancel')}
        onConfirm={() => void confirmRenamePasskey()}
        onCancel={() => {
          setRenamePasskey(null);
          setRenamePasskeyName('');
        }}
      >
        <label className="field">
          <span>{t('txt_name')}</span>
          <input className="input" value={renamePasskeyName} onInput={(e) => setRenamePasskeyName((e.currentTarget as HTMLInputElement).value)} />
        </label>
      </ConfirmDialog>

      <ConfirmDialog
        open={!!deletePasskey}
        title={t('txt_delete')}
        message={deletePasskey ? `确认删除 Passkey「${deletePasskey.name}」吗？` : ''}
        variant="warning"
        danger
        confirmText={t('txt_delete')}
        cancelText={t('txt_cancel')}
        onConfirm={() => void confirmDeletePasskey()}
        onCancel={() => setDeletePasskey(null)}
      />

      <section className="card">
        <div className="settings-twofactor-grid">
          <div className="settings-subcard">
            <h3>{t('txt_totp')}</h3>
            {totpLocked && <div className="status-ok">{t('txt_totp_is_enabled_for_this_account')}</div>}
            <div className="totp-grid">
              <div className="totp-qr">
                <img src={qrDataUrl} alt="TOTP QR" />
              </div>
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
                        void copyTextToClipboard(secret, { successMessage: t('txt_secret_copied') });
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
                  void copyTextToClipboard(recoveryCode, { successMessage: t('txt_recovery_code_copied') });
                }}
              >
                <Clipboard size={14} className="btn-icon" />
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
