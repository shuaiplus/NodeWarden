import { useEffect, useState } from 'preact/hooks';
import { Download, Eye, Lock } from 'lucide-preact';
import { accessPublicSend, accessPublicSendFile, decryptPublicSend, decryptPublicSendFileBytes } from '@/lib/api/send';
import { toBufferSource } from '@/lib/crypto';
import { downloadBytesAsFile, readResponseBytesWithProgress } from '@/lib/download';
import StandalonePageFrame from '@/components/StandalonePageFrame';
import { t } from '@/lib/i18n';

interface PublicSendPageProps {
  accessId: string;
  keyPart: string | null;
}

export default function PublicSendPage(props: PublicSendPageProps) {
  const [loading, setLoading] = useState(true);
  const [password, setPassword] = useState('');
  const [needPassword, setNeedPassword] = useState(false);
  const [error, setError] = useState('');
  const [sendData, setSendData] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [downloadPercent, setDownloadPercent] = useState<number | null>(null);

  async function loadSend(pass?: string): Promise<void> {
    setBusy(true);
    setError('');
    try {
      const data = await accessPublicSend(props.accessId, props.keyPart, pass);
      if (!props.keyPart) {
        setError(t('txt_this_link_is_missing_decryption_key'));
        setSendData(null);
        return;
      }
      const decrypted = await decryptPublicSend(data, props.keyPart);
      setSendData(decrypted);
      setNeedPassword(false);
    } catch (e) {
      const err = e as Error & { status?: number };
      if (err.status === 401) {
        setNeedPassword(true);
        setError(t('txt_this_send_is_password_protected'));
      } else {
        setError(err.message || t('txt_failed_to_open_send'));
      }
      setSendData(null);
    } finally {
      setBusy(false);
      setLoading(false);
    }
  }

  async function downloadFile(): Promise<void> {
    if (!sendData?.id || !sendData?.file?.id) return;
    setBusy(true);
    setDownloadPercent(null);
    setError('');
    try {
      const url = await accessPublicSendFile(sendData.id, sendData.file.id, props.keyPart, password || undefined);
      const resp = await fetch(url);
      if (!resp.ok) throw new Error(t('txt_download_failed'));
      const encryptedBytes = await readResponseBytesWithProgress(resp, (progress) => setDownloadPercent(progress.percent));
      let blob: Blob;
      if (props.keyPart) {
        try {
          const decryptedBytes = await decryptPublicSendFileBytes(encryptedBytes, props.keyPart);
          blob = new Blob([toBufferSource(decryptedBytes)], { type: 'application/octet-stream' });
        } catch {
          // Legacy compatibility: early web-created file sends uploaded plaintext bytes.
          blob = new Blob([toBufferSource(encryptedBytes)], { type: 'application/octet-stream' });
        }
      } else {
        blob = new Blob([toBufferSource(encryptedBytes)], { type: 'application/octet-stream' });
      }
      downloadBytesAsFile(
        new Uint8Array(await blob.arrayBuffer()),
        sendData.decFileName || sendData.file?.fileName || t('txt_send_file'),
        'application/octet-stream'
      );
    } catch (e) {
      const err = e as Error;
      setError(err.message || t('txt_download_failed'));
    } finally {
      setBusy(false);
      setDownloadPercent(null);
    }
  }

  useEffect(() => {
    void loadSend();
  }, [props.accessId, props.keyPart]);

  return (
    <div className="auth-page public-send-page">
      <StandalonePageFrame title={t('txt_nodewarden_send')}>
        {loading && <p className="muted">{t('txt_loading')}</p>}

        {!loading && needPassword && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void loadSend(password);
            }}
          >
            <label className="field">
              <span>{t('txt_password')}</span>
              <div className="password-wrap">
                <input
                  className="input"
                  type="password"
                  value={password}
                  autoComplete="current-password"
                  onInput={(e) => setPassword((e.currentTarget as HTMLInputElement).value)}
                />
              </div>
            </label>
            <button type="submit" className="btn btn-primary full" disabled={busy}>
              <Lock size={14} className="btn-icon" /> {t('txt_unlock_send')}
            </button>
          </form>
        )}

        {!loading && sendData && (
          <>
            <h2 style={{ marginTop: '8px' }}>{sendData.decName || t('txt_no_name')}</h2>
            {sendData.type === 0 ? (
              <div className="card" style={{ marginTop: '10px' }}>
                <div className="notes">{sendData.decText || ''}</div>
              </div>
            ) : (
              <div className="card" style={{ marginTop: '10px' }}>
                <div className="kv-line">
                  <span>{t('txt_file')}</span>
                  <strong>{sendData.decFileName || sendData.file?.fileName || sendData.file?.sizeName || t('txt_encrypted_file')}</strong>
                </div>
                <button type="button" className="btn btn-primary full" disabled={busy} onClick={() => void downloadFile()}>
                  <Download size={14} className="btn-icon" /> {downloadPercent == null ? (busy ? t('txt_downloading') : t('txt_download')) : t('txt_downloading_percent', { percent: downloadPercent })}
                </button>
              </div>
            )}
            {!!sendData.expirationDate && <p className="muted">{t('txt_expires_at_value', { value: sendData.expirationDate })}</p>}
          </>
        )}

        {!loading && !sendData && !needPassword && !error && (
          <p className="muted">
            <Eye size={14} style={{ verticalAlign: 'text-bottom' }} /> {t('txt_send_unavailable')}
          </p>
        )}
        {!!error && <p className="local-error">{error}</p>}
      </StandalonePageFrame>
    </div>
  );
}
