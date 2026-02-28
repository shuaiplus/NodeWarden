import { useEffect, useState } from 'preact/hooks';
import { Download, Eye, Lock } from 'lucide-preact';
import { accessPublicSend, accessPublicSendFile, decryptPublicSend } from '@/lib/api';

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

  async function loadSend(pass?: string): Promise<void> {
    setBusy(true);
    setError('');
    try {
      const data = await accessPublicSend(props.accessId, pass);
      if (!props.keyPart) {
        setError('This link is missing decryption key.');
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
        setError('This send is password protected.');
      } else {
        setError(err.message || 'Failed to open send');
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
    setError('');
    try {
      const url = await accessPublicSendFile(sendData.id, sendData.file.id, password || undefined);
      const resp = await fetch(url);
      if (!resp.ok) throw new Error('Download failed');
      const blob = await resp.blob();
      const obj = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = obj;
      a.download = sendData.decFileName || sendData.file?.fileName || 'send-file';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(obj);
    } catch (e) {
      const err = e as Error;
      setError(err.message || 'Download failed');
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    void loadSend();
  }, [props.accessId, props.keyPart]);

  return (
    <div className="auth-page public-send-page">
      <div className="auth-card">
        <h1>NodeWarden Send</h1>
        {loading && <p className="muted">Loading...</p>}

        {!loading && needPassword && (
          <>
            <label className="field">
              <span>Password</span>
              <div className="password-wrap">
                <input
                  className="input"
                  type="password"
                  value={password}
                  onInput={(e) => setPassword((e.currentTarget as HTMLInputElement).value)}
                />
              </div>
            </label>
            <button type="button" className="btn btn-primary full" disabled={busy} onClick={() => void loadSend(password)}>
              <Lock size={14} className="btn-icon" /> Unlock Send
            </button>
          </>
        )}

        {!loading && sendData && (
          <>
            <h2 style={{ marginTop: '8px' }}>{sendData.decName || '(No Name)'}</h2>
            {sendData.type === 0 ? (
              <div className="card" style={{ marginTop: '10px' }}>
                <div className="notes">{sendData.decText || ''}</div>
              </div>
            ) : (
              <div className="card" style={{ marginTop: '10px' }}>
                <div className="kv-line">
                  <span>File</span>
                  <strong>{sendData.decFileName || sendData.file?.fileName || sendData.file?.sizeName || 'Encrypted File'}</strong>
                </div>
                <button type="button" className="btn btn-primary full" disabled={busy} onClick={() => void downloadFile()}>
                  <Download size={14} className="btn-icon" /> Download
                </button>
              </div>
            )}
            {!!sendData.expirationDate && <p className="muted">Expires at: {sendData.expirationDate}</p>}
          </>
        )}

        {!loading && !sendData && !needPassword && !error && (
          <p className="muted">
            <Eye size={14} style={{ verticalAlign: 'text-bottom' }} /> Send unavailable.
          </p>
        )}
        {!!error && <p className="local-error">{error}</p>}
      </div>
    </div>
  );
}
