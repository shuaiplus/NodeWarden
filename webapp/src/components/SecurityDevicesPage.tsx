import { useState } from 'preact/hooks';
import { Clock3, Pencil, RefreshCw, ShieldOff, Trash2 } from 'lucide-preact';
import ConfirmDialog from '@/components/ConfirmDialog';
import type { AuthorizedDevice } from '@/lib/types';
import { t } from '@/lib/i18n';

interface SecurityDevicesPageProps {
  devices: AuthorizedDevice[];
  loading: boolean;
  onRefresh: () => void;
  onRenameDevice: (device: AuthorizedDevice, name: string) => Promise<void>;
  onRevokeTrust: (device: AuthorizedDevice) => void;
  onRemoveDevice: (device: AuthorizedDevice) => void;
  onRevokeAll: () => void;
  onRemoveAll: () => void;
}

function formatDateTime(value: string | null | undefined): string {
  if (!value) return t('txt_dash');
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return t('txt_dash');
  return date.toLocaleString();
}

function mapDeviceTypeName(type: number): string {
  switch (type) {
    case 0: return t('txt_android');
    case 1: return t('txt_ios');
    case 2: return t('txt_chrome_extension');
    case 3: return t('txt_firefox_extension');
    case 4: return t('txt_opera_extension');
    case 5: return t('txt_edge_extension');
    case 6: return t('txt_windows_desktop');
    case 7: return t('txt_macos_desktop');
    case 8: return t('txt_linux_desktop');
    case 9: return t('txt_chrome_browser');
    case 10: return t('txt_firefox_browser');
    case 11: return t('txt_opera_browser');
    case 12: return t('txt_edge_browser');
    case 13: return t('txt_ie_browser');
    case 14: return t('txt_web');
    default: return t('txt_type_type', { type });
  }
}

export default function SecurityDevicesPage(props: SecurityDevicesPageProps) {
  const [editingDevice, setEditingDevice] = useState<AuthorizedDevice | null>(null);
  const [deviceNote, setDeviceNote] = useState('');
  const [savingNote, setSavingNote] = useState(false);

  async function handleSaveDeviceNote(): Promise<void> {
    if (!editingDevice || savingNote) return;
    setSavingNote(true);
    try {
      await props.onRenameDevice(editingDevice, deviceNote);
      setEditingDevice(null);
      setDeviceNote('');
    } finally {
      setSavingNote(false);
    }
  }

  return (
    <>
      <div className="stack">
        <section className="card">
        <div className="section-head">
          <div>
            <h3 className="flush-title">{t('txt_device_management')}</h3>
            <div className="muted-inline section-note">
              {t('txt_manage_device_sessions_and_30_day_totp_trusted_sessions')}
            </div>
          </div>
          <div className="actions">
            <button type="button" className="btn btn-secondary small" onClick={props.onRefresh}>
              <RefreshCw size={14} className="btn-icon" />
              {t('txt_refresh')}
            </button>
            <button type="button" className="btn btn-danger small" onClick={props.onRevokeAll}>
              <ShieldOff size={14} className="btn-icon" />
              {t('txt_revoke_all_trusted')}
            </button>
            <button type="button" className="btn btn-danger small" onClick={props.onRemoveAll}>
              <Trash2 size={14} className="btn-icon" />
              {t('txt_remove_all_devices')}
            </button>
          </div>
        </div>
        </section>

        <section className="card">
        <h3 className="section-title-flush">{t('txt_authorized_devices')}</h3>
        <table className="table">
          <thead>
            <tr>
              <th>{t('txt_device')}</th>
              <th>{t('txt_type')}</th>
              <th>{t('txt_status')}</th>
              <th>{t('txt_added')}</th>
              <th>{t('txt_last_seen')}</th>
              <th>{t('txt_trusted_until')}</th>
              <th>{t('txt_actions')}</th>
            </tr>
          </thead>
          <tbody>
            {props.devices.map((device) => (
              <tr key={device.identifier}>
                <td data-label={t('txt_device')}>
                  <div>{device.name || t('txt_unknown_device')}</div>
                  {!!device.deviceNote && !!device.systemName && device.systemName !== device.name && (
                    <div className="muted-inline">{device.systemName}</div>
                  )}
                  <div className="muted-inline">{device.identifier}</div>
                </td>
                <td data-label={t('txt_type')}>{mapDeviceTypeName(device.type)}</td>
                <td data-label={t('txt_status')}>
                  <span className={`device-status-pill ${device.online ? 'online' : 'offline'}`}>
                    {device.online ? t('txt_online') : t('txt_offline')}
                  </span>
                </td>
                <td data-label={t('txt_added')}>{formatDateTime(device.creationDate)}</td>
                <td data-label={t('txt_last_seen')}>{formatDateTime(device.lastSeenAt || device.revisionDate)}</td>
                <td data-label={t('txt_trusted_until')}>
                  {device.trusted ? (
                    <div className="trusted-cell">
                      <Clock3 size={13} />
                      <span>{formatDateTime(device.trustedUntil)}</span>
                    </div>
                  ) : (
                    <span className="muted-inline">{t('txt_not_trusted')}</span>
                  )}
                </td>
                <td data-label={t('txt_actions')}>
                  <div className="actions">
                    <button
                      type="button"
                      className="btn btn-secondary small"
                      disabled={!device.trusted}
                      onClick={() => props.onRevokeTrust(device)}
                    >
                      <ShieldOff size={14} className="btn-icon" />
                      {t('txt_untrust')}
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary small"
                      disabled={device.hasStoredDevice === false}
                      onClick={() => {
                        setEditingDevice(device);
                        setDeviceNote(device.deviceNote || device.name || '');
                      }}
                    >
                      <Pencil size={14} className="btn-icon" />
                      {t('txt_device_note')}
                    </button>
                    <button
                      type="button"
                      className="btn btn-danger small"
                      disabled={device.hasStoredDevice === false}
                      onClick={() => props.onRemoveDevice(device)}
                    >
                      <Trash2 size={14} className="btn-icon" />
                      {t('txt_delete')}
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {!props.loading && props.devices.length === 0 && (
              <tr>
                <td colSpan={7}>
                  <div className="empty empty-comfortable">{t('txt_no_devices_found')}</div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
        </section>
      </div>

      <ConfirmDialog
        open={!!editingDevice}
        title={t('txt_device_note')}
        message={t('txt_replace_device_name_with_note')}
        confirmText={t('txt_save')}
        cancelText={t('txt_cancel')}
        showIcon={false}
        confirmDisabled={savingNote}
        cancelDisabled={savingNote}
        onConfirm={() => void handleSaveDeviceNote()}
        onCancel={() => {
          if (savingNote) return;
          setEditingDevice(null);
          setDeviceNote('');
        }}
      >
        <label className="field">
          <span>{t('txt_device_note')}</span>
          <input
            className="input"
            maxLength={128}
            value={deviceNote}
            onInput={(e) => setDeviceNote((e.currentTarget as HTMLInputElement).value)}
          />
        </label>
      </ConfirmDialog>
    </>
  );
}
