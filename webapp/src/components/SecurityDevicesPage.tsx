import { Clock3, RefreshCw, ShieldOff, Trash2 } from 'lucide-preact';
import type { AuthorizedDevice } from '@/lib/types';
import { t } from '@/lib/i18n';

interface SecurityDevicesPageProps {
  devices: AuthorizedDevice[];
  loading: boolean;
  onRefresh: () => void;
  onRevokeTrust: (device: AuthorizedDevice) => void;
  onRemoveDevice: (device: AuthorizedDevice) => void;
  onRevokeAll: () => void;
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
  return (
    <div className="stack">
      <section className="card">
        <div className="section-head">
          <div>
            <h3 style={{ margin: 0 }}>{t('txt_device_management')}</h3>
            <div className="muted-inline" style={{ marginTop: 4 }}>
              {t('txt_manage_authorized_devices_and_30_day_totp_trusted_sessions')}
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
          </div>
        </div>
      </section>

      <section className="card">
        <h3 style={{ marginTop: 0 }}>{t('txt_authorized_devices')}</h3>
        <table className="table">
          <thead>
            <tr>
              <th>{t('txt_device')}</th>
              <th>{t('txt_type')}</th>
              <th>{t('txt_added')}</th>
              <th>{t('txt_last_seen')}</th>
              <th>{t('txt_trusted_until')}</th>
              <th>{t('txt_actions')}</th>
            </tr>
          </thead>
          <tbody>
            {props.devices.map((device) => (
              <tr key={device.identifier}>
                <td>
                  <div>{device.name || t('txt_unknown_device')}</div>
                  <div className="muted-inline">{device.identifier}</div>
                </td>
                <td>{mapDeviceTypeName(device.type)}</td>
                <td>{formatDateTime(device.creationDate)}</td>
                <td>{formatDateTime(device.revisionDate)}</td>
                <td>
                  {device.trusted ? (
                    <div className="trusted-cell">
                      <Clock3 size={13} />
                      <span>{formatDateTime(device.trustedUntil)}</span>
                    </div>
                  ) : (
                    <span className="muted-inline">{t('txt_not_trusted')}</span>
                  )}
                </td>
                <td>
                  <div className="actions">
                    <button
                      type="button"
                      className="btn btn-secondary small"
                      disabled={!device.trusted}
                      onClick={() => props.onRevokeTrust(device)}
                    >
                      <ShieldOff size={14} className="btn-icon" />
                      {t('txt_revoke_trust')}
                    </button>
                    <button type="button" className="btn btn-danger small" onClick={() => props.onRemoveDevice(device)}>
                      <Trash2 size={14} className="btn-icon" />
                      {t('txt_remove_device_2')}
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {!props.loading && props.devices.length === 0 && (
              <tr>
                <td colSpan={6}>
                  <div className="empty" style={{ minHeight: 80 }}>{t('txt_no_devices_found')}</div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>
    </div>
  );
}
