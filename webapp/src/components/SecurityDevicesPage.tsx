import { Clock3, RefreshCw, ShieldOff, Trash2 } from 'lucide-preact';
import type { AuthorizedDevice } from '@/lib/types';

interface SecurityDevicesPageProps {
  devices: AuthorizedDevice[];
  loading: boolean;
  onRefresh: () => void;
  onRevokeTrust: (device: AuthorizedDevice) => void;
  onRemoveDevice: (device: AuthorizedDevice) => void;
  onRevokeAll: () => void;
}

function formatDateTime(value: string | null | undefined): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

function mapDeviceTypeName(type: number): string {
  switch (type) {
    case 0: return 'Android';
    case 1: return 'iOS';
    case 2: return 'Chrome Extension';
    case 3: return 'Firefox Extension';
    case 4: return 'Opera Extension';
    case 5: return 'Edge Extension';
    case 6: return 'Windows Desktop';
    case 7: return 'macOS Desktop';
    case 8: return 'Linux Desktop';
    case 9: return 'Chrome Browser';
    case 10: return 'Firefox Browser';
    case 11: return 'Opera Browser';
    case 12: return 'Edge Browser';
    case 13: return 'IE Browser';
    case 14: return 'Web';
    default: return `Type ${type}`;
  }
}

export default function SecurityDevicesPage(props: SecurityDevicesPageProps) {
  return (
    <div className="stack">
      <section className="card">
        <div className="section-head">
          <div>
            <h3 style={{ margin: 0 }}>Account Security</h3>
            <div className="muted-inline" style={{ marginTop: 4 }}>
              Manage authorized devices and 30-day TOTP trusted sessions.
            </div>
          </div>
          <div className="actions">
            <button type="button" className="btn btn-secondary small" onClick={props.onRefresh}>
              <RefreshCw size={14} className="btn-icon" />
              Refresh
            </button>
            <button type="button" className="btn btn-danger small" onClick={props.onRevokeAll}>
              <ShieldOff size={14} className="btn-icon" />
              Revoke All Trusted
            </button>
          </div>
        </div>
      </section>

      <section className="card">
        <h3 style={{ marginTop: 0 }}>Authorized Devices</h3>
        <table className="table">
          <thead>
            <tr>
              <th>Device</th>
              <th>Type</th>
              <th>Added</th>
              <th>Last Seen</th>
              <th>Trusted Until</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {props.devices.map((device) => (
              <tr key={device.identifier}>
                <td>
                  <div>{device.name || 'Unknown device'}</div>
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
                    <span className="muted-inline">Not trusted</span>
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
                      Revoke Trust
                    </button>
                    <button type="button" className="btn btn-danger small" onClick={() => props.onRemoveDevice(device)}>
                      <Trash2 size={14} className="btn-icon" />
                      Remove Device
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {!props.loading && props.devices.length === 0 && (
              <tr>
                <td colSpan={6}>
                  <div className="empty" style={{ minHeight: 80 }}>No devices found.</div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>
    </div>
  );
}
