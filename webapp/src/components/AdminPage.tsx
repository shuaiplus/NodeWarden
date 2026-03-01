import { useState } from 'preact/hooks';
import { ChevronLeft, ChevronRight, Clipboard, Plus, RefreshCw, Trash2, UserCheck, UserX } from 'lucide-preact';
import type { AdminInvite, AdminUser } from '@/lib/types';
import { t } from '@/lib/i18n';

interface AdminPageProps {
  currentUserId: string;
  users: AdminUser[];
  invites: AdminInvite[];
  onRefresh: () => void;
  onCreateInvite: (hours: number) => Promise<void>;
  onDeleteAllInvites: () => Promise<void>;
  onToggleUserStatus: (userId: string, currentStatus: string) => Promise<void>;
  onDeleteUser: (userId: string) => Promise<void>;
  onRevokeInvite: (code: string) => Promise<void>;
}

export default function AdminPage(props: AdminPageProps) {
  const [inviteHours, setInviteHours] = useState(168);
  const [page, setPage] = useState(1);
  const pageSize = 20;
  const formatExpiresAt = (x?: string) => (x ? new Date(x).toLocaleString() : t('txt_dash'));
  const totalPages = Math.max(1, Math.ceil(props.invites.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const pagedInvites = props.invites.slice((safePage - 1) * pageSize, safePage * pageSize);

  const roleText = (role: string) => {
    const normalized = String(role || '').toLowerCase();
    if (normalized === 'admin') return t('txt_role_admin');
    if (normalized === 'user') return t('txt_role_user');
    return role || '-';
  };

  const statusText = (status: string) => {
    const normalized = String(status || '').toLowerCase();
    if (normalized === 'active') return t('txt_status_active');
    if (normalized === 'banned') return t('txt_status_banned');
    if (normalized === 'inactive') return t('txt_status_inactive');
    return status || '-';
  };

  return (
    <div className="stack">
      <section className="card">
        <h3>{t('txt_users')}</h3>
        <table className="table">
          <thead>
            <tr>
              <th>{t('txt_email')}</th>
              <th>{t('txt_name')}</th>
              <th>{t('txt_role')}</th>
              <th>{t('txt_status')}</th>
              <th>{t('txt_actions')}</th>
            </tr>
          </thead>
          <tbody>
            {props.users.map((user) => (
              <tr key={user.id}>
                <td>{user.email}</td>
                <td>{user.name || t('txt_dash')}</td>
                <td>{roleText(user.role)}</td>
                <td>{statusText(user.status)}</td>
                <td>
                  <div className="actions">
                    <button
                      type="button"
                      className="btn btn-secondary"
                      disabled={user.id === props.currentUserId}
                      onClick={() => void props.onToggleUserStatus(user.id, user.status)}
                    >
                      {user.status === 'active' ? <UserX size={14} className="btn-icon" /> : <UserCheck size={14} className="btn-icon" />}
                      {user.status === 'active' ? t('txt_ban') : t('txt_unban')}
                    </button>
                    {user.role !== 'admin' && (
                      <button type="button" className="btn btn-danger" onClick={() => void props.onDeleteUser(user.id)}>
                        <Trash2 size={14} className="btn-icon" />
                        {t('txt_delete')}
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="card">
        <div className="section-head">
          <h3>{t('txt_invites')}</h3>
          <button type="button" className="btn btn-secondary" onClick={props.onRefresh}>
            <RefreshCw size={14} className="btn-icon" /> {t('txt_sync')}
          </button>
        </div>
        <div className="invite-toolbar">
          <div className="actions invite-create-group">
            <label className="field invite-hours-field">
              <span>{t('txt_invite_validity_hours')}</span>
              <input
                className="input small"
                type="number"
                value={inviteHours}
                min={1}
                max={720}
                onInput={(e) => setInviteHours(Number((e.currentTarget as HTMLInputElement).value || 168))}
              />
            </label>
            <button type="button" className="btn btn-primary" onClick={() => void props.onCreateInvite(inviteHours)}>
              <Plus size={14} className="btn-icon" />
              {t('txt_create_timed_invite')}
            </button>
          </div>
          <button type="button" className="btn btn-danger" onClick={() => void props.onDeleteAllInvites()}>
            <Trash2 size={14} className="btn-icon" /> {t('txt_delete_all')}
          </button>
        </div>
        <table className="table">
          <thead>
            <tr>
              <th>{t('txt_code')}</th>
              <th>{t('txt_status')}</th>
              <th>{t('txt_expires_at')}</th>
              <th className="invite-actions-head">{t('txt_actions')}</th>
            </tr>
          </thead>
          <tbody>
            {pagedInvites.map((invite) => (
              <tr key={invite.code}>
                <td>{invite.code}</td>
                <td>{statusText(invite.status)}</td>
                <td>{formatExpiresAt(invite.expiresAt)}</td>
                <td>
                  <div className="actions invite-row-actions">
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={() => navigator.clipboard.writeText(invite.inviteLink || '')}
                    >
                      <Clipboard size={14} className="btn-icon" /> {t('txt_copy_link')}
                    </button>
                    {invite.status === 'active' && (
                      <button type="button" className="btn btn-danger" onClick={() => void props.onRevokeInvite(invite.code)}>
                        <Trash2 size={14} className="btn-icon" /> {t('txt_revoke')}
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="actions">
          <button type="button" className="btn btn-secondary small" disabled={safePage <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>
            <ChevronLeft size={14} className="btn-icon" />
            {t('txt_prev')}
          </button>
          <span className="muted-inline">{safePage} / {totalPages}</span>
          <button type="button" className="btn btn-secondary small" disabled={safePage >= totalPages} onClick={() => setPage((p) => Math.min(totalPages, p + 1))}>
            {t('txt_next')}
            <ChevronRight size={14} className="btn-icon" />
          </button>
        </div>
      </section>
    </div>
  );
}
