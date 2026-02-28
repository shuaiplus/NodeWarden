import { useState } from 'preact/hooks';
import { Clipboard, RefreshCw, Trash2, UserCheck, UserX } from 'lucide-preact';
import type { AdminInvite, AdminUser } from '@/lib/types';

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
  const formatExpiresAt = (x?: string) => (x ? new Date(x).toLocaleString() : '-');
  const totalPages = Math.max(1, Math.ceil(props.invites.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const pagedInvites = props.invites.slice((safePage - 1) * pageSize, safePage * pageSize);

  return (
    <div className="stack">
      <section className="card">
        <h3>Users</h3>
        <table className="table">
          <thead>
            <tr>
              <th>Email</th>
              <th>Name</th>
              <th>Role</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {props.users.map((user) => (
              <tr key={user.id}>
                <td>{user.email}</td>
                <td>{user.name || '-'}</td>
                <td>{user.role}</td>
                <td>{user.status}</td>
                <td>
                  <div className="actions">
                    <button
                      type="button"
                      className="btn btn-secondary"
                      disabled={user.id === props.currentUserId}
                      onClick={() => void props.onToggleUserStatus(user.id, user.status)}
                    >
                      {user.status === 'active' ? <UserX size={14} className="btn-icon" /> : <UserCheck size={14} className="btn-icon" />}
                      {user.status === 'active' ? 'Ban' : 'Unban'}
                    </button>
                    {user.role !== 'admin' && (
                      <button type="button" className="btn btn-danger" onClick={() => void props.onDeleteUser(user.id)}>
                        <Trash2 size={14} className="btn-icon" />
                        Delete
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
          <h3>Invites</h3>
          <button type="button" className="btn btn-secondary" onClick={props.onRefresh}>
            <RefreshCw size={14} className="btn-icon" /> Sync
          </button>
        </div>
        <div className="invite-toolbar">
          <div className="actions invite-create-group">
            <label className="field invite-hours-field">
              <span>邀请码有效时长（小时）</span>
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
              创建时效邀请码
            </button>
          </div>
          <button type="button" className="btn btn-danger" onClick={() => void props.onDeleteAllInvites()}>
            <Trash2 size={14} className="btn-icon" /> Delete All
          </button>
        </div>
        <table className="table">
          <thead>
            <tr>
              <th>Code</th>
              <th>Status</th>
              <th>Expires At</th>
              <th className="invite-actions-head">Actions</th>
            </tr>
          </thead>
          <tbody>
            {pagedInvites.map((invite) => (
              <tr key={invite.code}>
                <td>{invite.code}</td>
                <td>{invite.status}</td>
                <td>{formatExpiresAt(invite.expiresAt)}</td>
                <td>
                  <div className="actions invite-row-actions">
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={() => navigator.clipboard.writeText(invite.inviteLink || '')}
                    >
                      <Clipboard size={14} className="btn-icon" /> Copy Link
                    </button>
                    {invite.status === 'active' && (
                      <button type="button" className="btn btn-danger" onClick={() => void props.onRevokeInvite(invite.code)}>
                        <Trash2 size={14} className="btn-icon" /> Revoke
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
            Prev
          </button>
          <span className="muted-inline">{safePage} / {totalPages}</span>
          <button type="button" className="btn btn-secondary small" disabled={safePage >= totalPages} onClick={() => setPage((p) => Math.min(totalPages, p + 1))}>
            Next
          </button>
        </div>
      </section>
    </div>
  );
}
