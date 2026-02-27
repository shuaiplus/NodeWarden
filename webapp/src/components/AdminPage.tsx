import { useState } from 'preact/hooks';
import type { AdminInvite, AdminUser } from '@/lib/types';

interface AdminPageProps {
  users: AdminUser[];
  invites: AdminInvite[];
  onRefresh: () => void;
  onCreateInvite: (hours: number) => Promise<void>;
  onToggleUserStatus: (userId: string, currentStatus: string) => Promise<void>;
  onDeleteUser: (userId: string) => Promise<void>;
  onRevokeInvite: (code: string) => Promise<void>;
}

export default function AdminPage(props: AdminPageProps) {
  const [inviteHours, setInviteHours] = useState(168);

  return (
    <div className="stack">
      <section className="card">
        <div className="section-head">
          <h3>Invites</h3>
          <button type="button" className="btn btn-secondary" onClick={props.onRefresh}>
            Sync
          </button>
        </div>
        <div className="actions">
          <input
            className="input small"
            type="number"
            value={inviteHours}
            min={1}
            max={720}
            onInput={(e) => setInviteHours(Number((e.currentTarget as HTMLInputElement).value || 168))}
          />
          <button type="button" className="btn btn-primary" onClick={() => void props.onCreateInvite(inviteHours)}>
            Create Invite
          </button>
        </div>
        <table className="table">
          <thead>
            <tr>
              <th>Code</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {props.invites.map((invite) => (
              <tr key={invite.code}>
                <td>{invite.code}</td>
                <td>{invite.status}</td>
                <td>
                  <div className="actions">
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={() => navigator.clipboard.writeText(invite.inviteLink || '')}
                    >
                      Copy Link
                    </button>
                    {invite.status === 'active' && (
                      <button type="button" className="btn btn-danger" onClick={() => void props.onRevokeInvite(invite.code)}>
                        Revoke
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
                      onClick={() => void props.onToggleUserStatus(user.id, user.status)}
                    >
                      {user.status === 'active' ? 'Ban' : 'Unban'}
                    </button>
                    {user.role !== 'admin' && (
                      <button type="button" className="btn btn-danger" onClick={() => void props.onDeleteUser(user.id)}>
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
    </div>
  );
}
