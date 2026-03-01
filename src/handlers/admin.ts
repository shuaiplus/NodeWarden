import { Env, User, Invite } from '../types';
import { StorageService } from '../services/storage';
import { jsonResponse, errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';

function isAdmin(user: User): boolean {
  return user.role === 'admin' && user.status === 'active';
}

function randomHex(bytes: number): string {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(data).map(v => v.toString(16).padStart(2, '0')).join('');
}

function buildInviteLink(request: Request, code: string): string {
  const url = new URL(request.url);
  return `${url.origin}/?invite=${encodeURIComponent(code)}`;
}

async function writeAuditLog(
  storage: StorageService,
  actorUserId: string | null,
  action: string,
  targetType: string | null,
  targetId: string | null,
  metadata: Record<string, unknown> | null
): Promise<void> {
  await storage.createAuditLog({
    id: generateUUID(),
    actorUserId,
    action,
    targetType,
    targetId,
    metadata: metadata ? JSON.stringify(metadata) : null,
    createdAt: new Date().toISOString(),
  });
}

function toInviteResponse(request: Request, invite: Invite): Record<string, unknown> {
  return {
    code: invite.code,
    status: invite.status,
    createdBy: invite.createdBy,
    usedBy: invite.usedBy,
    createdAt: invite.createdAt,
    updatedAt: invite.updatedAt,
    expiresAt: invite.expiresAt,
    inviteLink: buildInviteLink(request, invite.code),
    object: 'invite',
  };
}

// GET /api/admin/users
export async function handleAdminListUsers(
  request: Request,
  env: Env,
  actorUser: User
): Promise<Response> {
  void request;
  if (!isAdmin(actorUser)) {
    return errorResponse('Forbidden', 403);
  }

  const storage = new StorageService(env.DB);
  const users = await storage.getAllUsers();
  return jsonResponse({
    data: users.map(user => ({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      status: user.status,
      twoFactorEnabled: !!user.totpSecret,
      creationDate: user.createdAt,
      revisionDate: user.updatedAt,
      object: 'user',
    })),
    object: 'list',
    continuationToken: null,
  });
}

// POST /api/admin/invites
export async function handleAdminCreateInvite(
  request: Request,
  env: Env,
  actorUser: User
): Promise<Response> {
  if (!isAdmin(actorUser)) {
    return errorResponse('Forbidden', 403);
  }

  const storage = new StorageService(env.DB);
  let body: { expiresInHours?: number } = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  const expiresInHours = Number.isFinite(body.expiresInHours)
    ? Math.max(1, Math.min(24 * 30, Math.floor(Number(body.expiresInHours))))
    : 24 * 7;
  const now = new Date();
  const expiresAt = new Date(now.getTime() + expiresInHours * 60 * 60 * 1000);
  const invite: Invite = {
    code: randomHex(20),
    createdBy: actorUser.id,
    usedBy: null,
    expiresAt: expiresAt.toISOString(),
    status: 'active',
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
  };

  await storage.createInvite(invite);
  await writeAuditLog(storage, actorUser.id, 'admin.invite.create', 'invite', invite.code, {
    expiresInHours,
  });

  return jsonResponse(toInviteResponse(request, invite), 201);
}

// GET /api/admin/invites
export async function handleAdminListInvites(
  request: Request,
  env: Env,
  actorUser: User
): Promise<Response> {
  if (!isAdmin(actorUser)) {
    return errorResponse('Forbidden', 403);
  }

  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  const includeInactive = url.searchParams.get('includeInactive') === 'true';
  const invites = await storage.listInvites(includeInactive);
  return jsonResponse({
    data: invites.map(invite => toInviteResponse(request, invite)),
    object: 'list',
    continuationToken: null,
  });
}

// DELETE /api/admin/invites/:code
export async function handleAdminRevokeInvite(
  request: Request,
  env: Env,
  actorUser: User,
  code: string
): Promise<Response> {
  if (!isAdmin(actorUser)) {
    return errorResponse('Forbidden', 403);
  }

  const storage = new StorageService(env.DB);
  const revoked = await storage.revokeInvite(code);
  if (!revoked) {
    return errorResponse('Invite not found or already inactive', 404);
  }

  await writeAuditLog(storage, actorUser.id, 'admin.invite.revoke', 'invite', code, null);
  return new Response(null, { status: 204 });
}

// DELETE /api/admin/invites
export async function handleAdminDeleteAllInvites(
  request: Request,
  env: Env,
  actorUser: User
): Promise<Response> {
  void request;
  if (!isAdmin(actorUser)) {
    return errorResponse('Forbidden', 403);
  }

  const storage = new StorageService(env.DB);
  const deleted = await storage.deleteAllInvites();
  await writeAuditLog(storage, actorUser.id, 'admin.invite.delete_all', 'invite', null, {
    deleted,
  });

  return jsonResponse({ deleted }, 200);
}

// PUT /api/admin/users/:id/status
export async function handleAdminSetUserStatus(
  request: Request,
  env: Env,
  actorUser: User,
  targetUserId: string
): Promise<Response> {
  if (!isAdmin(actorUser)) {
    return errorResponse('Forbidden', 403);
  }

  let body: { status?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const nextStatus = body.status === 'banned' ? 'banned' : body.status === 'active' ? 'active' : null;
  if (!nextStatus) {
    return errorResponse('status must be active or banned', 400);
  }
  if (targetUserId === actorUser.id && nextStatus !== 'active') {
    return errorResponse('You cannot ban yourself', 400);
  }

  const storage = new StorageService(env.DB);
  const target = await storage.getUserById(targetUserId);
  if (!target) {
    return errorResponse('User not found', 404);
  }

  target.status = nextStatus;
  target.updatedAt = new Date().toISOString();
  await storage.saveUser(target);
  if (nextStatus === 'banned') {
    await storage.deleteRefreshTokensByUserId(target.id);
  }
  await writeAuditLog(storage, actorUser.id, 'admin.user.status', 'user', target.id, {
    status: nextStatus,
  });

  return jsonResponse({
    id: target.id,
    email: target.email,
    role: target.role,
    status: target.status,
    object: 'user',
  });
}

// DELETE /api/admin/users/:id
export async function handleAdminDeleteUser(
  request: Request,
  env: Env,
  actorUser: User,
  targetUserId: string
): Promise<Response> {
  void request;
  if (!isAdmin(actorUser)) {
    return errorResponse('Forbidden', 403);
  }
  if (targetUserId === actorUser.id) {
    return errorResponse('You cannot delete yourself', 400);
  }

  const storage = new StorageService(env.DB);
  const target = await storage.getUserById(targetUserId);
  if (!target) {
    return errorResponse('User not found', 404);
  }

  // Clean up R2 files before DB cascade deletes the metadata rows.
  // 1. Attachment files (keyed by cipherId/attachmentId)
  const attachmentMap = await storage.getAttachmentsByUserId(target.id);
  for (const [cipherId, attachments] of attachmentMap) {
    for (const att of attachments) {
      await env.ATTACHMENTS.delete(`${cipherId}/${att.id}`);
    }
  }
  // 2. Send files (keyed by sends/sendId/fileId)
  const sends = await storage.getAllSends(target.id);
  for (const send of sends) {
    if (send.type === 1) { // SendType.File
      try {
        const parsed = JSON.parse(send.data) as Record<string, unknown>;
        const fileId = typeof parsed.id === 'string' ? parsed.id : null;
        if (fileId) {
          await env.ATTACHMENTS.delete(`sends/${send.id}/${fileId}`);
        }
      } catch { /* non-file send or bad data, skip */ }
    }
  }

  await storage.deleteRefreshTokensByUserId(target.id);
  await storage.deleteUserById(target.id);
  await writeAuditLog(storage, actorUser.id, 'admin.user.delete', 'user', target.id, {
    email: target.email,
  });

  return new Response(null, { status: 204 });
}
