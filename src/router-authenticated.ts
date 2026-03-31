import type { Env, User } from './types';
import { errorResponse, jsonResponse } from './utils/response';
import {
  handleGetProfile,
  handleUpdateProfile,
  handleSetKeys,
  handleGetRevisionDate,
  handleVerifyPassword,
  handleChangePassword,
  handleSetVerifyDevices,
  handleGetTotpStatus,
  handleSetTotpStatus,
  handleGetTotpRecoveryCode,
} from './handlers/accounts';
import {
  handleGetCiphers,
  handleGetCipher,
  handleCreateCipher,
  handleUpdateCipher,
  handleDeleteCipher,
  handleDeleteCipherCompat,
  handlePermanentDeleteCipher,
  handleRestoreCipher,
  handleBulkArchiveCiphers,
  handlePartialUpdateCipher,
  handleBulkUnarchiveCiphers,
  handleBulkMoveCiphers,
  handleBulkDeleteCiphers,
  handleBulkPermanentDeleteCiphers,
  handleBulkRestoreCiphers,
  handleArchiveCipher,
  handleUnarchiveCipher,
} from './handlers/ciphers';
import {
  handleGetFolders,
  handleGetFolder,
  handleCreateFolder,
  handleUpdateFolder,
  handleDeleteFolder,
  handleBulkDeleteFolders,
} from './handlers/folders';
import {
  handleGetSends,
  handleGetSend,
  handleCreateSend,
  handleCreateFileSendV2,
  handleGetSendFileUpload,
  handleUploadSendFile,
  handleUpdateSend,
  handleDeleteSend,
  handleBulkDeleteSends,
  handleRemoveSendPassword,
  handleRemoveSendAuth,
} from './handlers/sends';
import { handleSync } from './handlers/sync';
import { handleCiphersImport } from './handlers/import';
import {
  handleCreateAttachment,
  handleUploadAttachment,
  handleGetAttachment,
  handleDeleteAttachment,
} from './handlers/attachments';
import { handleAuthenticatedDeviceRoute } from './router-devices';
import { handleAdminRoute } from './router-admin';
import {
  handleBeginPasskeyRegistration,
  handleDeletePasskey,
  handleFinishPasskeyRegistration,
  handleListPasskeys,
  handleRenamePasskey,
} from './handlers/passkeys';

export async function handleAuthenticatedRoute(
  request: Request,
  env: Env,
  userId: string,
  currentUser: User,
  path: string,
  method: string
): Promise<Response | null> {
  if (method === 'POST' || method === 'PUT' || method === 'DELETE') {
    const blockedAccountPaths = new Set([
      '/api/accounts/set-password',
      '/api/accounts/delete',
      '/api/accounts/delete-account',
      '/api/accounts/delete-vault',
    ]);
    if (blockedAccountPaths.has(path)) {
      return errorResponse('Not implemented', 501);
    }
  }

  if (path === '/api/accounts/profile') {
    if (method === 'GET') return handleGetProfile(request, env, userId);
    if (method === 'PUT') return handleUpdateProfile(request, env, userId);
    return errorResponse('Method not allowed', 405);
  }

  if ((path === '/api/accounts/password' || path === '/api/accounts/change-password') && (method === 'POST' || method === 'PUT')) {
    return handleChangePassword(request, env, userId);
  }

  if (path === '/api/accounts/keys' && method === 'POST') {
    return handleSetKeys(request, env, userId);
  }

  if (path === '/api/accounts/totp') {
    if (method === 'GET') return handleGetTotpStatus(request, env, userId);
    if (method === 'PUT' || method === 'POST') return handleSetTotpStatus(request, env, userId);
    return null;
  }

  if ((path === '/api/accounts/totp/recovery-code' || path === '/api/two-factor/get-recover') && method === 'POST') {
    return handleGetTotpRecoveryCode(request, env, userId);
  }

  if (path === '/api/accounts/passkeys' && method === 'GET') {
    return handleListPasskeys(request, env, userId);
  }

  if (path === '/api/accounts/passkeys/begin-registration' && method === 'POST') {
    return handleBeginPasskeyRegistration(request, env, userId);
  }

  if (path === '/api/accounts/passkeys/finish-registration' && method === 'POST') {
    return handleFinishPasskeyRegistration(request, env, userId);
  }

  const passkeyMatch = path.match(/^\/api\/accounts\/passkeys\/([a-f0-9-]+)$/i);
  if (passkeyMatch) {
    if (method === 'PATCH' || method === 'PUT') return handleRenamePasskey(request, env, userId, passkeyMatch[1]);
    if (method === 'DELETE') return handleDeletePasskey(request, env, userId, passkeyMatch[1]);
  }

  if (path === '/api/accounts/revision-date' && method === 'GET') {
    return handleGetRevisionDate(request, env, userId);
  }

  if (path === '/api/accounts/verify-password' && method === 'POST') {
    return handleVerifyPassword(request, env, userId);
  }

  if (path === '/api/accounts/verify-devices' && (method === 'PUT' || method === 'POST')) {
    return handleSetVerifyDevices(request, env, userId);
  }

  if (path === '/api/sync' && method === 'GET') {
    return handleSync(request, env, userId);
  }

  if (path.startsWith('/notifications/')) {
    return errorResponse('Not found', 404);
  }

  if (path === '/api/ciphers' || path === '/api/ciphers/create') {
    if (method === 'GET') return handleGetCiphers(request, env, userId);
    if (method === 'POST') return handleCreateCipher(request, env, userId);
    return null;
  }

  if (path === '/api/ciphers/import' && method === 'POST') {
    return handleCiphersImport(request, env, userId);
  }

  if (path === '/api/ciphers/delete' && method === 'POST') {
    return handleBulkDeleteCiphers(request, env, userId);
  }

  if (path === '/api/ciphers/delete-permanent' && method === 'POST') {
    return handleBulkPermanentDeleteCiphers(request, env, userId);
  }

  if (path === '/api/ciphers/restore' && method === 'POST') {
    return handleBulkRestoreCiphers(request, env, userId);
  }

  if (path === '/api/ciphers/archive' && (method === 'PUT' || method === 'POST')) {
    return handleBulkArchiveCiphers(request, env, userId);
  }

  if (path === '/api/ciphers/unarchive' && (method === 'PUT' || method === 'POST')) {
    return handleBulkUnarchiveCiphers(request, env, userId);
  }

  if (path === '/api/ciphers/move' && (method === 'POST' || method === 'PUT')) {
    return handleBulkMoveCiphers(request, env, userId);
  }

  const cipherMatch = path.match(/^\/api\/ciphers\/([a-f0-9-]+)(\/.*)?$/i);
  if (cipherMatch) {
    const cipherId = cipherMatch[1];
    const subPath = cipherMatch[2] || '';

    if (subPath === '' || subPath === '/') {
      if (method === 'GET') return handleGetCipher(request, env, userId, cipherId);
      if (method === 'PUT' || method === 'POST') return handleUpdateCipher(request, env, userId, cipherId);
      if (method === 'DELETE') return handleDeleteCipherCompat(request, env, userId, cipherId);
    }

    if (subPath === '/delete' && method === 'PUT') return handleDeleteCipher(request, env, userId, cipherId);
    if (subPath === '/delete' && method === 'DELETE') return handlePermanentDeleteCipher(request, env, userId, cipherId);
    if (subPath === '/restore' && method === 'PUT') return handleRestoreCipher(request, env, userId, cipherId);
    if (subPath === '/archive' && (method === 'PUT' || method === 'POST')) return handleArchiveCipher(request, env, userId, cipherId);
    if (subPath === '/unarchive' && (method === 'PUT' || method === 'POST')) return handleUnarchiveCipher(request, env, userId, cipherId);
    if (subPath === '/partial' && (method === 'PUT' || method === 'POST')) return handlePartialUpdateCipher(request, env, userId, cipherId);
    if (subPath === '/share' && method === 'POST') return handleGetCipher(request, env, userId, cipherId);
    if (subPath === '/details' && method === 'GET') return handleGetCipher(request, env, userId, cipherId);
    if (subPath === '/attachment/v2' && method === 'POST') return handleCreateAttachment(request, env, userId, cipherId);
    if (subPath === '/attachment' && method === 'POST') return handleCreateAttachment(request, env, userId, cipherId);

    const attachmentMatch = subPath.match(/^\/attachment\/([a-f0-9-]+)$/i);
    if (attachmentMatch) {
      const attachmentId = attachmentMatch[1];
      if (method === 'POST' || method === 'PUT') return handleUploadAttachment(request, env, userId, cipherId, attachmentId);
      if (method === 'GET') return handleGetAttachment(request, env, userId, cipherId, attachmentId);
      if (method === 'DELETE') return handleDeleteAttachment(request, env, userId, cipherId, attachmentId);
    }

    const attachmentDeleteMatch = subPath.match(/^\/attachment\/([a-f0-9-]+)\/delete$/i);
    if (attachmentDeleteMatch && method === 'POST') {
      return handleDeleteAttachment(request, env, userId, cipherId, attachmentDeleteMatch[1]);
    }
  }

  if (path === '/api/folders') {
    if (method === 'GET') return handleGetFolders(request, env, userId);
    if (method === 'POST') return handleCreateFolder(request, env, userId);
    return null;
  }

  if (path === '/api/folders/delete' && method === 'POST') {
    return handleBulkDeleteFolders(request, env, userId);
  }

  const folderMatch = path.match(/^\/api\/folders\/([a-f0-9-]+)$/i);
  if (folderMatch) {
    const folderId = folderMatch[1];
    if (method === 'GET') return handleGetFolder(request, env, userId, folderId);
    if (method === 'PUT') return handleUpdateFolder(request, env, userId, folderId);
    if (method === 'DELETE') return handleDeleteFolder(request, env, userId, folderId);
  }

  if (path.startsWith('/api/auth-requests')) {
    return jsonResponse({ data: [], object: 'list', continuationToken: null });
  }

  if (path === '/api/collections' || path.startsWith('/api/collections/')) {
    if (method === 'GET') {
      return jsonResponse({ data: [], object: 'list', continuationToken: null });
    }
    return null;
  }

  if (path === '/api/organizations' || path.startsWith('/api/organizations/')) {
    if (method === 'GET') {
      return jsonResponse({ data: [], object: 'list', continuationToken: null });
    }
    return null;
  }

  if (path === '/api/sends') {
    if (method === 'GET') return handleGetSends(request, env, userId);
    if (method === 'POST') return handleCreateSend(request, env, userId);
    return null;
  }

  if (path === '/api/sends/file/v2' && method === 'POST') {
    return handleCreateFileSendV2(request, env, userId);
  }

  if (path === '/api/sends/delete' && method === 'POST') {
    return handleBulkDeleteSends(request, env, userId);
  }

  const sendMatch = path.match(/^\/api\/sends\/([^/]+)(\/.*)?$/i);
  if (sendMatch) {
    const sendId = sendMatch[1];
    const subPath = sendMatch[2] || '';

    if (subPath === '' || subPath === '/') {
      if (method === 'GET') return handleGetSend(request, env, userId, sendId);
      if (method === 'PUT') return handleUpdateSend(request, env, userId, sendId);
      if (method === 'DELETE') return handleDeleteSend(request, env, userId, sendId);
    }

    if (subPath === '/remove-password' && (method === 'PUT' || method === 'POST')) {
      return handleRemoveSendPassword(request, env, userId, sendId);
    }

    if (subPath === '/remove-auth' && (method === 'PUT' || method === 'POST')) {
      return handleRemoveSendAuth(request, env, userId, sendId);
    }

    const sendFileUploadMatch = subPath.match(/^\/file\/([^/]+)\/?$/i);
    if (sendFileUploadMatch) {
      const fileId = sendFileUploadMatch[1];
      if (method === 'GET') return handleGetSendFileUpload(request, env, userId, sendId, fileId);
      if (method === 'POST' || method === 'PUT') return handleUploadSendFile(request, env, userId, sendId, fileId);
    }
  }

  if (path === '/api/policies' || path.startsWith('/api/policies/')) {
    if (method === 'GET') {
      return jsonResponse({ data: [], object: 'list', continuationToken: null });
    }
    return null;
  }

  if (path === '/api/settings/domains') {
    if (method === 'GET' || method === 'PUT' || method === 'POST') {
      return jsonResponse({
        equivalentDomains: [],
        globalEquivalentDomains: [],
        object: 'domains',
      });
    }
    return null;
  }

  const authenticatedDeviceResponse = await handleAuthenticatedDeviceRoute(request, env, userId, path, method);
  if (authenticatedDeviceResponse) return authenticatedDeviceResponse;

  const adminResponse = await handleAdminRoute(request, env, currentUser, path, method);
  if (adminResponse) return adminResponse;

  return null;
}
