import { Env, Cipher, CipherResponse, Attachment } from '../types';
import { StorageService } from '../services/storage';
import { notifyUserVaultSync } from '../durable/notifications-hub';
import { jsonResponse, errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { deleteAllAttachmentsForCipher } from './attachments';
import { parsePagination, encodeContinuationToken } from '../utils/pagination';
import { readActingDeviceIdentifier } from '../utils/device';

function normalizeOptionalId(value: unknown): string | null {
  if (value == null) return null;
  const normalized = String(value).trim();
  return normalized ? normalized : null;
}

async function notifyVaultSyncForRequest(
  request: Request,
  env: Env,
  userId: string,
  revisionDate: string
): Promise<void> {
  await notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
}

function getAliasedProp(source: any, aliases: string[]): { present: boolean; value: any } {
  if (!source || typeof source !== 'object') return { present: false, value: undefined };
  for (const key of aliases) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      return { present: true, value: source[key] };
    }
  }
  return { present: false, value: undefined };
}

function normalizeCipherTimestamp(value: unknown): string | null {
  if (value == null || value === '') return null;
  const parsed = new Date(String(value));
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

function readCipherArchivedAt(source: any, fallback: string | null = null): string | null {
  const archived = getAliasedProp(source, ['archivedAt', 'ArchivedAt', 'archivedDate', 'ArchivedDate']);
  return archived.present ? normalizeCipherTimestamp(archived.value) : fallback;
}

function syncCipherComputedAliases(cipher: Cipher): Cipher {
  cipher.archivedDate = cipher.archivedAt ?? null;
  cipher.deletedDate = cipher.deletedAt ?? null;
  return cipher;
}

function normalizeCipherForStorage(cipher: Cipher): Cipher {
  cipher.login = normalizeCipherLoginForStorage(cipher.login);
  cipher.sshKey = normalizeCipherSshKeyForCompatibility(cipher.sshKey);
  cipher.folderId = normalizeOptionalId(cipher.folderId);
  const hasArchivedAt = Object.prototype.hasOwnProperty.call(cipher as object, 'archivedAt');
  cipher.archivedAt = hasArchivedAt
    ? normalizeCipherTimestamp(cipher.archivedAt) ?? null
    : normalizeCipherTimestamp(cipher.archivedDate) ?? null;
  return syncCipherComputedAliases(cipher);
}

export function normalizeCipherLoginForStorage(login: any): any {
  if (!login || typeof login !== 'object') return login ?? null;
  return {
    ...login,
    fido2Credentials: Array.isArray(login.fido2Credentials) ? login.fido2Credentials : null,
  };
}

export function normalizeCipherLoginForCompatibility(login: any): any {
  const normalized = normalizeCipherLoginForStorage(login);
  if (!normalized || typeof normalized !== 'object') return normalized ?? null;
  return normalized;
}

// Android 2026.2.0 requires sshKey.keyFingerprint in sync payloads.
// Keep legacy alias "fingerprint" in parallel for older web payloads.
export function normalizeCipherSshKeyForCompatibility(sshKey: any): any {
  if (!sshKey || typeof sshKey !== 'object') return sshKey ?? null;

  const candidate =
    sshKey.keyFingerprint !== undefined && sshKey.keyFingerprint !== null
      ? sshKey.keyFingerprint
      : sshKey.fingerprint;

  const normalizedFingerprint =
    candidate === undefined || candidate === null
      ? ''
      : String(candidate);

  return {
    ...sshKey,
    keyFingerprint: normalizedFingerprint,
    fingerprint: normalizedFingerprint,
  };
}

// Format attachments for API response
export function formatAttachments(attachments: Attachment[]): any[] | null {
  if (attachments.length === 0) return null;
  return attachments.map(a => ({
    id: a.id,
    fileName: a.fileName,
    // Bitwarden clients decode attachment size as string in cipher payloads.
    size: String(Number(a.size) || 0),
    sizeName: a.sizeName,
    key: a.key,
    url: `/api/ciphers/${a.cipherId}/attachment/${a.id}`,  // Android requires non-null url!
    object: 'attachment',
  }));
}

// Convert internal cipher to API response format.
// Uses opaque passthrough: spreads ALL stored fields (including unknown/future ones),
// then overlays server-computed fields. This ensures new Bitwarden client fields
// survive a round-trip without code changes.
export function cipherToResponse(
  cipher: Cipher,
  attachments: Attachment[] = []
): CipherResponse {
  // Strip internal-only fields that must not appear in the API response
  const { userId, createdAt, updatedAt, archivedAt, deletedAt, ...passthrough } = cipher;
  const normalizedLogin = normalizeCipherLoginForCompatibility((passthrough as any).login ?? null);
  const normalizedSshKey = normalizeCipherSshKeyForCompatibility((passthrough as any).sshKey ?? null);

  return {
    // Pass through ALL stored cipher fields (known + unknown)
    ...passthrough,
    // Server-computed / enforced fields (always override)
    folderId: normalizeOptionalId(cipher.folderId),
    type: Number(cipher.type) || 1,
    organizationId: null,
    organizationUseTotp: false,
    creationDate: createdAt,
    revisionDate: updatedAt,
    deletedDate: deletedAt,
    archivedDate: archivedAt ?? null,
    edit: true,
    viewPassword: true,
    permissions: {
      delete: true,
      restore: true,
    },
    object: 'cipher',
    collectionIds: [],
    attachments: formatAttachments(attachments),
    login: normalizedLogin,
    sshKey: normalizedSshKey,
    encryptedFor: null,
  };
}

// GET /api/ciphers
export async function handleGetCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  const includeDeleted = url.searchParams.get('deleted') === 'true';
  const pagination = parsePagination(url);

  let filteredCiphers: Cipher[];
  let continuationToken: string | null = null;
  if (pagination) {
    const pageRows = await storage.getCiphersPage(
      userId,
      includeDeleted,
      pagination.limit + 1,
      pagination.offset
    );
    const hasNext = pageRows.length > pagination.limit;
    filteredCiphers = hasNext ? pageRows.slice(0, pagination.limit) : pageRows;
    continuationToken = hasNext ? encodeContinuationToken(pagination.offset + filteredCiphers.length) : null;
  } else {
    const ciphers = await storage.getAllCiphers(userId);
    filteredCiphers = includeDeleted
      ? ciphers
      : ciphers.filter(c => !c.deletedAt);
  }

  const attachmentsByCipher = await storage.getAttachmentsByUserId(userId);

  // Get attachments for all ciphers
  const cipherResponses = [];
  for (const cipher of filteredCiphers) {
    const attachments = attachmentsByCipher.get(cipher.id) || [];
    cipherResponses.push(cipherToResponse(cipher, attachments));
  }

  return jsonResponse({
    data: cipherResponses,
    object: 'list',
    continuationToken: continuationToken,
  });
}

// GET /api/ciphers/:id
export async function handleGetCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const cipher = await storage.getCipher(id);

  if (!cipher || cipher.userId !== userId) {
    return errorResponse('Cipher not found', 404);
  }

  const attachments = await storage.getAttachmentsByCipher(cipher.id);
  return jsonResponse(
    cipherToResponse(cipher, attachments)
  );
}

async function verifyFolderOwnership(storage: StorageService, folderId: string | null | undefined, userId: string): Promise<boolean> {
  if (!folderId) return true;
  const folder = await storage.getFolder(folderId);
  return !!(folder && folder.userId === userId);
}

// POST /api/ciphers
export async function handleCreateCipher(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  // Handle nested cipher object (from some clients)
  // Android client sends PascalCase "Cipher" for organization ciphers
  const cipherData = body.Cipher || body.cipher || body;

  const now = new Date().toISOString();
  // Opaque passthrough: spread ALL client fields to preserve unknown/future ones,
  // then override only server-controlled fields.
  const cipher: Cipher = {
    ...cipherData,
    // Server-controlled fields (always override client values)
    id: generateUUID(),
    userId: userId,
    type: Number(cipherData.type) || 1,
    favorite: !!cipherData.favorite,
    reprompt: cipherData.reprompt || 0,
    createdAt: now,
    updatedAt: now,
    archivedAt: readCipherArchivedAt(cipherData, null),
    deletedAt: null,
  };
  const createFields = getAliasedProp(cipherData, ['fields', 'Fields']);
  cipher.fields = createFields.present ? (createFields.value ?? null) : (cipher.fields ?? null);
  normalizeCipherForStorage(cipher);

  // Prevent referencing a folder owned by another user.
  if (cipher.folderId) {
    const folderOk = await verifyFolderOwnership(storage, cipher.folderId, userId);
    if (!folderOk) return errorResponse('Folder not found', 404);
  }

  await storage.saveCipher(cipher);
  const revisionDate = await storage.updateRevisionDate(userId);
  await notifyVaultSyncForRequest(request, env, userId, revisionDate);

  return jsonResponse(
    cipherToResponse(cipher, []),
    200
  );
}

// PUT /api/ciphers/:id
export async function handleUpdateCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const existingCipher = await storage.getCipher(id);

  if (!existingCipher || existingCipher.userId !== userId) {
    return errorResponse('Cipher not found', 404);
  }

  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  // Handle nested cipher object
  // Android client sends PascalCase "Cipher" for organization ciphers
  const cipherData = body.Cipher || body.cipher || body;

  // Opaque passthrough: merge existing stored data with ALL incoming client fields.
  // Unknown/future fields from the client are preserved; server-controlled fields are protected.
  const cipher: Cipher = {
    ...existingCipher,   // start with all existing stored data (including unknowns)
    ...cipherData,       // overlay all client data (including new/unknown fields)
    // Server-controlled fields (never from client)
    id: existingCipher.id,
    userId: existingCipher.userId,
    type: Number(cipherData.type) || existingCipher.type,
    favorite: cipherData.favorite ?? existingCipher.favorite,
    reprompt: cipherData.reprompt ?? existingCipher.reprompt,
    createdAt: existingCipher.createdAt,
    updatedAt: new Date().toISOString(),
    archivedAt: readCipherArchivedAt(cipherData, existingCipher.archivedAt ?? null),
    deletedAt: existingCipher.deletedAt,
  };

  // Custom fields deletion compatibility:
  // - Accept both camelCase "fields" and PascalCase "Fields".
  // - For full update (PUT/POST on this endpoint), missing fields means cleared fields.
  //   This prevents stale custom fields from being resurrected by merge fallback.
  const incomingFields = getAliasedProp(cipherData, ['fields', 'Fields']);
  if (incomingFields.present) {
    cipher.fields = incomingFields.value ?? null;
  } else if (request.method === 'PUT' || request.method === 'POST') {
    cipher.fields = null;
  }
  normalizeCipherForStorage(cipher);

  // Prevent referencing a folder owned by another user.
  if (cipher.folderId) {
    const folderOk = await verifyFolderOwnership(storage, cipher.folderId, userId);
    if (!folderOk) return errorResponse('Folder not found', 404);
  }

  await storage.saveCipher(cipher);
  const revisionDate = await storage.updateRevisionDate(userId);
  await notifyVaultSyncForRequest(request, env, userId, revisionDate);

  return jsonResponse(
    cipherToResponse(cipher, [])
  );
}

// DELETE /api/ciphers/:id
export async function handleDeleteCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const cipher = await storage.getCipher(id);

  if (!cipher || cipher.userId !== userId) {
    return errorResponse('Cipher not found', 404);
  }

  // Soft delete
  cipher.deletedAt = new Date().toISOString();
  cipher.updatedAt = cipher.deletedAt;
  syncCipherComputedAliases(cipher);
  await storage.saveCipher(cipher);
  const revisionDate = await storage.updateRevisionDate(userId);
  await notifyVaultSyncForRequest(request, env, userId, revisionDate);

  return jsonResponse(
    cipherToResponse(cipher, [])
  );
}

// DELETE /api/ciphers/:id (compat mode)
// Bitwarden clients may call DELETE on a trashed item to purge it permanently.
// For compatibility:
// - If item is active -> soft delete.
// - If item is already soft-deleted -> hard delete.
export async function handleDeleteCipherCompat(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const cipher = await storage.getCipher(id);

  if (!cipher || cipher.userId !== userId) {
    return errorResponse('Cipher not found', 404);
  }

  if (cipher.deletedAt) {
    await deleteAllAttachmentsForCipher(env, id);
    await storage.deleteCipher(id, userId);
    const revisionDate = await storage.updateRevisionDate(userId);
    await notifyVaultSyncForRequest(request, env, userId, revisionDate);
    return new Response(null, { status: 204 });
  }

  return handleDeleteCipher(request, env, userId, id);
}

// DELETE /api/ciphers/:id (permanent)
export async function handlePermanentDeleteCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const cipher = await storage.getCipher(id);

  if (!cipher || cipher.userId !== userId) {
    return errorResponse('Cipher not found', 404);
  }

  // Delete all attachments first
  await deleteAllAttachmentsForCipher(env, id);

  await storage.deleteCipher(id, userId);
  const revisionDate = await storage.updateRevisionDate(userId);
  await notifyVaultSyncForRequest(request, env, userId, revisionDate);

  return new Response(null, { status: 204 });
}

// PUT /api/ciphers/:id/restore
export async function handleRestoreCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const cipher = await storage.getCipher(id);

  if (!cipher || cipher.userId !== userId) {
    return errorResponse('Cipher not found', 404);
  }

  cipher.deletedAt = null;
  cipher.updatedAt = new Date().toISOString();
  syncCipherComputedAliases(cipher);
  await storage.saveCipher(cipher);
  const revisionDate = await storage.updateRevisionDate(userId);
  await notifyVaultSyncForRequest(request, env, userId, revisionDate);

  return jsonResponse(
    cipherToResponse(cipher, [])
  );
}

// PUT /api/ciphers/:id/partial - Update only favorite/folderId
export async function handlePartialUpdateCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const cipher = await storage.getCipher(id);

  if (!cipher || cipher.userId !== userId) {
    return errorResponse('Cipher not found', 404);
  }

  let body: { folderId?: string | null; favorite?: boolean };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (body.folderId !== undefined) {
    const folderId = normalizeOptionalId(body.folderId);
    if (folderId) {
      const folderOk = await verifyFolderOwnership(storage, folderId, userId);
      if (!folderOk) return errorResponse('Folder not found', 404);
    }
    cipher.folderId = folderId;
  }
  if (body.favorite !== undefined) {
    cipher.favorite = body.favorite;
  }
  cipher.updatedAt = new Date().toISOString();
  syncCipherComputedAliases(cipher);

  await storage.saveCipher(cipher);
  const revisionDate = await storage.updateRevisionDate(userId);
  await notifyVaultSyncForRequest(request, env, userId, revisionDate);

  return jsonResponse(
    cipherToResponse(cipher, [])
  );
}

// POST/PUT /api/ciphers/move - Bulk move to folder
export async function handleBulkMoveCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { ids?: string[]; folderId?: string | null };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.ids || !Array.isArray(body.ids)) {
    return errorResponse('ids array is required', 400);
  }

  const folderId = normalizeOptionalId(body.folderId);
  if (folderId) {
    const folderOk = await verifyFolderOwnership(storage, folderId, userId);
    if (!folderOk) return errorResponse('Folder not found', 404);
  }

  const revisionDate = await storage.bulkMoveCiphers(body.ids, folderId, userId);
  if (revisionDate) {
    await notifyVaultSyncForRequest(request, env, userId, revisionDate);
  }

  return new Response(null, { status: 204 });
}

async function buildCipherListResponse(
  request: Request,
  storage: StorageService,
  userId: string,
  ids: string[]
): Promise<Response> {
  const ciphers = await storage.getCiphersByIds(ids, userId);
  const attachmentsByCipher = await storage.getAttachmentsByCipherIds(ciphers.map((cipher) => cipher.id));

  return jsonResponse({
    data: ciphers.map((cipher) =>
      cipherToResponse(cipher, attachmentsByCipher.get(cipher.id) || [])
    ),
    object: 'list',
    continuationToken: null,
  });
}

function parseCipherIdList(body: { ids?: unknown }): string[] | null {
  if (!Array.isArray(body.ids)) return null;
  return Array.from(new Set(body.ids.map((id) => String(id || '').trim()).filter(Boolean)));
}

// PUT/POST /api/ciphers/:id/archive
export async function handleArchiveCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const cipher = await storage.getCipher(id);

  if (!cipher || cipher.userId !== userId) {
    return errorResponse('Cipher not found', 404);
  }
  if (cipher.deletedAt) {
    return errorResponse('Cannot archive a deleted cipher', 400);
  }

  cipher.archivedAt = new Date().toISOString();
  cipher.updatedAt = cipher.archivedAt;
  normalizeCipherForStorage(cipher);
  await storage.saveCipher(cipher);
  const revisionDate = await storage.updateRevisionDate(userId);
  await notifyVaultSyncForRequest(request, env, userId, revisionDate);

  const attachments = await storage.getAttachmentsByCipher(cipher.id);
  return jsonResponse(
    cipherToResponse(cipher, attachments)
  );
}

// PUT/POST /api/ciphers/:id/unarchive
export async function handleUnarchiveCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const cipher = await storage.getCipher(id);

  if (!cipher || cipher.userId !== userId) {
    return errorResponse('Cipher not found', 404);
  }

  cipher.archivedAt = null;
  cipher.updatedAt = new Date().toISOString();
  normalizeCipherForStorage(cipher);
  await storage.saveCipher(cipher);
  const revisionDate = await storage.updateRevisionDate(userId);
  await notifyVaultSyncForRequest(request, env, userId, revisionDate);

  const attachments = await storage.getAttachmentsByCipher(cipher.id);
  return jsonResponse(
    cipherToResponse(cipher, attachments)
  );
}

// PUT/POST /api/ciphers/archive
export async function handleBulkArchiveCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { ids?: unknown };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const ids = parseCipherIdList(body);
  if (!ids) {
    return errorResponse('ids array is required', 400);
  }

  const revisionDate = await storage.bulkArchiveCiphers(ids, userId);
  if (revisionDate) {
    await notifyVaultSyncForRequest(request, env, userId, revisionDate);
  }

  return buildCipherListResponse(request, storage, userId, ids);
}

// PUT/POST /api/ciphers/unarchive
export async function handleBulkUnarchiveCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { ids?: unknown };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const ids = parseCipherIdList(body);
  if (!ids) {
    return errorResponse('ids array is required', 400);
  }

  const revisionDate = await storage.bulkUnarchiveCiphers(ids, userId);
  if (revisionDate) {
    await notifyVaultSyncForRequest(request, env, userId, revisionDate);
  }

  return buildCipherListResponse(request, storage, userId, ids);
}

// POST /api/ciphers/delete - Bulk soft delete
export async function handleBulkDeleteCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { ids?: string[] };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.ids || !Array.isArray(body.ids)) {
    return errorResponse('ids array is required', 400);
  }

  const revisionDate = await storage.bulkSoftDeleteCiphers(body.ids, userId);
  if (revisionDate) {
    await notifyVaultSyncForRequest(request, env, userId, revisionDate);
  }

  return new Response(null, { status: 204 });
}

// POST /api/ciphers/restore - Bulk restore
export async function handleBulkRestoreCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { ids?: string[] };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.ids || !Array.isArray(body.ids)) {
    return errorResponse('ids array is required', 400);
  }

  const revisionDate = await storage.bulkRestoreCiphers(body.ids, userId);
  if (revisionDate) {
    await notifyVaultSyncForRequest(request, env, userId, revisionDate);
  }

  return new Response(null, { status: 204 });
}

// POST /api/ciphers/delete-permanent - Bulk permanent delete
export async function handleBulkPermanentDeleteCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { ids?: string[] };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.ids || !Array.isArray(body.ids)) {
    return errorResponse('ids array is required', 400);
  }

  const ids = Array.from(new Set(body.ids.map((id) => String(id || '').trim()).filter(Boolean)));
  if (!ids.length) {
    return new Response(null, { status: 204 });
  }

  for (const id of ids) {
    await deleteAllAttachmentsForCipher(env, id);
  }

  const revisionDate = await storage.bulkDeleteCiphers(ids, userId);
  if (revisionDate) {
    await notifyVaultSyncForRequest(request, env, userId, revisionDate);
  }

  return new Response(null, { status: 204 });
}
