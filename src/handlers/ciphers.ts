import { Env, Cipher, CipherResponse, Attachment } from '../types';
import { StorageService } from '../services/storage';
import { jsonResponse, errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { deleteAllAttachmentsForCipher } from './attachments';
import { parsePagination, encodeContinuationToken } from '../utils/pagination';

function getAliasedProp(source: any, aliases: string[]): { present: boolean; value: any } {
  if (!source || typeof source !== 'object') return { present: false, value: undefined };
  for (const key of aliases) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      return { present: true, value: source[key] };
    }
  }
  return { present: false, value: undefined };
}

// Android 2026.2.0 expects fido2Credentials[].counter to be a string.
export function normalizeCipherLoginForCompatibility(login: any): any {
  if (!login || typeof login !== 'object') return login ?? null;

  const fido2 = Array.isArray(login.fido2Credentials)
    ? login.fido2Credentials.map((cred: any) => {
        if (!cred || typeof cred !== 'object') return cred;
        const rawCounter = cred.counter;
        const counter =
          rawCounter === null || rawCounter === undefined
            ? '0'
            : String(rawCounter);
        return {
          ...cred,
          counter,
        };
      })
    : login.fido2Credentials;

  return {
    ...login,
    fido2Credentials: fido2,
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
export function cipherToResponse(cipher: Cipher, attachments: Attachment[] = []): CipherResponse {
  // Strip internal-only fields that must not appear in the API response
  const { userId, createdAt, updatedAt, deletedAt, ...passthrough } = cipher;
  const normalizedLogin = normalizeCipherLoginForCompatibility((passthrough as any).login ?? null);

  return {
    // Pass through ALL stored cipher fields (known + unknown)
    ...passthrough,
    // Server-computed / enforced fields (always override)
    type: Number(cipher.type) || 1,
    organizationId: null,
    organizationUseTotp: false,
    creationDate: createdAt,
    revisionDate: updatedAt,
    deletedDate: deletedAt,
    archivedDate: null,
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
  return jsonResponse(cipherToResponse(cipher, attachments));
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
    deletedAt: null,
  };
  cipher.login = normalizeCipherLoginForCompatibility(cipher.login);
  const createFields = getAliasedProp(cipherData, ['fields', 'Fields']);
  cipher.fields = createFields.present ? (createFields.value ?? null) : (cipher.fields ?? null);

  // Prevent referencing a folder owned by another user.
  if (cipher.folderId) {
    const folderOk = await verifyFolderOwnership(storage, cipher.folderId, userId);
    if (!folderOk) return errorResponse('Folder not found', 404);
  }

  await storage.saveCipher(cipher);
  await storage.updateRevisionDate(userId);

  return jsonResponse(cipherToResponse(cipher), 200);
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
    deletedAt: existingCipher.deletedAt,
  };
  cipher.login = normalizeCipherLoginForCompatibility(cipher.login);

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

  // Prevent referencing a folder owned by another user.
  if (cipher.folderId) {
    const folderOk = await verifyFolderOwnership(storage, cipher.folderId, userId);
    if (!folderOk) return errorResponse('Folder not found', 404);
  }

  await storage.saveCipher(cipher);
  await storage.updateRevisionDate(userId);

  return jsonResponse(cipherToResponse(cipher));
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
  await storage.saveCipher(cipher);
  await storage.updateRevisionDate(userId);

  return jsonResponse(cipherToResponse(cipher));
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
    await storage.updateRevisionDate(userId);
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
  await storage.updateRevisionDate(userId);

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
  await storage.saveCipher(cipher);
  await storage.updateRevisionDate(userId);

  return jsonResponse(cipherToResponse(cipher));
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
    if (body.folderId) {
      const folderOk = await verifyFolderOwnership(storage, body.folderId, userId);
      if (!folderOk) return errorResponse('Folder not found', 404);
    }
    cipher.folderId = body.folderId;
  }
  if (body.favorite !== undefined) {
    cipher.favorite = body.favorite;
  }
  cipher.updatedAt = new Date().toISOString();

  await storage.saveCipher(cipher);
  await storage.updateRevisionDate(userId);

  return jsonResponse(cipherToResponse(cipher));
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

  if (body.folderId) {
    const folderOk = await verifyFolderOwnership(storage, body.folderId, userId);
    if (!folderOk) return errorResponse('Folder not found', 404);
  }

  await storage.bulkMoveCiphers(body.ids, body.folderId || null, userId);

  return new Response(null, { status: 204 });
}
