import { Env, Send, SendResponse, SendType, DEFAULT_DEV_SECRET } from '../types';
import { StorageService } from '../services/storage';
import { jsonResponse, errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { parsePagination, encodeContinuationToken } from '../utils/pagination';
import { LIMITS } from '../config/limits';
import { createSendFileDownloadToken, verifySendFileDownloadToken } from '../utils/jwt';

const SEND_INACCESSIBLE_MSG = 'Send does not exist or is no longer available';
const SEND_PASSWORD_ITERATIONS = 100_000;

function getAliasedProp(source: unknown, aliases: string[]): { present: boolean; value: unknown } {
  if (!source || typeof source !== 'object') return { present: false, value: undefined };
  for (const key of aliases) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      const value = (source as Record<string, unknown>)[key];
      return { present: true, value };
    }
  }
  return { present: false, value: undefined };
}

function base64UrlEncode(data: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...data));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(input: string): Uint8Array | null {
  try {
    let normalized = input.replace(/-/g, '+').replace(/_/g, '/');
    while (normalized.length % 4) normalized += '=';
    const raw = atob(normalized);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function uuidToBytes(uuid: string): Uint8Array | null {
  const hex = uuid.replace(/-/g, '').toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) return null;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToUuid(bytes: Uint8Array): string | null {
  if (bytes.length !== 16) return null;
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-');
}

function toAccessId(sendId: string): string {
  const bytes = uuidToBytes(sendId);
  if (!bytes) return '';
  return base64UrlEncode(bytes);
}

function fromAccessId(accessId: string): string | null {
  const bytes = base64UrlDecode(accessId);
  if (!bytes || bytes.length !== 16) return null;
  return bytesToUuid(bytes);
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} Bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function parseDate(raw: unknown): Date | null {
  if (typeof raw !== 'string' || !raw.trim()) return null;
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return null;
  return date;
}

function parseInteger(raw: unknown): number | null {
  if (raw === null || raw === undefined || raw === '') return null;
  const value = typeof raw === 'string' ? Number(raw) : raw;
  if (typeof value !== 'number' || !Number.isFinite(value) || !Number.isInteger(value)) return null;
  return value;
}

function sanitizeSendData(raw: unknown): Record<string, unknown> | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const data = { ...(raw as Record<string, unknown>) };
  delete data.response;
  return data;
}

function parseStoredSendData(send: Send): Record<string, unknown> {
  try {
    const parsed = JSON.parse(send.data) as unknown;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return { ...(parsed as Record<string, unknown>) };
    }
    return {};
  } catch {
    return {};
  }
}

function normalizeSendDataSizeField(data: Record<string, unknown>): Record<string, unknown> {
  const normalized = { ...data };
  if (typeof normalized.size === 'number' && Number.isFinite(normalized.size)) {
    normalized.size = String(Math.trunc(normalized.size));
  }
  return normalized;
}

function getSendFilePath(sendId: string, fileId: string): string {
  return `sends/${sendId}/${fileId}`;
}

function isSendAvailable(send: Send): boolean {
  const now = Date.now();

  if (send.maxAccessCount !== null && send.accessCount >= send.maxAccessCount) {
    return false;
  }

  if (send.expirationDate) {
    const expirationMs = new Date(send.expirationDate).getTime();
    if (!Number.isNaN(expirationMs) && now >= expirationMs) {
      return false;
    }
  }

  const deletionMs = new Date(send.deletionDate).getTime();
  if (!Number.isNaN(deletionMs) && now >= deletionMs) {
    return false;
  }

  if (send.disabled) {
    return false;
  }

  return true;
}

async function deriveSendPasswordHash(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256',
    },
    key,
    256
  );
  return new Uint8Array(bits);
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

async function setSendPassword(send: Send, password: string | null): Promise<void> {
  if (!password) {
    send.passwordHash = null;
    send.passwordSalt = null;
    send.passwordIterations = null;
    return;
  }

  const salt = crypto.getRandomValues(new Uint8Array(64));
  const hash = await deriveSendPasswordHash(password, salt, SEND_PASSWORD_ITERATIONS);

  send.passwordSalt = base64UrlEncode(salt);
  send.passwordHash = base64UrlEncode(hash);
  send.passwordIterations = SEND_PASSWORD_ITERATIONS;
}

async function verifySendPassword(send: Send, password: string): Promise<boolean> {
  if (!send.passwordHash || !send.passwordSalt || !send.passwordIterations) {
    return false;
  }

  const salt = base64UrlDecode(send.passwordSalt);
  const expected = base64UrlDecode(send.passwordHash);
  if (!salt || !expected) return false;

  const actual = await deriveSendPasswordHash(password, salt, send.passwordIterations);
  return constantTimeEqual(actual, expected);
}

function validateDeletionDate(date: Date): Response | null {
  const maxMs = Date.now() + LIMITS.send.maxDeletionDays * 24 * 60 * 60 * 1000;
  if (date.getTime() > maxMs) {
    return errorResponse(
      'You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again.',
      400
    );
  }
  return null;
}

function parseMaxAccessCount(value: unknown): { ok: true; value: number | null } | { ok: false; response: Response } {
  const parsed = parseInteger(value);
  if (value === undefined || value === null || value === '') {
    return { ok: true, value: null };
  }
  if (parsed === null || parsed < 0) {
    return { ok: false, response: errorResponse('Invalid maxAccessCount', 400) };
  }
  return { ok: true, value: parsed };
}

function parseFileLength(value: unknown): { ok: true; value: number } | { ok: false; response: Response } {
  const parsed = parseInteger(value);
  if (parsed === null) {
    return { ok: false, response: errorResponse('Invalid send length', 400) };
  }
  if (parsed < 0) {
    return { ok: false, response: errorResponse("Send size can't be negative", 400) };
  }
  return { ok: true, value: parsed };
}

function parseSendType(value: unknown): SendType | null {
  const type = parseInteger(value);
  if (type === SendType.Text || type === SendType.File) return type;
  return null;
}

export function sendToResponse(send: Send): SendResponse {
  const data = normalizeSendDataSizeField(parseStoredSendData(send));
  return {
    id: send.id,
    accessId: toAccessId(send.id),
    type: Number(send.type) || 0,
    name: send.name,
    notes: send.notes,
    text: send.type === SendType.Text ? data : null,
    file: send.type === SendType.File ? data : null,
    key: send.key,
    maxAccessCount: send.maxAccessCount,
    accessCount: send.accessCount,
    password: send.passwordHash,
    disabled: send.disabled,
    hideEmail: send.hideEmail,
    revisionDate: send.updatedAt,
    expirationDate: send.expirationDate,
    deletionDate: send.deletionDate,
    object: 'send',
  };
}

function sendToAccessResponse(send: Send, creatorIdentifier: string | null): Record<string, unknown> {
  const data = normalizeSendDataSizeField(parseStoredSendData(send));
  return {
    id: send.id,
    type: Number(send.type) || 0,
    name: send.name,
    text: send.type === SendType.Text ? data : null,
    file: send.type === SendType.File ? data : null,
    expirationDate: send.expirationDate,
    creatorIdentifier,
    object: 'send-access',
  };
}

async function getCreatorIdentifier(storage: StorageService, send: Send): Promise<string | null> {
  if (send.hideEmail) return null;
  const owner = await storage.getUserById(send.userId);
  return owner?.email ?? null;
}

// GET /api/sends
export async function handleGetSends(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  const pagination = parsePagination(url);

  let sends: Send[];
  let continuationToken: string | null = null;
  if (pagination) {
    const pageRows = await storage.getSendsPage(userId, pagination.limit + 1, pagination.offset);
    const hasNext = pageRows.length > pagination.limit;
    sends = hasNext ? pageRows.slice(0, pagination.limit) : pageRows;
    continuationToken = hasNext ? encodeContinuationToken(pagination.offset + sends.length) : null;
  } else {
    sends = await storage.getAllSends(userId);
  }

  return jsonResponse({
    data: sends.map(sendToResponse),
    object: 'list',
    continuationToken,
  });
}

// GET /api/sends/:id
export async function handleGetSend(request: Request, env: Env, userId: string, sendId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const send = await storage.getSend(sendId);

  if (!send || send.userId !== userId) {
    return errorResponse('Send not found', 404);
  }

  return jsonResponse(sendToResponse(send));
}

// POST /api/sends
export async function handleCreateSend(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const typeRaw = getAliasedProp(body, ['type', 'Type']);
  const sendType = parseSendType(typeRaw.value);
  if (sendType === null) {
    return errorResponse('Invalid Send type', 400);
  }
  if (sendType === SendType.File) {
    return errorResponse('File sends should use /api/sends/file/v2', 400);
  }

  const nameRaw = getAliasedProp(body, ['name', 'Name']);
  const keyRaw = getAliasedProp(body, ['key', 'Key']);
  const deletionDateRaw = getAliasedProp(body, ['deletionDate', 'DeletionDate']);
  const textRaw = getAliasedProp(body, ['text', 'Text']);

  if (typeof nameRaw.value !== 'string' || !nameRaw.value.trim()) {
    return errorResponse('Name is required', 400);
  }
  if (typeof keyRaw.value !== 'string' || !keyRaw.value.trim()) {
    return errorResponse('Key is required', 400);
  }

  const deletionDate = parseDate(deletionDateRaw.value);
  if (!deletionDate) {
    return errorResponse('Invalid deletionDate', 400);
  }

  const deletionValidation = validateDeletionDate(deletionDate);
  if (deletionValidation) return deletionValidation;

  const sendData = sanitizeSendData(textRaw.value);
  if (!sendData) {
    return errorResponse('Send data not provided', 400);
  }

  const maxAccessRaw = getAliasedProp(body, ['maxAccessCount', 'MaxAccessCount']);
  const maxAccess = parseMaxAccessCount(maxAccessRaw.value);
  if (!maxAccess.ok) return maxAccess.response;

  const expirationRaw = getAliasedProp(body, ['expirationDate', 'ExpirationDate']);
  const expirationDate = expirationRaw.value === null || expirationRaw.value === undefined
    ? null
    : parseDate(expirationRaw.value);
  if (expirationRaw.value !== null && expirationRaw.value !== undefined && !expirationDate) {
    return errorResponse('Invalid expirationDate', 400);
  }

  const disabledRaw = getAliasedProp(body, ['disabled', 'Disabled']);
  const hideEmailRaw = getAliasedProp(body, ['hideEmail', 'HideEmail']);
  const notesRaw = getAliasedProp(body, ['notes', 'Notes']);
  const passwordRaw = getAliasedProp(body, ['password', 'Password']);

  const now = new Date().toISOString();
  const send: Send = {
    id: generateUUID(),
    userId,
    type: sendType,
    name: nameRaw.value.trim(),
    notes: typeof notesRaw.value === 'string' ? notesRaw.value : null,
    data: JSON.stringify(sendData),
    key: keyRaw.value,
    passwordHash: null,
    passwordSalt: null,
    passwordIterations: null,
    maxAccessCount: maxAccess.value,
    accessCount: 0,
    disabled: typeof disabledRaw.value === 'boolean' ? disabledRaw.value : false,
    hideEmail: typeof hideEmailRaw.value === 'boolean' ? hideEmailRaw.value : null,
    createdAt: now,
    updatedAt: now,
    expirationDate: expirationDate ? expirationDate.toISOString() : null,
    deletionDate: deletionDate.toISOString(),
  };

  if (typeof passwordRaw.value === 'string' && passwordRaw.value.length > 0) {
    await setSendPassword(send, passwordRaw.value);
  }

  await storage.saveSend(send);
  await storage.updateRevisionDate(userId);

  return jsonResponse(sendToResponse(send));
}

// POST /api/sends/file/v2
export async function handleCreateFileSendV2(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const typeRaw = getAliasedProp(body, ['type', 'Type']);
  const sendType = parseSendType(typeRaw.value);
  if (sendType !== SendType.File) {
    return errorResponse('Send content is not a file', 400);
  }

  const fileLengthRaw = getAliasedProp(body, ['fileLength', 'FileLength']);
  const fileLengthParsed = parseFileLength(fileLengthRaw.value);
  if (!fileLengthParsed.ok) return fileLengthParsed.response;
  if (fileLengthParsed.value > LIMITS.send.maxFileSizeBytes) {
    return errorResponse('Send storage limit exceeded with this file', 400);
  }

  const nameRaw = getAliasedProp(body, ['name', 'Name']);
  const keyRaw = getAliasedProp(body, ['key', 'Key']);
  const deletionDateRaw = getAliasedProp(body, ['deletionDate', 'DeletionDate']);
  const fileRaw = getAliasedProp(body, ['file', 'File']);

  if (typeof nameRaw.value !== 'string' || !nameRaw.value.trim()) {
    return errorResponse('Name is required', 400);
  }
  if (typeof keyRaw.value !== 'string' || !keyRaw.value.trim()) {
    return errorResponse('Key is required', 400);
  }

  const deletionDate = parseDate(deletionDateRaw.value);
  if (!deletionDate) {
    return errorResponse('Invalid deletionDate', 400);
  }
  const deletionValidation = validateDeletionDate(deletionDate);
  if (deletionValidation) return deletionValidation;

  const fileData = sanitizeSendData(fileRaw.value);
  if (!fileData) {
    return errorResponse('Send data not provided', 400);
  }

  const fileId = generateUUID();
  fileData.id = fileId;
  fileData.size = fileLengthParsed.value;
  fileData.sizeName = formatSize(fileLengthParsed.value);

  const maxAccessRaw = getAliasedProp(body, ['maxAccessCount', 'MaxAccessCount']);
  const maxAccess = parseMaxAccessCount(maxAccessRaw.value);
  if (!maxAccess.ok) return maxAccess.response;

  const expirationRaw = getAliasedProp(body, ['expirationDate', 'ExpirationDate']);
  const expirationDate = expirationRaw.value === null || expirationRaw.value === undefined
    ? null
    : parseDate(expirationRaw.value);
  if (expirationRaw.value !== null && expirationRaw.value !== undefined && !expirationDate) {
    return errorResponse('Invalid expirationDate', 400);
  }

  const disabledRaw = getAliasedProp(body, ['disabled', 'Disabled']);
  const hideEmailRaw = getAliasedProp(body, ['hideEmail', 'HideEmail']);
  const notesRaw = getAliasedProp(body, ['notes', 'Notes']);
  const passwordRaw = getAliasedProp(body, ['password', 'Password']);

  const now = new Date().toISOString();
  const send: Send = {
    id: generateUUID(),
    userId,
    type: sendType,
    name: nameRaw.value.trim(),
    notes: typeof notesRaw.value === 'string' ? notesRaw.value : null,
    data: JSON.stringify(fileData),
    key: keyRaw.value,
    passwordHash: null,
    passwordSalt: null,
    passwordIterations: null,
    maxAccessCount: maxAccess.value,
    accessCount: 0,
    disabled: typeof disabledRaw.value === 'boolean' ? disabledRaw.value : false,
    hideEmail: typeof hideEmailRaw.value === 'boolean' ? hideEmailRaw.value : null,
    createdAt: now,
    updatedAt: now,
    expirationDate: expirationDate ? expirationDate.toISOString() : null,
    deletionDate: deletionDate.toISOString(),
  };

  if (typeof passwordRaw.value === 'string' && passwordRaw.value.length > 0) {
    await setSendPassword(send, passwordRaw.value);
  }

  await storage.saveSend(send);
  await storage.updateRevisionDate(userId);

  return jsonResponse({
    fileUploadType: 0,
    object: 'send-fileUpload',
    url: `/api/sends/${send.id}/file/${fileId}`,
    sendResponse: sendToResponse(send),
  });
}

// POST /api/sends/:id/file/:fileId
export async function handleUploadSendFile(
  request: Request,
  env: Env,
  userId: string,
  sendId: string,
  fileId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const send = await storage.getSend(sendId);
  if (!send || send.userId !== userId) {
    return errorResponse('Send not found. Unable to save the file.', 404);
  }
  if (send.type !== SendType.File) {
    return errorResponse('Send is not a file type send.', 400);
  }

  const sendData = parseStoredSendData(send);
  const expectedFileId = typeof sendData.id === 'string' ? sendData.id : null;
  if (!expectedFileId || expectedFileId !== fileId) {
    return errorResponse('Send file does not match send data.', 400);
  }

  const contentType = request.headers.get('content-type') || '';
  if (!contentType.includes('multipart/form-data')) {
    return errorResponse('Content-Type must be multipart/form-data', 400);
  }

  const formData = await request.formData();
  const file = formData.get('data') as File | null;
  if (!file) {
    return errorResponse('No file uploaded', 400);
  }

  if (file.size > LIMITS.send.maxFileSizeBytes) {
    return errorResponse('Send storage limit exceeded with this file', 413);
  }

  const expectedFileName = typeof sendData.fileName === 'string' ? sendData.fileName : null;
  if (expectedFileName && file.name !== expectedFileName) {
    return errorResponse('Send file name does not match.', 400);
  }

  const expectedSize = parseInteger(sendData.size);
  if (expectedSize !== null && file.size !== expectedSize) {
    return errorResponse('Send file size does not match.', 400);
  }

  await env.ATTACHMENTS.put(getSendFilePath(sendId, fileId), file.stream(), {
    httpMetadata: {
      contentType: 'application/octet-stream',
    },
    customMetadata: {
      sendId,
      fileId,
    },
  });

  await storage.updateRevisionDate(userId);

  return new Response(null, { status: 200 });
}

// PUT /api/sends/:id
export async function handleUpdateSend(request: Request, env: Env, userId: string, sendId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const send = await storage.getSend(sendId);
  if (!send || send.userId !== userId) {
    return errorResponse('Send not found', 404);
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const typeRaw = getAliasedProp(body, ['type', 'Type']);
  if (typeRaw.present) {
    const incomingType = parseSendType(typeRaw.value);
    if (incomingType === null) {
      return errorResponse('Invalid Send type', 400);
    }
    if (incomingType !== send.type) {
      return errorResponse("Sends can't change type", 400);
    }
  }

  const deletionRaw = getAliasedProp(body, ['deletionDate', 'DeletionDate']);
  if (deletionRaw.present) {
    const deletionDate = parseDate(deletionRaw.value);
    if (!deletionDate) return errorResponse('Invalid deletionDate', 400);
    const deletionValidation = validateDeletionDate(deletionDate);
    if (deletionValidation) return deletionValidation;
    send.deletionDate = deletionDate.toISOString();
  }

  const expirationRaw = getAliasedProp(body, ['expirationDate', 'ExpirationDate']);
  if (expirationRaw.present) {
    if (expirationRaw.value === null || expirationRaw.value === '') {
      send.expirationDate = null;
    } else {
      const expiration = parseDate(expirationRaw.value);
      if (!expiration) return errorResponse('Invalid expirationDate', 400);
      send.expirationDate = expiration.toISOString();
    }
  }

  const nameRaw = getAliasedProp(body, ['name', 'Name']);
  if (nameRaw.present) {
    if (typeof nameRaw.value !== 'string' || !nameRaw.value.trim()) {
      return errorResponse('Name is required', 400);
    }
    send.name = nameRaw.value.trim();
  }

  const keyRaw = getAliasedProp(body, ['key', 'Key']);
  if (keyRaw.present) {
    if (typeof keyRaw.value !== 'string' || !keyRaw.value.trim()) {
      return errorResponse('Key is required', 400);
    }
    send.key = keyRaw.value;
  }

  const notesRaw = getAliasedProp(body, ['notes', 'Notes']);
  if (notesRaw.present) {
    send.notes = typeof notesRaw.value === 'string' ? notesRaw.value : null;
  }

  const disabledRaw = getAliasedProp(body, ['disabled', 'Disabled']);
  if (disabledRaw.present) {
    if (typeof disabledRaw.value !== 'boolean') {
      return errorResponse('Invalid disabled', 400);
    }
    send.disabled = disabledRaw.value;
  }

  const hideEmailRaw = getAliasedProp(body, ['hideEmail', 'HideEmail']);
  if (hideEmailRaw.present) {
    if (hideEmailRaw.value === null) {
      send.hideEmail = null;
    } else if (typeof hideEmailRaw.value === 'boolean') {
      send.hideEmail = hideEmailRaw.value;
    } else {
      return errorResponse('Invalid hideEmail', 400);
    }
  }

  const maxAccessRaw = getAliasedProp(body, ['maxAccessCount', 'MaxAccessCount']);
  if (maxAccessRaw.present) {
    const parsedMax = parseMaxAccessCount(maxAccessRaw.value);
    if (!parsedMax.ok) return parsedMax.response;
    send.maxAccessCount = parsedMax.value;
  }

  if (send.type === SendType.Text) {
    const textRaw = getAliasedProp(body, ['text', 'Text']);
    if (textRaw.present) {
      const textData = sanitizeSendData(textRaw.value);
      if (!textData) {
        return errorResponse('Send data not provided', 400);
      }
      send.data = JSON.stringify(textData);
    }
  }

  const passwordRaw = getAliasedProp(body, ['password', 'Password']);
  if (passwordRaw.present && typeof passwordRaw.value === 'string') {
    await setSendPassword(send, passwordRaw.value);
  }

  send.updatedAt = new Date().toISOString();
  await storage.saveSend(send);
  await storage.updateRevisionDate(userId);

  return jsonResponse(sendToResponse(send));
}

// DELETE /api/sends/:id
export async function handleDeleteSend(request: Request, env: Env, userId: string, sendId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const send = await storage.getSend(sendId);
  if (!send || send.userId !== userId) {
    return errorResponse('Send not found', 404);
  }

  if (send.type === SendType.File) {
    const data = parseStoredSendData(send);
    const fileId = typeof data.id === 'string' ? data.id : null;
    if (fileId) {
      await env.ATTACHMENTS.delete(getSendFilePath(send.id, fileId));
    }
  }

  await storage.deleteSend(sendId, userId);
  await storage.updateRevisionDate(userId);

  return new Response(null, { status: 200 });
}

// PUT /api/sends/:id/remove-password
export async function handleRemoveSendPassword(request: Request, env: Env, userId: string, sendId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const send = await storage.getSend(sendId);
  if (!send || send.userId !== userId) {
    return errorResponse('Send not found', 404);
  }

  await setSendPassword(send, null);
  send.updatedAt = new Date().toISOString();
  await storage.saveSend(send);
  await storage.updateRevisionDate(userId);

  return jsonResponse(sendToResponse(send));
}

// POST /api/sends/access/:accessId
export async function handleAccessSend(request: Request, env: Env, accessId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const sendId = fromAccessId(accessId);
  if (!sendId) {
    return errorResponse(SEND_INACCESSIBLE_MSG, 404);
  }

  const send = await storage.getSend(sendId);
  if (!send || !isSendAvailable(send)) {
    return errorResponse(SEND_INACCESSIBLE_MSG, 404);
  }

  let body: unknown = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  const passwordRaw = getAliasedProp(body, ['password', 'Password']);
  if (send.passwordHash) {
    if (typeof passwordRaw.value !== 'string') {
      return errorResponse('Password not provided', 401);
    }
    const validPassword = await verifySendPassword(send, passwordRaw.value);
    if (!validPassword) {
      return errorResponse('Invalid password', 400);
    }
  }

  if (send.type === SendType.Text) {
    send.accessCount += 1;
    send.updatedAt = new Date().toISOString();
    await storage.saveSend(send);
    await storage.updateRevisionDate(send.userId);
  }

  const creatorIdentifier = await getCreatorIdentifier(storage, send);
  return jsonResponse(sendToAccessResponse(send, creatorIdentifier));
}

// POST /api/sends/:sendId/access/file/:fileId
export async function handleAccessSendFile(
  request: Request,
  env: Env,
  sendId: string,
  fileId: string
): Promise<Response> {
  const secret = (env.JWT_SECRET || '').trim();
  if (!secret || secret.length < LIMITS.auth.jwtSecretMinLength || secret === DEFAULT_DEV_SECRET) {
    return errorResponse('Server configuration error', 500);
  }

  const storage = new StorageService(env.DB);
  const send = await storage.getSend(sendId);
  if (!send || !isSendAvailable(send) || send.type !== SendType.File) {
    return errorResponse(SEND_INACCESSIBLE_MSG, 404);
  }

  const data = parseStoredSendData(send);
  const expectedFileId = typeof data.id === 'string' ? data.id : null;
  if (!expectedFileId || expectedFileId !== fileId) {
    return errorResponse(SEND_INACCESSIBLE_MSG, 404);
  }

  let body: unknown = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  const passwordRaw = getAliasedProp(body, ['password', 'Password']);
  if (send.passwordHash) {
    if (typeof passwordRaw.value !== 'string') {
      return errorResponse('Password not provided', 401);
    }
    const validPassword = await verifySendPassword(send, passwordRaw.value);
    if (!validPassword) {
      return errorResponse('Invalid password', 400);
    }
  }

  send.accessCount += 1;
  send.updatedAt = new Date().toISOString();
  await storage.saveSend(send);
  await storage.updateRevisionDate(send.userId);

  const token = await createSendFileDownloadToken(sendId, fileId, secret);
  const url = new URL(request.url);
  const downloadUrl = `${url.origin}/api/sends/${sendId}/${fileId}?t=${token}`;

  return jsonResponse({
    object: 'send-fileDownload',
    id: fileId,
    url: downloadUrl,
  });
}

// GET /api/sends/:sendId/:fileId?t=...
export async function handleDownloadSendFile(
  request: Request,
  env: Env,
  sendId: string,
  fileId: string
): Promise<Response> {
  const secret = (env.JWT_SECRET || '').trim();
  if (!secret || secret.length < LIMITS.auth.jwtSecretMinLength || secret === DEFAULT_DEV_SECRET) {
    return errorResponse('Server configuration error', 500);
  }

  const url = new URL(request.url);
  const token = url.searchParams.get('t') || url.searchParams.get('token');
  if (!token) {
    return errorResponse('Token required', 401);
  }

  const claims = await verifySendFileDownloadToken(token, secret);
  if (!claims) {
    return errorResponse('Invalid or expired token', 401);
  }
  if (claims.sendId !== sendId || claims.fileId !== fileId) {
    return errorResponse('Token mismatch', 401);
  }

  const object = await env.ATTACHMENTS.get(getSendFilePath(sendId, fileId));
  if (!object) {
    return errorResponse('Send file not found', 404);
  }

  return new Response(object.body, {
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(object.size),
      'Cache-Control': 'private, no-cache',
    },
  });
}
