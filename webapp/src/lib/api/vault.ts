import { base64ToBytes, decryptBw, decryptBwFileData, decryptStr, encryptBw, encryptBwFileData } from '../crypto';
import type {
  Cipher,
  Folder,
  ListResponse,
  SessionState,
  VaultDraft,
  VaultDraftField,
} from '../types';
import {
  BULK_API_CHUNK_SIZE,
  chunkArray,
  parseErrorMessage,
  parseJson,
  uploadDirectEncryptedPayload,
  type AuthedFetch,
} from './shared';
import { readResponseBytesWithProgress } from '../download';

export async function getFolders(authedFetch: AuthedFetch): Promise<Folder[]> {
  const resp = await authedFetch('/api/folders');
  if (!resp.ok) throw new Error('Failed to load folders');
  const body = await parseJson<ListResponse<Folder>>(resp);
  return body?.data || [];
}

export async function createFolder(
  authedFetch: AuthedFetch,
  session: SessionState,
  name: string
): Promise<{ id: string; name?: string | null }> {
  if (!session.symEncKey || !session.symMacKey) throw new Error('Vault key unavailable');
  const enc = base64ToBytes(session.symEncKey);
  const mac = base64ToBytes(session.symMacKey);
  const encryptedName = await encryptBw(new TextEncoder().encode(name), enc, mac);
  const resp = await authedFetch('/api/folders', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: encryptedName }),
  });
  if (!resp.ok) throw new Error('Create folder failed');
  const body = await parseJson<{ id?: string; name?: string | null }>(resp);
  if (!body?.id) throw new Error('Create folder failed');
  return { id: body.id, name: body.name ?? null };
}

export async function encryptFolderImportName(session: SessionState, name: string): Promise<string> {
  if (!session.symEncKey || !session.symMacKey) throw new Error('Vault key unavailable');
  const enc = base64ToBytes(session.symEncKey);
  const mac = base64ToBytes(session.symMacKey);
  return encryptBw(new TextEncoder().encode(name), enc, mac);
}

export async function deleteFolder(authedFetch: AuthedFetch, folderId: string): Promise<void> {
  const id = String(folderId || '').trim();
  if (!id) throw new Error('Folder id is required');
  const resp = await authedFetch(`/api/folders/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  });
  if (!resp.ok) throw new Error('Delete folder failed');
}

export async function bulkDeleteFolders(authedFetch: AuthedFetch, ids: string[]): Promise<void> {
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  for (const chunk of chunkArray(uniqueIds, BULK_API_CHUNK_SIZE)) {
    const resp = await authedFetch('/api/folders/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: chunk }),
    });
    if (!resp.ok) throw new Error('Bulk delete folders failed');
  }
}

export async function updateFolder(
  authedFetch: AuthedFetch,
  session: SessionState,
  folderId: string,
  name: string
): Promise<void> {
  const id = String(folderId || '').trim();
  if (!id) throw new Error('Folder id is required');
  if (!session.symEncKey || !session.symMacKey) throw new Error('Vault key unavailable');
  const enc = base64ToBytes(session.symEncKey);
  const mac = base64ToBytes(session.symMacKey);
  const encryptedName = await encryptBw(new TextEncoder().encode(name), enc, mac);
  const resp = await authedFetch(`/api/folders/${encodeURIComponent(id)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: encryptedName }),
  });
  if (!resp.ok) throw new Error('Update folder failed');
}

export async function getCiphers(authedFetch: AuthedFetch): Promise<Cipher[]> {
  const resp = await authedFetch('/api/ciphers?deleted=true');
  if (!resp.ok) throw new Error('Failed to load ciphers');
  const body = await parseJson<ListResponse<Cipher>>(resp);
  return body?.data || [];
}

export interface CiphersImportPayload {
  ciphers: Array<Record<string, unknown>>;
  folders: Array<{ name: string }>;
  folderRelationships: Array<{ key: number; value: number }>;
}

export interface ImportedCipherMapEntry {
  index: number;
  sourceId: string | null;
  id: string;
}

const IMPORT_ITEM_LIMIT = 5000;

export async function importCiphers(
  authedFetch: AuthedFetch,
  payload: CiphersImportPayload,
  options?: { returnCipherMap?: boolean }
): Promise<ImportedCipherMapEntry[] | null> {
  const returnCipherMap = !!options?.returnCipherMap;
  const url = returnCipherMap ? '/api/ciphers/import?returnCipherMap=1' : '/api/ciphers/import';
  const totalItems = (payload.folders?.length || 0) + (payload.ciphers?.length || 0);
  if (totalItems > IMPORT_ITEM_LIMIT) {
    throw new Error(`Import exceeds maximum of ${IMPORT_ITEM_LIMIT} items`);
  }
  const resp = await authedFetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Import failed'));
  if (!returnCipherMap) return null;

  const body =
    (await parseJson<{
      cipherMap?: Array<{ index?: number; sourceId?: string | null; id?: string }>;
    }>(resp)) || {};
  if (!Array.isArray(body.cipherMap)) return [];

  const responses: ImportedCipherMapEntry[] = [];
  for (const row of body.cipherMap) {
    const index = Number(row?.index);
    const id = String(row?.id || '').trim();
    if (!Number.isFinite(index) || !id) continue;
    const sourceRaw = String(row?.sourceId || '').trim();
    responses.push({
      index,
      id,
      sourceId: sourceRaw || null,
    });
  }
  return responses;
}

export interface AttachmentDownloadInfo {
  id: string;
  url: string;
  fileName: string | null;
  key: string | null;
  size: string | null;
  sizeName: string | null;
}

export async function getAttachmentDownloadInfo(
  authedFetch: AuthedFetch,
  cipherId: string,
  attachmentId: string
): Promise<AttachmentDownloadInfo> {
  const resp = await authedFetch(`/api/ciphers/${encodeURIComponent(cipherId)}/attachment/${encodeURIComponent(attachmentId)}`);
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Failed to load attachment'));
  const body =
    (await parseJson<{
      id?: string;
      url?: string;
      fileName?: string | null;
      key?: string | null;
      size?: string | null;
      sizeName?: string | null;
    }>(resp)) || {};
  const id = String(body.id || attachmentId || '').trim();
  const url = String(body.url || '').trim();
  if (!id || !url) throw new Error('Invalid attachment download response');
  return {
    id,
    url,
    fileName: body.fileName ?? null,
    key: body.key ?? null,
    size: body.size ?? null,
    sizeName: body.sizeName ?? null,
  };
}

function looksLikeCipherString(value: unknown): boolean {
  return /^\d+\.[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+(?:\|[A-Za-z0-9+/=]+)?$/.test(String(value || '').trim());
}

export async function uploadCipherAttachment(
  authedFetch: AuthedFetch,
  session: SessionState,
  cipherId: string,
  file: File,
  cipherForKey?: Cipher | null,
  onProgress?: (percent: number | null) => void
): Promise<void> {
  if (!session.symEncKey || !session.symMacKey) throw new Error('Vault key unavailable');
  const id = String(cipherId || '').trim();
  if (!id) throw new Error('Cipher id is required');
  if (!file) throw new Error('File is required');

  const userEnc = base64ToBytes(session.symEncKey);
  const userMac = base64ToBytes(session.symMacKey);
  const itemKeys = await getCipherKeys(cipherForKey || null, userEnc, userMac);

  const encryptedFileName = await encryptTextValue(file.name, itemKeys.enc, itemKeys.mac);
  if (!encryptedFileName) throw new Error('Invalid attachment name');

  const attachmentRawKey = crypto.getRandomValues(new Uint8Array(64));
  const attachmentWrappedKey = await encryptBw(attachmentRawKey, itemKeys.enc, itemKeys.mac);
  const fileBytes = new Uint8Array(await file.arrayBuffer());
  const encryptedBytes = await encryptBwFileData(fileBytes, attachmentRawKey.slice(0, 32), attachmentRawKey.slice(32, 64));

  const metaResp = await authedFetch(`/api/ciphers/${encodeURIComponent(id)}/attachment/v2`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      fileName: encryptedFileName,
      key: attachmentWrappedKey,
      fileSize: encryptedBytes.byteLength,
    }),
  });
  if (!metaResp.ok) throw new Error(await parseErrorMessage(metaResp, 'Create attachment failed'));

  const meta =
    (await parseJson<{
      attachmentId?: string;
      url?: string;
      fileUploadType?: number;
    }>(metaResp)) || {};
  const attachmentId = String(meta.attachmentId || '').trim();
  const uploadUrl = String(meta.url || '').trim();
  if (!attachmentId || !uploadUrl) throw new Error('Create attachment failed');

  const payload = new ArrayBuffer(encryptedBytes.byteLength);
  new Uint8Array(payload).set(encryptedBytes);
  const uploadResp = await uploadDirectEncryptedPayload({
    accessToken: session.accessToken,
    uploadUrl,
    payload,
    fileUploadType: meta.fileUploadType,
    unsupportedMessage: 'Unsupported attachment upload type',
    onProgress,
  });
  if (!uploadResp.ok) {
    try {
      await authedFetch(`/api/ciphers/${encodeURIComponent(id)}/attachment/${encodeURIComponent(attachmentId)}`, { method: 'DELETE' });
    } catch {
      // ignore rollback failure
    }
    throw new Error(await parseErrorMessage(uploadResp, 'Upload attachment failed'));
  }
}

export async function deleteCipherAttachment(
  authedFetch: AuthedFetch,
  cipherId: string,
  attachmentId: string
): Promise<void> {
  const cid = String(cipherId || '').trim();
  const aid = String(attachmentId || '').trim();
  if (!cid || !aid) throw new Error('Attachment id is required');
  const resp = await authedFetch(`/api/ciphers/${encodeURIComponent(cid)}/attachment/${encodeURIComponent(aid)}`, {
    method: 'DELETE',
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Delete attachment failed'));
}

export async function downloadCipherAttachmentDecrypted(
  authedFetch: AuthedFetch,
  session: SessionState,
  cipher: Cipher,
  attachmentId: string,
  onProgress?: (percent: number | null) => void
): Promise<{ fileName: string; bytes: Uint8Array }> {
  if (!session.symEncKey || !session.symMacKey) throw new Error('Vault key unavailable');
  const cid = String(cipher?.id || '').trim();
  const aid = String(attachmentId || '').trim();
  if (!cid || !aid) throw new Error('Attachment id is required');

  const info = await getAttachmentDownloadInfo(authedFetch, cid, aid);
  const rawResp = await fetch(info.url, { cache: 'no-store' });
  if (!rawResp.ok) throw new Error('Download attachment failed');
  const encryptedBytes = await readResponseBytesWithProgress(rawResp, (progress) => onProgress?.(progress.percent));

  const userEnc = base64ToBytes(session.symEncKey);
  const userMac = base64ToBytes(session.symMacKey);
  const itemKeys = await getCipherKeys(cipher, userEnc, userMac);

  let fileEnc = itemKeys.enc;
  let fileMac = itemKeys.mac;
  const keyCipher = String(info.key || '').trim();
  if (keyCipher && looksLikeCipherString(keyCipher)) {
    try {
      const fileRawKey = await decryptBw(keyCipher, itemKeys.enc, itemKeys.mac);
      if (fileRawKey.length >= 64) {
        fileEnc = fileRawKey.slice(0, 32);
        fileMac = fileRawKey.slice(32, 64);
      }
    } catch {
      // fallback to item key
    }
  }

  const plainBytes = await decryptBwFileData(encryptedBytes, fileEnc, fileMac);

  const fileNameRaw = String(info.fileName || '').trim();
  let fileName = fileNameRaw || `attachment-${aid}`;
  if (fileNameRaw && looksLikeCipherString(fileNameRaw)) {
    try {
      fileName = (await decryptStr(fileNameRaw, itemKeys.enc, itemKeys.mac)) || fileName;
    } catch {
      // keep fallback name
    }
  }

  return { fileName, bytes: plainBytes };
}

function asNullable(v: string): string | null {
  const s = String(v || '').trim();
  return s ? s : null;
}

function parseFieldType(v: number | string): 0 | 1 | 2 | 3 {
  if (typeof v === 'number') {
    if (v === 1 || v === 2 || v === 3) return v;
    return 0;
  }
  const s = String(v).trim().toLowerCase();
  if (s === '1' || s === 'hidden') return 1;
  if (s === '2' || s === 'boolean' || s === 'checkbox') return 2;
  if (s === '3' || s === 'linked' || s === 'link') return 3;
  return 0;
}

async function encryptTextValue(value: string, enc: Uint8Array, mac: Uint8Array): Promise<string | null> {
  const s = String(value || '');
  if (!s.trim()) return null;
  return encryptBw(new TextEncoder().encode(s), enc, mac);
}

async function encryptCustomFields(
  fields: VaultDraftField[],
  enc: Uint8Array,
  mac: Uint8Array
): Promise<Array<{ type: number; name: string | null; value: string | null }>> {
  const out: Array<{ type: number; name: string | null; value: string | null }> = [];
  for (const field of fields || []) {
    const label = String(field.label || '').trim();
    if (!label) continue;
    out.push({
      type: parseFieldType(field.type),
      name: await encryptTextValue(label, enc, mac),
      value: await encryptTextValue(String(field.value || ''), enc, mac),
    });
  }
  return out;
}

async function encryptUris(
  uris: VaultDraft['loginUris'],
  enc: Uint8Array,
  mac: Uint8Array
): Promise<Array<{ uri: string | null; match: number | null }>> {
  const out: Array<{ uri: string | null; match: number | null }> = [];
  for (const entry of uris || []) {
    const trimmed = String(entry?.uri || '').trim();
    if (!trimmed) continue;
    out.push({
      uri: await encryptTextValue(trimmed, enc, mac),
      match: typeof entry?.match === 'number' && Number.isFinite(entry.match) ? entry.match : null,
    });
  }
  return out;
}

function toIsoDateOrNow(value: unknown): string {
  const raw = String(value ?? '').trim();
  if (!raw) return new Date().toISOString();
  const parsed = new Date(raw);
  if (!Number.isFinite(parsed.getTime())) return new Date().toISOString();
  return parsed.toISOString();
}

async function getCipherKeys(
  cipher: Cipher | null,
  userEnc: Uint8Array,
  userMac: Uint8Array
): Promise<{ enc: Uint8Array; mac: Uint8Array; key: string | null }> {
  if (cipher?.key) {
    try {
      const raw = await decryptBw(cipher.key, userEnc, userMac);
      if (raw.length >= 64) return { enc: raw.slice(0, 32), mac: raw.slice(32, 64), key: cipher.key };
    } catch {
      // use user key
    }
  }
  return { enc: userEnc, mac: userMac, key: null };
}

async function buildCipherPayload(
  session: SessionState,
  draft: VaultDraft,
  cipher: Cipher | null
): Promise<Record<string, unknown>> {
  if (!session.symEncKey || !session.symMacKey) throw new Error('Vault key unavailable');
  const userEnc = base64ToBytes(session.symEncKey);
  const userMac = base64ToBytes(session.symMacKey);
  const keys = await getCipherKeys(cipher, userEnc, userMac);
  const type = Number(draft.type || cipher?.type || 1);

  const payload: Record<string, unknown> = {
    type,
    favorite: !!draft.favorite,
    folderId: asNullable(draft.folderId),
    reprompt: draft.reprompt ? 1 : 0,
    name: await encryptTextValue(draft.name, keys.enc, keys.mac),
    notes: await encryptTextValue(draft.notes, keys.enc, keys.mac),
    login: null,
    card: null,
    identity: null,
    secureNote: null,
    sshKey: null,
    fields: await encryptCustomFields(draft.customFields || [], keys.enc, keys.mac),
  };

  if (cipher?.id) {
    payload.id = cipher.id;
    payload.key = keys.key;
  }

  if (type === 1) {
    payload.login = {
      username: await encryptTextValue(draft.loginUsername, keys.enc, keys.mac),
      password: await encryptTextValue(draft.loginPassword, keys.enc, keys.mac),
      totp: await encryptTextValue(draft.loginTotp, keys.enc, keys.mac),
      uris: await encryptUris(draft.loginUris || [], keys.enc, keys.mac),
    };
  } else if (type === 3) {
    payload.card = {
      cardholderName: await encryptTextValue(draft.cardholderName, keys.enc, keys.mac),
      number: await encryptTextValue(draft.cardNumber, keys.enc, keys.mac),
      brand: await encryptTextValue(draft.cardBrand, keys.enc, keys.mac),
      expMonth: await encryptTextValue(draft.cardExpMonth, keys.enc, keys.mac),
      expYear: await encryptTextValue(draft.cardExpYear, keys.enc, keys.mac),
      code: await encryptTextValue(draft.cardCode, keys.enc, keys.mac),
    };
  } else if (type === 4) {
    payload.identity = {
      title: await encryptTextValue(draft.identTitle, keys.enc, keys.mac),
      firstName: await encryptTextValue(draft.identFirstName, keys.enc, keys.mac),
      middleName: await encryptTextValue(draft.identMiddleName, keys.enc, keys.mac),
      lastName: await encryptTextValue(draft.identLastName, keys.enc, keys.mac),
      username: await encryptTextValue(draft.identUsername, keys.enc, keys.mac),
      company: await encryptTextValue(draft.identCompany, keys.enc, keys.mac),
      ssn: await encryptTextValue(draft.identSsn, keys.enc, keys.mac),
      passportNumber: await encryptTextValue(draft.identPassportNumber, keys.enc, keys.mac),
      licenseNumber: await encryptTextValue(draft.identLicenseNumber, keys.enc, keys.mac),
      email: await encryptTextValue(draft.identEmail, keys.enc, keys.mac),
      phone: await encryptTextValue(draft.identPhone, keys.enc, keys.mac),
      address1: await encryptTextValue(draft.identAddress1, keys.enc, keys.mac),
      address2: await encryptTextValue(draft.identAddress2, keys.enc, keys.mac),
      address3: await encryptTextValue(draft.identAddress3, keys.enc, keys.mac),
      city: await encryptTextValue(draft.identCity, keys.enc, keys.mac),
      state: await encryptTextValue(draft.identState, keys.enc, keys.mac),
      postalCode: await encryptTextValue(draft.identPostalCode, keys.enc, keys.mac),
      country: await encryptTextValue(draft.identCountry, keys.enc, keys.mac),
    };
  } else if (type === 5) {
    const encryptedFingerprint = await encryptTextValue(draft.sshFingerprint, keys.enc, keys.mac);
    payload.sshKey = {
      privateKey: await encryptTextValue(draft.sshPrivateKey, keys.enc, keys.mac),
      publicKey: await encryptTextValue(draft.sshPublicKey, keys.enc, keys.mac),
      keyFingerprint: encryptedFingerprint,
      fingerprint: encryptedFingerprint,
    };
  } else if (type === 2) {
    payload.secureNote = { type: 0 };
  }

  return payload;
}

export async function buildCipherImportPayload(session: SessionState, draft: VaultDraft): Promise<Record<string, unknown>> {
  return buildCipherPayload(session, draft, null);
}

export async function createCipher(
  authedFetch: AuthedFetch,
  session: SessionState,
  draft: VaultDraft
): Promise<{ id: string }> {
  const payload = await buildCipherPayload(session, draft, null);

  const resp = await authedFetch('/api/ciphers', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) throw new Error('Create item failed');
  const body = await parseJson<{ id?: string }>(resp);
  if (!body?.id) throw new Error('Create item failed');
  return { id: body.id };
}

export async function updateCipher(
  authedFetch: AuthedFetch,
  session: SessionState,
  cipher: Cipher,
  draft: VaultDraft
): Promise<void> {
  const payload = await buildCipherPayload(session, draft, cipher);

  const resp = await authedFetch(`/api/ciphers/${encodeURIComponent(cipher.id)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) throw new Error('Update item failed');
}

export async function deleteCipher(authedFetch: AuthedFetch, cipherId: string): Promise<void> {
  const resp = await authedFetch(`/api/ciphers/${encodeURIComponent(cipherId)}`, { method: 'DELETE' });
  if (!resp.ok) throw new Error('Delete item failed');
}

export async function archiveCipher(authedFetch: AuthedFetch, cipherId: string): Promise<void> {
  const id = String(cipherId || '').trim();
  if (!id) throw new Error('Cipher id is required');
  const resp = await authedFetch(`/api/ciphers/${encodeURIComponent(id)}/archive`, { method: 'PUT' });
  if (!resp.ok) throw new Error('Archive item failed');
}

export async function unarchiveCipher(authedFetch: AuthedFetch, cipherId: string): Promise<void> {
  const id = String(cipherId || '').trim();
  if (!id) throw new Error('Cipher id is required');
  const resp = await authedFetch(`/api/ciphers/${encodeURIComponent(id)}/unarchive`, { method: 'PUT' });
  if (!resp.ok) throw new Error('Unarchive item failed');
}

export async function bulkDeleteCiphers(authedFetch: AuthedFetch, ids: string[]): Promise<void> {
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  for (const chunk of chunkArray(uniqueIds, BULK_API_CHUNK_SIZE)) {
    const resp = await authedFetch('/api/ciphers/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: chunk }),
    });
    if (!resp.ok) throw new Error('Bulk delete failed');
  }
}

export async function bulkArchiveCiphers(authedFetch: AuthedFetch, ids: string[]): Promise<void> {
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  for (const chunk of chunkArray(uniqueIds, BULK_API_CHUNK_SIZE)) {
    const resp = await authedFetch('/api/ciphers/archive', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: chunk }),
    });
    if (!resp.ok) throw new Error('Bulk archive failed');
  }
}

export async function bulkPermanentDeleteCiphers(authedFetch: AuthedFetch, ids: string[]): Promise<void> {
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  for (const chunk of chunkArray(uniqueIds, BULK_API_CHUNK_SIZE)) {
    const resp = await authedFetch('/api/ciphers/delete-permanent', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: chunk }),
    });
    if (!resp.ok) throw new Error('Bulk permanent delete failed');
  }
}

export async function bulkRestoreCiphers(authedFetch: AuthedFetch, ids: string[]): Promise<void> {
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  for (const chunk of chunkArray(uniqueIds, BULK_API_CHUNK_SIZE)) {
    const resp = await authedFetch('/api/ciphers/restore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: chunk }),
    });
    if (!resp.ok) throw new Error('Bulk restore failed');
  }
}

export async function bulkUnarchiveCiphers(authedFetch: AuthedFetch, ids: string[]): Promise<void> {
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  for (const chunk of chunkArray(uniqueIds, BULK_API_CHUNK_SIZE)) {
    const resp = await authedFetch('/api/ciphers/unarchive', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: chunk }),
    });
    if (!resp.ok) throw new Error('Bulk unarchive failed');
  }
}

export async function bulkMoveCiphers(
  authedFetch: AuthedFetch,
  ids: string[],
  folderId: string | null
): Promise<void> {
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  for (const chunk of chunkArray(uniqueIds, BULK_API_CHUNK_SIZE)) {
    const resp = await authedFetch('/api/ciphers/move', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: chunk, folderId }),
    });
    if (!resp.ok) throw new Error('Bulk move failed');
  }
}
