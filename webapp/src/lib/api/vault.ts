import { base64ToBytes, decryptBw, decryptBwFileData, decryptStr, encryptBw, encryptBwFileData } from '../crypto';
import type {
  Cipher,
  CipherPasswordHistoryEntry,
  Folder,
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
  uploadWithProgress,
  type AuthedFetch,
} from './shared';
import { readResponseBytesWithProgress } from '../download';
import { loadVaultSyncSnapshot } from './vault-sync';

export async function getFolders(authedFetch: AuthedFetch): Promise<Folder[]> {
  const body = await loadVaultSyncSnapshot(authedFetch);
  return body.folders || [];
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
  const body = await loadVaultSyncSnapshot(authedFetch);
  return body.ciphers || [];
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
  if (!session.accessToken) throw new Error('Unauthorized');

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

export async function repairCipherAttachmentMetadata(
  authedFetch: AuthedFetch,
  cipherId: string,
  attachmentId: string,
  metadata: { fileName?: string; key?: string | null }
): Promise<void> {
  const resp = await authedFetch(
    `/api/ciphers/${encodeURIComponent(cipherId)}/attachment/${encodeURIComponent(attachmentId)}/metadata`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(metadata),
    }
  );
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Update attachment metadata failed'));
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

async function decryptCipherStringWithKey(
  value: string,
  enc: Uint8Array,
  mac: Uint8Array
): Promise<Uint8Array | null> {
  try {
    return await decryptBw(value, enc, mac);
  } catch {
    return null;
  }
}

async function decryptAttachmentFileName(
  rawFileName: string,
  itemKeys: { enc: Uint8Array; mac: Uint8Array },
  userKeys: { enc: Uint8Array; mac: Uint8Array }
): Promise<{ fileName: string; source: 'plain' | 'item' | 'user' }> {
  const fallback = rawFileName || 'attachment.bin';
  if (!rawFileName || !looksLikeCipherString(rawFileName)) return { fileName: fallback, source: 'plain' };

  try {
    const fileName = await decryptStr(rawFileName, itemKeys.enc, itemKeys.mac);
    if (fileName) return { fileName, source: 'item' };
  } catch {
    // 继续尝试旧 user key 文件名。
  }

  if (!sameBytes(itemKeys.enc, userKeys.enc) || !sameBytes(itemKeys.mac, userKeys.mac)) {
    try {
      const fileName = await decryptStr(rawFileName, userKeys.enc, userKeys.mac);
      if (fileName) return { fileName, source: 'user' };
    } catch {
      // 保留原始文件名。
    }
  }

  return { fileName: fallback, source: 'plain' };
}

type AttachmentDecryptMode = 'attachment-item' | 'attachment-user' | 'legacy-item' | 'legacy-user';

interface AttachmentDecryptCandidate {
  mode: AttachmentDecryptMode;
  enc: Uint8Array;
  mac: Uint8Array;
  rawAttachmentKey: Uint8Array | null;
}

async function uploadRepairedAttachmentBlob(
  authedFetch: AuthedFetch,
  session: SessionState,
  cipherId: string,
  attachmentId: string,
  encryptedBytes: Uint8Array
): Promise<void> {
  if (!session.accessToken) throw new Error('Unauthorized');
  const payload = new ArrayBuffer(encryptedBytes.byteLength);
  new Uint8Array(payload).set(encryptedBytes);
  const resp = await uploadWithProgress(`/api/ciphers/${encodeURIComponent(cipherId)}/attachment/${encodeURIComponent(attachmentId)}`, {
    accessToken: session.accessToken,
    method: 'PUT',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: payload,
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Repair attachment upload failed'));
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
  const userKeys = { enc: userEnc, mac: userMac };

  const candidates: AttachmentDecryptCandidate[] = [];
  const keyCipher = String(info.key || '').trim();
  if (keyCipher && looksLikeCipherString(keyCipher)) {
    const itemWrappedKey = await decryptCipherStringWithKey(keyCipher, itemKeys.enc, itemKeys.mac);
    if (itemWrappedKey && itemWrappedKey.length >= 64) {
      candidates.push({
        mode: 'attachment-item',
        enc: itemWrappedKey.slice(0, 32),
        mac: itemWrappedKey.slice(32, 64),
        rawAttachmentKey: itemWrappedKey,
      });
    }

    if (!sameBytes(itemKeys.enc, userEnc) || !sameBytes(itemKeys.mac, userMac)) {
      const userWrappedKey = await decryptCipherStringWithKey(keyCipher, userEnc, userMac);
      if (userWrappedKey && userWrappedKey.length >= 64) {
        candidates.push({
          mode: 'attachment-user',
          enc: userWrappedKey.slice(0, 32),
          mac: userWrappedKey.slice(32, 64),
          rawAttachmentKey: userWrappedKey,
        });
      }
    }
  }
  candidates.push({ mode: 'legacy-item', enc: itemKeys.enc, mac: itemKeys.mac, rawAttachmentKey: null });
  if (!sameBytes(itemKeys.enc, userEnc) || !sameBytes(itemKeys.mac, userMac)) {
    candidates.push({ mode: 'legacy-user', enc: userEnc, mac: userMac, rawAttachmentKey: null });
  }

  let plainBytes: Uint8Array | null = null;
  let usedCandidate: AttachmentDecryptCandidate | null = null;
  for (const candidate of candidates) {
    try {
      plainBytes = await decryptBwFileData(encryptedBytes, candidate.enc, candidate.mac);
      usedCandidate = candidate;
      break;
    } catch {
      // 继续尝试下一种旧附件格式。
    }
  }
  if (!plainBytes || !usedCandidate) throw new Error('Attachment decryption failed');

  const fileNameRaw = String(info.fileName || '').trim();
  const nameResult = await decryptAttachmentFileName(fileNameRaw, itemKeys, userKeys);
  const fileName = nameResult.fileName || `attachment-${aid}`;

  try {
    const metadata: { fileName?: string; key?: string | null } = {};
    if (nameResult.source === 'user') {
      metadata.fileName = await encryptTextValue(fileName, itemKeys.enc, itemKeys.mac) || undefined;
    }

    if (usedCandidate.mode === 'attachment-user' && usedCandidate.rawAttachmentKey) {
      metadata.key = await encryptBw(usedCandidate.rawAttachmentKey, itemKeys.enc, itemKeys.mac);
    } else if (usedCandidate.mode === 'legacy-item') {
      metadata.key = null;
    } else if (usedCandidate.mode === 'legacy-user') {
      const repairedBytes = await encryptBwFileData(plainBytes, itemKeys.enc, itemKeys.mac);
      await uploadRepairedAttachmentBlob(authedFetch, session, cid, aid, repairedBytes);
      metadata.key = null;
    }

    if (Object.keys(metadata).length > 0) {
      await repairCipherAttachmentMetadata(authedFetch, cid, aid, metadata);
    }
  } catch {
    // 修复失败不影响本次下载，旧附件内容已经成功解密。
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

async function encryptPasswordHistory(
  entries: CipherPasswordHistoryEntry[] | null | undefined,
  enc: Uint8Array,
  mac: Uint8Array
): Promise<CipherPasswordHistoryEntry[] | null> {
  if (!Array.isArray(entries) || entries.length === 0) return null;

  const out: CipherPasswordHistoryEntry[] = [];
  for (const entry of entries) {
    const rawPassword = String(entry?.password || '');
    const plainPassword = entry?.decPassword ?? rawPassword;
    const encryptedPassword = looksLikeCipherString(rawPassword)
      ? rawPassword
      : await encryptTextValue(plainPassword, enc, mac);
    if (!encryptedPassword) continue;
    out.push({
      password: encryptedPassword,
      lastUsedDate: toIsoDateOrNow(entry?.lastUsedDate),
    });
  }

  return out.length ? out : null;
}

async function buildUpdatedPasswordHistory(
  cipher: Cipher | null,
  draft: VaultDraft,
  enc: Uint8Array,
  mac: Uint8Array
): Promise<CipherPasswordHistoryEntry[] | null> {
  const existingHistory = Array.isArray(cipher?.passwordHistory) ? cipher.passwordHistory : [];
  const currentPassword = String(cipher?.login?.decPassword || '');
  const nextPassword = String(draft.loginPassword || '');
  const passwordChanged = currentPassword !== nextPassword;
  const history = await encryptPasswordHistory(existingHistory, enc, mac);

  if (!passwordChanged || !currentPassword.trim()) {
    return history;
  }

  const encryptedCurrentPassword = await encryptTextValue(currentPassword, enc, mac);
  if (!encryptedCurrentPassword) {
    return history;
  }

  const nextEntries: CipherPasswordHistoryEntry[] = [
    {
      password: encryptedCurrentPassword,
      lastUsedDate: new Date().toISOString(),
    },
    ...(history || []),
  ];
  return nextEntries.slice(0, 5);
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
): Promise<Array<Record<string, unknown>>> {
  const out: Array<Record<string, unknown>> = [];
  for (const entry of uris || []) {
    const trimmed = String(entry?.uri || '').trim();
    if (!trimmed) continue;
    const preservedExtra =
      entry?.extra && typeof entry.extra === 'object'
        ? { ...entry.extra }
        : {};
    if (String(entry?.originalUri || '').trim() !== trimmed) {
      delete preservedExtra.uriChecksum;
    }
    out.push({
      ...preservedExtra,
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

async function encryptMaybeFidoValue(
  value: unknown,
  enc: Uint8Array,
  mac: Uint8Array,
  fallback = ''
): Promise<string> {
  const normalized = String(value ?? '').trim() || fallback;
  if (looksLikeCipherString(normalized)) return normalized;
  return encryptBw(new TextEncoder().encode(normalized), enc, mac);
}

async function encryptMaybeNullableFidoValue(
  value: unknown,
  enc: Uint8Array,
  mac: Uint8Array
): Promise<string | null> {
  const normalized = String(value ?? '').trim();
  if (!normalized) return null;
  if (looksLikeCipherString(normalized)) return normalized;
  return encryptBw(new TextEncoder().encode(normalized), enc, mac);
}

async function normalizeFido2Credentials(
  credentials: Array<Record<string, unknown>> | null | undefined,
  enc: Uint8Array,
  mac: Uint8Array
): Promise<Array<Record<string, unknown>> | null> {
  if (!Array.isArray(credentials) || credentials.length === 0) return null;
  const out: Array<Record<string, unknown>> = [];
  for (const credential of credentials) {
    if (!credential || typeof credential !== 'object') continue;
    out.push({
      credentialId: await encryptMaybeFidoValue(credential.credentialId, enc, mac),
      keyType: await encryptMaybeFidoValue(credential.keyType, enc, mac, 'public-key'),
      keyAlgorithm: await encryptMaybeFidoValue(credential.keyAlgorithm, enc, mac, 'ECDSA'),
      keyCurve: await encryptMaybeFidoValue(credential.keyCurve, enc, mac, 'P-256'),
      keyValue: await encryptMaybeFidoValue(credential.keyValue, enc, mac),
      rpId: await encryptMaybeFidoValue(credential.rpId, enc, mac),
      rpName: await encryptMaybeNullableFidoValue(credential.rpName, enc, mac),
      userHandle: await encryptMaybeNullableFidoValue(credential.userHandle, enc, mac),
      userName: await encryptMaybeNullableFidoValue(credential.userName, enc, mac),
      userDisplayName: await encryptMaybeNullableFidoValue(credential.userDisplayName, enc, mac),
      counter: await encryptMaybeFidoValue(credential.counter, enc, mac, '0'),
      discoverable: await encryptMaybeFidoValue(credential.discoverable, enc, mac, 'false'),
      creationDate: toIsoDateOrNow(credential.creationDate),
    });
  }
  return out.length ? out : null;
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
  const now = new Date().toISOString();

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
    passwordHistory: await encryptPasswordHistory(cipher?.passwordHistory, keys.enc, keys.mac),
  };

  if (cipher?.id) {
    payload.id = cipher.id;
    payload.key = keys.key;
  }

  if (type === 1) {
    const passwordChanged = String(cipher?.login?.decPassword || '') !== String(draft.loginPassword || '');
    const existingFido2 =
      cipher?.login && Array.isArray((cipher.login as any).fido2Credentials)
        ? (cipher.login as any).fido2Credentials
        : draft.loginFido2Credentials;
    const existingLogin =
      cipher?.login && typeof cipher.login === 'object'
        ? { ...(cipher.login as Record<string, unknown>) }
        : {};
    payload.login = {
      ...existingLogin,
      username: await encryptTextValue(draft.loginUsername, keys.enc, keys.mac),
      password: await encryptTextValue(draft.loginPassword, keys.enc, keys.mac),
      totp: await encryptTextValue(draft.loginTotp, keys.enc, keys.mac),
      passwordRevisionDate: passwordChanged ? now : existingLogin.passwordRevisionDate ?? null,
      fido2Credentials: await normalizeFido2Credentials(existingFido2, keys.enc, keys.mac),
      uris: await encryptUris(draft.loginUris || [], keys.enc, keys.mac),
    };
    payload.passwordHistory = await buildUpdatedPasswordHistory(cipher, draft, keys.enc, keys.mac);
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
