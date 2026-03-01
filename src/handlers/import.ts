import { Env, Cipher, Folder, CipherType } from '../types';
import { StorageService } from '../services/storage';
import { errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { LIMITS } from '../config/limits';
import { normalizeCipherLoginForCompatibility } from './ciphers';

// Bitwarden client import request format
interface CiphersImportRequest {
  ciphers: Array<{
    type: number;
    name?: string | null;
    notes?: string | null;
    favorite?: boolean;
    reprompt?: number;
    sshKey?: any | null;
    key?: string | null;
    login?: {
      uris?: Array<{ uri: string | null; match?: number | null }> | null;
      username?: string | null;
      password?: string | null;
      totp?: string | null;
      autofillOnPageLoad?: boolean | null;
      fido2Credentials?: any[] | null;
      uri?: string | null;
      passwordRevisionDate?: string | null;
      [key: string]: any;
    } | null;
    card?: {
      cardholderName?: string | null;
      brand?: string | null;
      number?: string | null;
      expMonth?: string | null;
      expYear?: string | null;
      code?: string | null;
    } | null;
    identity?: {
      title?: string | null;
      firstName?: string | null;
      middleName?: string | null;
      lastName?: string | null;
      address1?: string | null;
      address2?: string | null;
      address3?: string | null;
      city?: string | null;
      state?: string | null;
      postalCode?: string | null;
      country?: string | null;
      company?: string | null;
      email?: string | null;
      phone?: string | null;
      ssn?: string | null;
      username?: string | null;
      passportNumber?: string | null;
      licenseNumber?: string | null;
    } | null;
    secureNote?: { type: number } | null;
    fields?: Array<{
      name?: string | null;
      value?: string | null;
      type: number;
      linkedId?: number | null;
    }> | null;
    passwordHistory?: Array<{
      password: string;
      lastUsedDate: string;
    }> | null;
    [key: string]: any;
  }>;
  folders: Array<{
    name: string;
  }>;
  folderRelationships: Array<{
    key: number;   // cipher index
    value: number; // folder index
  }>;
}

function bindNull(v: any): any {
  return v === undefined ? null : v;
}

async function runBatchInChunks(db: D1Database, statements: D1PreparedStatement[], chunkSize: number): Promise<void> {
  for (let i = 0; i < statements.length; i += chunkSize) {
    const chunk = statements.slice(i, i + chunkSize);
    await db.batch(chunk);
  }
}

// POST /api/ciphers/import - Bitwarden client import endpoint
export async function handleCiphersImport(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let importData: CiphersImportRequest;
  try {
    importData = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const folders = importData.folders || [];
  const ciphers = importData.ciphers || [];
  const folderRelationships = importData.folderRelationships || [];

  if (folders.length + ciphers.length > LIMITS.performance.importItemLimit) {
    return errorResponse(`Import exceeds maximum of ${LIMITS.performance.importItemLimit} items`, 400);
  }

  const now = new Date().toISOString();
  const batchChunkSize = LIMITS.performance.bulkMoveChunkSize;

  // Create folders and build index -> id mapping
  const folderIdMap = new Map<number, string>();
  const folderRows: Folder[] = [];
  
  for (let i = 0; i < folders.length; i++) {
    const folderId = generateUUID();
    folderIdMap.set(i, folderId);

    const folder: Folder = {
      id: folderId,
      userId: userId,
      name: folders[i].name,
      createdAt: now,
      updatedAt: now,
    };

    folderRows.push(folder);
  }

  if (folderRows.length > 0) {
    const folderStatements = folderRows.map(folder =>
      env.DB
        .prepare(
          'INSERT INTO folders(id, user_id, name, created_at, updated_at) VALUES(?, ?, ?, ?, ?) ' +
          'ON CONFLICT(id) DO UPDATE SET user_id=excluded.user_id, name=excluded.name, updated_at=excluded.updated_at'
        )
        .bind(folder.id, folder.userId, folder.name, folder.createdAt, folder.updatedAt)
    );
    await runBatchInChunks(env.DB, folderStatements, batchChunkSize);
  }

  // Build cipher index -> folder id mapping from relationships
  const cipherFolderMap = new Map<number, string>();
  for (const rel of folderRelationships) {
    const folderId = folderIdMap.get(rel.value);
    if (folderId) {
      cipherFolderMap.set(rel.key, folderId);
    }
  }

  // Create ciphers
  const cipherRows: Cipher[] = [];
  for (let i = 0; i < ciphers.length; i++) {
    const c = ciphers[i];
    const folderId = cipherFolderMap.get(i) || null;

    const cipher: Cipher = {
      ...c,
      id: generateUUID(),
      userId: userId,
      type: c.type as CipherType,
      folderId: folderId,
      name: c.name ?? 'Untitled',
      notes: c.notes ?? null,
      favorite: c.favorite ?? false,
      login: c.login ? {
        ...c.login,
        username: c.login.username ?? null,
        password: c.login.password ?? null,
        uris: c.login.uris?.map(u => ({
          ...u,
          uri: u.uri ?? null,
          uriChecksum: null,
          match: u.match ?? null,
        })) || null,
        totp: c.login.totp ?? null,
        autofillOnPageLoad: c.login.autofillOnPageLoad ?? null,
        fido2Credentials: c.login.fido2Credentials ?? null,
        uri: c.login.uri ?? null,
        passwordRevisionDate: c.login.passwordRevisionDate ?? null,
      } : null,
      card: c.card ? {
        ...c.card,
        cardholderName: c.card.cardholderName ?? null,
        brand: c.card.brand ?? null,
        number: c.card.number ?? null,
        expMonth: c.card.expMonth ?? null,
        expYear: c.card.expYear ?? null,
        code: c.card.code ?? null,
      } : null,
      identity: c.identity ? {
        ...c.identity,
        title: c.identity.title ?? null,
        firstName: c.identity.firstName ?? null,
        middleName: c.identity.middleName ?? null,
        lastName: c.identity.lastName ?? null,
        address1: c.identity.address1 ?? null,
        address2: c.identity.address2 ?? null,
        address3: c.identity.address3 ?? null,
        city: c.identity.city ?? null,
        state: c.identity.state ?? null,
        postalCode: c.identity.postalCode ?? null,
        country: c.identity.country ?? null,
        company: c.identity.company ?? null,
        email: c.identity.email ?? null,
        phone: c.identity.phone ?? null,
        ssn: c.identity.ssn ?? null,
        username: c.identity.username ?? null,
        passportNumber: c.identity.passportNumber ?? null,
        licenseNumber: c.identity.licenseNumber ?? null,
      } : null,
      secureNote: c.secureNote ?? null,
      fields: c.fields?.map(f => ({
        ...f,
        name: f.name ?? null,
        value: f.value ?? null,
        type: f.type,
        linkedId: f.linkedId ?? null,
      })) || null,
      passwordHistory: c.passwordHistory ?? null,
      reprompt: c.reprompt ?? 0,
      sshKey: (c as any).sshKey ?? null,
      key: (c as any).key ?? null,
      createdAt: now,
      updatedAt: now,
      deletedAt: null,
    };
    cipher.login = normalizeCipherLoginForCompatibility(cipher.login);

    cipherRows.push(cipher);
  }

  if (cipherRows.length > 0) {
    const cipherStatements = cipherRows.map(cipher => {
      const data = JSON.stringify(cipher);
      return env.DB
        .prepare(
          'INSERT INTO ciphers(id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, deleted_at) ' +
          'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
          'ON CONFLICT(id) DO UPDATE SET ' +
          'user_id=excluded.user_id, type=excluded.type, folder_id=excluded.folder_id, name=excluded.name, notes=excluded.notes, favorite=excluded.favorite, data=excluded.data, reprompt=excluded.reprompt, key=excluded.key, updated_at=excluded.updated_at, deleted_at=excluded.deleted_at'
        )
        .bind(
          cipher.id,
          cipher.userId,
          Number(cipher.type) || 1,
          bindNull(cipher.folderId),
          bindNull(cipher.name),
          bindNull(cipher.notes),
          cipher.favorite ? 1 : 0,
          data,
          bindNull(cipher.reprompt ?? 0),
          bindNull(cipher.key),
          cipher.createdAt,
          cipher.updatedAt,
          bindNull(cipher.deletedAt)
        );
    });
    await runBatchInChunks(env.DB, cipherStatements, batchChunkSize);
  }

  // Update revision date
  await storage.updateRevisionDate(userId);

  return new Response(null, { status: 200 });
}
