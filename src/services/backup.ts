import { Uint8ArrayReader, Uint8ArrayWriter, ZipWriter } from '@zip.js/zip.js';
import { Env, Cipher, Folder, Attachment } from '../types';
import { StorageService } from './storage';

interface ExportCipher {
  type: number;
  name: string;
  notes: string | null;
  favorite: boolean;
  reprompt: number;
  login: Cipher['login'];
  card: Cipher['card'];
  identity: Cipher['identity'];
  secureNote: Cipher['secureNote'];
  fields: Cipher['fields'];
  passwordHistory: Cipher['passwordHistory'];
}

interface ExportPayload {
  encrypted: boolean;
  folders: Array<{ name: string }>;
  ciphers: ExportCipher[];
  folderRelationships: Array<{ key: number; value: number }>;
}

function parseBool(value: string | undefined, defaultValue: boolean): boolean {
  if (!value) return defaultValue;
  const normalized = value.trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on';
}

function parsePositiveInt(value: string | undefined, defaultValue: number): number {
  if (!value) return defaultValue;
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n) || n < 1) return defaultValue;
  return n;
}

function normalizePrefix(prefix: string | undefined): string {
  const value = (prefix || 'backups/').trim() || 'backups/';
  return value.endsWith('/') ? value : `${value}/`;
}

function makeTimestamp(date: Date): string {
  const y = date.getUTCFullYear();
  const m = String(date.getUTCMonth() + 1).padStart(2, '0');
  const d = String(date.getUTCDate()).padStart(2, '0');
  const hh = String(date.getUTCHours()).padStart(2, '0');
  const mm = String(date.getUTCMinutes()).padStart(2, '0');
  const ss = String(date.getUTCSeconds()).padStart(2, '0');
  return `${y}${m}${d}-${hh}${mm}${ss}`;
}

function makeDatePath(date: Date): string {
  const y = date.getUTCFullYear();
  const m = String(date.getUTCMonth() + 1).padStart(2, '0');
  return `${y}/${m}`;
}

function textBytes(input: string): Uint8Array {
  return new TextEncoder().encode(input);
}

function sanitizePathSegment(name: string): string {
  return name.replace(/[\\/:*?"<>|\u0000-\u001F]/g, '_').trim() || 'file';
}

async function getSingleUserId(db: D1Database): Promise<string | null> {
  const row = await db.prepare('SELECT id FROM users LIMIT 1').first<{ id: string }>();
  return row?.id || null;
}

function toExportCipher(cipher: Cipher): ExportCipher {
  return {
    type: Number(cipher.type) || 1,
    name: cipher.name || 'Untitled',
    notes: cipher.notes,
    favorite: cipher.favorite,
    reprompt: cipher.reprompt || 0,
    login: cipher.login,
    card: cipher.card,
    identity: cipher.identity,
    secureNote: cipher.secureNote,
    fields: cipher.fields,
    passwordHistory: cipher.passwordHistory,
  };
}

function buildExportPayload(ciphers: Cipher[], folders: Folder[]): ExportPayload {
  const folderIndexById = new Map<string, number>();
  const exportFolders = folders.map((folder, idx) => {
    folderIndexById.set(folder.id, idx);
    return { name: folder.name };
  });

  const exportCiphers: ExportCipher[] = [];
  const folderRelationships: Array<{ key: number; value: number }> = [];

  for (let i = 0; i < ciphers.length; i++) {
    const cipher = ciphers[i];
    exportCiphers.push(toExportCipher(cipher));
    if (cipher.folderId) {
      const folderIdx = folderIndexById.get(cipher.folderId);
      if (folderIdx !== undefined) {
        folderRelationships.push({ key: i, value: folderIdx });
      }
    }
  }

  return {
    encrypted: false,
    folders: exportFolders,
    ciphers: exportCiphers,
    folderRelationships,
  };
}

function makeAttachmentPath(c: Cipher, a: Attachment): string {
  const safeName = sanitizePathSegment(a.fileName || a.id);
  return `attachments/${c.id}/${a.id}-${safeName}`;
}

async function saveBackupStatus(db: D1Database, key: string, value: string): Promise<void> {
  await db.prepare(
    'INSERT INTO config(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
  ).bind(key, value).run();
}

export async function runScheduledBackup(env: Env): Promise<void> {
  const enabled = parseBool(env.BACKUP_ENABLED, true);
  if (!enabled) {
    console.log('Backup skipped: BACKUP_ENABLED is false');
    return;
  }

  const password = (env.BACKUP_PASSWORD || '').trim();
  if (!password) {
    console.log('Backup skipped: BACKUP_PASSWORD is not set');
    return;
  }

  const keepLast = parsePositiveInt(env.BACKUP_KEEP_LAST, 30);
  const prefix = normalizePrefix(env.BACKUP_R2_PREFIX);
  const includeAttachments = parseBool(env.BACKUP_INCLUDE_ATTACHMENTS, true);
  const storage = new StorageService(env.DB);

  const userId = await getSingleUserId(env.DB);
  if (!userId) {
    console.log('Backup skipped: no user found');
    return;
  }

  const now = new Date();
  const stamp = makeTimestamp(now);
  const datePath = makeDatePath(now);
  const objectKey = `${prefix}${datePath}/nodewarden-${stamp}.zip`;

  try {
    const ciphers = await storage.getAllCiphers(userId);
    const folders = await storage.getAllFolders(userId);
    const payload = buildExportPayload(ciphers, folders);
    const zipWriter = new ZipWriter(new Uint8ArrayWriter(), {
      password,
      encryptionStrength: 3,
      zipCrypto: false,
    });

    const exportJson = JSON.stringify(payload);
    await zipWriter.add('export.json', new Uint8ArrayReader(textBytes(exportJson)));

    if (includeAttachments && ciphers.length > 0) {
      const attachmentsByCipher = await storage.getAttachmentsByCipherIds(ciphers.map(c => c.id));
      for (const cipher of ciphers) {
        const attachments = attachmentsByCipher.get(cipher.id) || [];
        for (const attachment of attachments) {
          const r2Object = await env.ATTACHMENTS.get(`${cipher.id}/${attachment.id}`);
          if (!r2Object) continue;
          const body = new Uint8Array(await r2Object.arrayBuffer());
          const path = makeAttachmentPath(cipher, attachment);
          await zipWriter.add(path, new Uint8ArrayReader(body));
        }
      }
    }

    const zipBytes = await zipWriter.close();
    await env.ATTACHMENTS.put(objectKey, zipBytes, {
      httpMetadata: {
        contentType: 'application/zip',
      },
      customMetadata: {
        type: 'backup',
        createdAt: now.toISOString(),
      },
    });

    const listed = await env.ATTACHMENTS.list({ prefix });
    const backupObjects = listed.objects
      .filter(o => (o.customMetadata?.type || '') === 'backup' || o.key.endsWith('.zip'))
      .sort((a, b) => b.uploaded.getTime() - a.uploaded.getTime());

    if (backupObjects.length > keepLast) {
      const toDelete = backupObjects.slice(keepLast);
      for (const obj of toDelete) {
        await env.ATTACHMENTS.delete(obj.key);
      }
    }

    await saveBackupStatus(env.DB, 'backup_last_success_at', now.toISOString());
    await saveBackupStatus(env.DB, 'backup_last_object', objectKey);
    await saveBackupStatus(env.DB, 'backup_last_size', String(zipBytes.byteLength));
    console.log(`Backup complete: ${objectKey}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    await saveBackupStatus(env.DB, 'backup_last_error', `${new Date().toISOString()} ${message}`);
    console.error('Backup failed:', error);
  }
}
