import { Env, SyncResponse, CipherResponse, FolderResponse, ProfileResponse } from '../types';
import { StorageService } from '../services/storage';
import { errorResponse } from '../utils/response';
import { cipherToResponse } from './ciphers';
import { sendToResponse } from './sends';
import { LIMITS } from '../config/limits';
import {
  buildAccountKeys,
  buildUserDecryptionCompat,
  buildUserDecryptionOptions,
} from '../utils/user-decryption';

function buildSyncCacheRequest(request: Request, userId: string, revisionDate: string, excludeDomains: boolean): Request {
  const url = new URL(request.url);
  const cacheUrl = new URL(
    `/__nodewarden/cache/sync/${encodeURIComponent(userId)}/${encodeURIComponent(revisionDate)}/${excludeDomains ? '1' : '0'}`,
    url.origin
  );
  return new Request(cacheUrl.toString(), { method: 'GET' });
}

async function readSyncCache(cacheRequest: Request): Promise<Response | null> {
  const hit = await caches.default.match(cacheRequest);
  if (!hit) return null;
  return new Response(hit.body, hit);
}

async function writeSyncCache(cacheRequest: Request, response: Response): Promise<void> {
  await caches.default.put(cacheRequest, response.clone());
}

// GET /api/sync
export async function handleSync(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  const excludeDomainsParam = url.searchParams.get('excludeDomains');
  const excludeDomains = excludeDomainsParam !== null && /^(1|true|yes)$/i.test(excludeDomainsParam);

  const user = await storage.getUserById(userId);
  if (!user) {
    return errorResponse('User not found', 404);
  }

  const revisionDate = await storage.getRevisionDate(userId);
  const cacheRequest = buildSyncCacheRequest(request, userId, revisionDate, excludeDomains);
  const cachedResponse = await readSyncCache(cacheRequest);
  if (cachedResponse) {
    return cachedResponse;
  }

  const [ciphers, folders, sends, attachmentsByCipher] = await Promise.all([
    storage.getAllCiphers(userId),
    storage.getAllFolders(userId),
    storage.getAllSends(userId),
    storage.getAttachmentsByUserId(userId),
  ]);
  const accountKeys = buildAccountKeys(user);
  const userDecryptionOptions = buildUserDecryptionOptions(user);

  const profile: ProfileResponse = {
    id: user.id,
    name: user.name,
    email: user.email,
    emailVerified: true,
    premium: true,
    premiumFromOrganization: false,
    usesKeyConnector: false,
    masterPasswordHint: user.masterPasswordHint,
    culture: 'en-US',
    twoFactorEnabled: !!user.totpSecret,
    key: user.key,
    privateKey: user.privateKey,
    accountKeys,
    securityStamp: user.securityStamp || user.id,
    organizations: [],
    providers: [],
    providerOrganizations: [],
    forcePasswordReset: false,
    avatarColor: null,
    creationDate: user.createdAt,
    verifyDevices: user.verifyDevices,
    object: 'profile',
  };

  const cipherResponses: CipherResponse[] = [];
  for (const cipher of ciphers) {
    cipherResponses.push(cipherToResponse(cipher, attachmentsByCipher.get(cipher.id) || []));
  }

  const folderResponses: FolderResponse[] = [];
  for (const folder of folders) {
    folderResponses.push({
      id: folder.id,
      name: folder.name,
      revisionDate: folder.updatedAt,
      object: 'folder',
    });
  }

  const sendResponses = sends.map(sendToResponse);
  const syncResponse: SyncResponse = {
    profile,
    folders: folderResponses,
    collections: [],
    ciphers: cipherResponses,
    domains: excludeDomains
      ? null
      : {
          equivalentDomains: [],
          globalEquivalentDomains: [],
          object: 'domains',
        },
    policies: [],
    sends: sendResponses,
    UserDecryption: {
      MasterPasswordUnlock: userDecryptionOptions.MasterPasswordUnlock,
      TrustedDeviceOption: null,
      KeyConnectorOption: null,
      Object: 'userDecryption',
    },
    UserDecryptionOptions: userDecryptionOptions,
    userDecryption: buildUserDecryptionCompat(user) as SyncResponse['userDecryption'],
    object: 'sync',
  };

  const response = new Response(JSON.stringify(syncResponse), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': `private, max-age=${Math.max(1, Math.floor(LIMITS.cache.syncResponseTtlMs / 1000))}`,
    },
  });
  await writeSyncCache(cacheRequest, response);
  return response;
}
