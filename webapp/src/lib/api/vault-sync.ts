import type { Cipher, Folder, Send } from '../types';
import { parseJson, type AuthedFetch } from './shared';

interface VaultSyncResponse {
  ciphers?: Cipher[];
  folders?: Folder[];
  sends?: Send[];
}

const pendingSyncRequests = new WeakMap<AuthedFetch, Promise<VaultSyncResponse>>();

export async function loadVaultSyncSnapshot(authedFetch: AuthedFetch): Promise<VaultSyncResponse> {
  const existing = pendingSyncRequests.get(authedFetch);
  if (existing) return existing;

  const request = (async () => {
    const resp = await authedFetch('/api/sync');
    if (!resp.ok) throw new Error('Failed to load vault');
    const body = await parseJson<VaultSyncResponse>(resp);
    return body || {};
  })();

  pendingSyncRequests.set(authedFetch, request);
  try {
    return await request;
  } finally {
    if (pendingSyncRequests.get(authedFetch) === request) {
      pendingSyncRequests.delete(authedFetch);
    }
  }
}
