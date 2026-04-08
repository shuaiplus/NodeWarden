import { base64ToBytes, decryptBw, toBufferSource } from './crypto';
import type { AdminBackupSettings, BackupSettingsPortablePayload } from './api/backup';
import type { Profile, SessionState } from './types';

const PORTABLE_ALGORITHM = 'RSA-OAEP';
const PORTABLE_HASH = 'SHA-1';
const AES_GCM_ALGORITHM = 'AES-GCM';

async function importPortablePrivateKey(pkcs8: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'pkcs8',
    toBufferSource(pkcs8),
    { name: PORTABLE_ALGORITHM, hash: PORTABLE_HASH },
    false,
    ['decrypt']
  );
}

async function importPortableAesKey(keyBytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', toBufferSource(keyBytes), { name: AES_GCM_ALGORITHM }, false, ['decrypt']);
}

export async function decryptPortableBackupSettings(
  portable: BackupSettingsPortablePayload,
  profile: Profile,
  session: SessionState
): Promise<AdminBackupSettings> {
  if (!profile.id) {
    throw new Error('Current administrator profile is missing an id');
  }
  if (!profile.privateKey) {
    throw new Error('Current administrator profile is missing a private key');
  }
  if (!session.symEncKey || !session.symMacKey) {
    throw new Error('Current session is missing unlocked vault keys');
  }

  const wrap = portable.wraps.find((entry) => entry.userId === profile.id);
  if (!wrap) {
    throw new Error('No portable backup settings wrap is available for the current administrator');
  }

  const privateKeyBytes = await decryptBw(
    profile.privateKey,
    base64ToBytes(session.symEncKey),
    base64ToBytes(session.symMacKey)
  );
  const privateKey = await importPortablePrivateKey(privateKeyBytes);
  const portableDek = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: PORTABLE_ALGORITHM },
      privateKey,
      toBufferSource(base64ToBytes(wrap.wrappedKey))
    )
  );
  const aesKey = await importPortableAesKey(portableDek);
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: AES_GCM_ALGORITHM, iv: toBufferSource(base64ToBytes(portable.iv)) },
      aesKey,
      toBufferSource(base64ToBytes(portable.ciphertext))
    )
  );
  return JSON.parse(new TextDecoder().decode(plaintext)) as AdminBackupSettings;
}
