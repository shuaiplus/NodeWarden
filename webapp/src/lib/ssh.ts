function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array | null {
  const normalized = base64.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (!normalized) return null;
  const padLength = (4 - (normalized.length % 4)) % 4;
  const padded = normalized + '='.repeat(padLength);
  try {
    const binary = atob(padded);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function encodeSshString(value: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + value.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, value.length, false);
  out.set(value, 4);
  return out;
}

function extractSshBlobFromPublicKey(publicKey: string): Uint8Array | null {
  const text = String(publicKey || '').trim();
  if (!text) return null;
  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  for (const line of lines) {
    const match = line.match(/^([A-Za-z0-9-]+)\s+([A-Za-z0-9+/=_-]+)(?:\s+.*)?$/);
    if (!match) continue;
    const keyType = match[1].toLowerCase();
    if (!keyType.startsWith('ssh-') && !keyType.startsWith('ecdsa-')) continue;
    return base64ToBytes(match[2]);
  }
  return null;
}

export async function computeSshFingerprint(publicKey: string): Promise<string> {
  const blob = extractSshBlobFromPublicKey(publicKey);
  if (!blob) return '';
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', blob as unknown as BufferSource));
  return `SHA256:${bytesToBase64(digest).replace(/=+$/g, '')}`;
}

function toPem(tag: string, bytes: Uint8Array): string {
  const b64 = bytesToBase64(bytes);
  const chunks: string[] = [];
  for (let i = 0; i < b64.length; i += 64) chunks.push(b64.slice(i, i + 64));
  return `-----BEGIN ${tag}-----\n${chunks.join('\n')}\n-----END ${tag}-----`;
}

function extractEd25519RawPublicKey(spki: Uint8Array): Uint8Array | null {
  const prefix = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
  const hasPrefix = spki.length >= prefix.length + 32 && prefix.every((value, idx) => spki[idx] === value);
  if (hasPrefix) return spki.slice(prefix.length, prefix.length + 32);
  if (spki.length >= 32) return spki.slice(spki.length - 32);
  return null;
}

export async function generateDefaultSshKeyMaterial(): Promise<{ privateKey: string; publicKey: string; fingerprint: string }> {
  const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
  const rawPublic = extractEd25519RawPublicKey(spki);
  if (!rawPublic) throw new Error('Cannot export Ed25519 public key');

  const encoder = new TextEncoder();
  const sshBlob = concatBytes(encodeSshString(encoder.encode('ssh-ed25519')), encodeSshString(rawPublic));
  const publicKey = `ssh-ed25519 ${bytesToBase64(sshBlob)}`;
  const privateKey = toPem('PRIVATE KEY', pkcs8);
  const fingerprint = await computeSshFingerprint(publicKey);
  return { privateKey, publicKey, fingerprint };
}
