export function bytesToBase64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 1) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

export function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function toBufferSource(bytes: Uint8Array): ArrayBuffer {
  return new Uint8Array(bytes).buffer;
}

export async function pbkdf2(
  passwordOrBytes: string | Uint8Array,
  saltOrBytes: string | Uint8Array,
  iterations: number,
  keyLen: number
): Promise<Uint8Array> {
  const pwdBytes = typeof passwordOrBytes === 'string' ? new TextEncoder().encode(passwordOrBytes) : passwordOrBytes;
  const saltBytes = typeof saltOrBytes === 'string' ? new TextEncoder().encode(saltOrBytes) : saltOrBytes;
  const key = await crypto.subtle.importKey('raw', toBufferSource(pwdBytes), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: toBufferSource(saltBytes), iterations },
    key,
    keyLen * 8
  );
  return new Uint8Array(bits);
}

export async function hkdfExpand(prk: Uint8Array, info: string, length: number): Promise<Uint8Array> {
  const infoBytes = new TextEncoder().encode(info || '');
  const key = await crypto.subtle.importKey('raw', toBufferSource(prk), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const result = new Uint8Array(length);
  let previous = new Uint8Array(0);
  let offset = 0;
  let counter = 1;

  while (offset < length) {
    const input = new Uint8Array(previous.length + infoBytes.length + 1);
    input.set(previous, 0);
    input.set(infoBytes, previous.length);
    input[input.length - 1] = counter & 0xff;
    previous = new Uint8Array(await crypto.subtle.sign('HMAC', key, toBufferSource(input)));
    const copyLen = Math.min(previous.length, length - offset);
    result.set(previous.slice(0, copyLen), offset);
    offset += copyLen;
    counter += 1;
  }

  return result;
}

export async function hkdf(
  ikm: Uint8Array,
  salt: string | Uint8Array,
  info: string | Uint8Array,
  outputByteSize: number
): Promise<Uint8Array> {
  const saltBytes = typeof salt === 'string' ? new TextEncoder().encode(salt) : salt;
  const infoBytes = typeof info === 'string' ? new TextEncoder().encode(info) : info;
  const params: HkdfParams = {
    name: 'HKDF',
    salt: toBufferSource(saltBytes),
    info: toBufferSource(infoBytes),
    hash: 'SHA-256',
  };
  const key = await crypto.subtle.importKey('raw', toBufferSource(ikm), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(params, key, outputByteSize * 8);
  return new Uint8Array(bits);
}

async function hmacSha256(keyBytes: Uint8Array, dataBytes: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', toBufferSource(keyBytes), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, toBufferSource(dataBytes)));
}

async function encryptAesCbc(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey('raw', toBufferSource(key), { name: 'AES-CBC' }, false, ['encrypt']);
  return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: toBufferSource(iv) }, cryptoKey, toBufferSource(data)));
}

async function decryptAesCbc(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey('raw', toBufferSource(key), { name: 'AES-CBC' }, false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv: toBufferSource(iv) }, cryptoKey, toBufferSource(data)));
}

export async function encryptBwFileData(data: Uint8Array, encKey: Uint8Array, macKey: Uint8Array): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const cipher = await encryptAesCbc(data, encKey, iv);
  const mac = await hmacSha256(macKey, concatBytes(iv, cipher));
  const out = new Uint8Array(1 + iv.length + mac.length + cipher.length);
  out[0] = 2; // EncryptionType.AesCbc256_HmacSha256_B64
  out.set(iv, 1);
  out.set(mac, 1 + iv.length);
  out.set(cipher, 1 + iv.length + mac.length);
  return out;
}

export async function decryptBwFileData(encrypted: Uint8Array, encKey: Uint8Array, macKey: Uint8Array): Promise<Uint8Array> {
  if (!encrypted || encrypted.length < 1 + 16 + 32 + 1) throw new Error('Invalid encrypted file data');
  const encType = encrypted[0];
  if (encType !== 2) throw new Error('Unsupported file encryption type');
  const iv = encrypted.slice(1, 17);
  const mac = encrypted.slice(17, 49);
  const cipher = encrypted.slice(49);
  const expected = await hmacSha256(macKey, concatBytes(iv, cipher));
  if (bytesToBase64(expected) !== bytesToBase64(mac)) throw new Error('MAC mismatch');
  return decryptAesCbc(cipher, encKey, iv);
}

export async function encryptBw(data: Uint8Array, encKey: Uint8Array, macKey: Uint8Array): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const cipher = await encryptAesCbc(data, encKey, iv);
  const mac = await hmacSha256(macKey, concatBytes(iv, cipher));
  return `2.${bytesToBase64(iv)}|${bytesToBase64(cipher)}|${bytesToBase64(mac)}`;
}

function parseCipherString(s: string): { type: number; iv: Uint8Array; ct: Uint8Array; mac: Uint8Array | null } {
  if (!s || typeof s !== 'string') throw new Error('invalid encrypted string');
  const p = s.indexOf('.');
  if (p <= 0) throw new Error('invalid encrypted string');
  const type = Number(s.slice(0, p));
  const body = s.slice(p + 1);
  const parts = body.split('|');
  if (type === 2 && parts.length === 3) {
    return { type: 2, iv: base64ToBytes(parts[0]), ct: base64ToBytes(parts[1]), mac: base64ToBytes(parts[2]) };
  }
  if ((type === 0 || type === 1 || type === 4) && parts.length >= 2) {
    return { type, iv: base64ToBytes(parts[0]), ct: base64ToBytes(parts[1]), mac: null };
  }
  throw new Error('unsupported enc type');
}

export async function decryptBw(cipherString: string, encKey: Uint8Array, macKey?: Uint8Array): Promise<Uint8Array> {
  const parsed = parseCipherString(cipherString);
  if (parsed.type === 2 && macKey && parsed.mac) {
    const expected = await hmacSha256(macKey, concatBytes(parsed.iv, parsed.ct));
    if (bytesToBase64(expected) !== bytesToBase64(parsed.mac)) throw new Error('MAC mismatch');
  }
  return decryptAesCbc(parsed.ct, encKey, parsed.iv);
}

export async function decryptStr(cipherString: string | null | undefined, encKey: Uint8Array, macKey?: Uint8Array): Promise<string> {
  if (!cipherString || typeof cipherString !== 'string') return '';
  const plain = await decryptBw(cipherString, encKey, macKey);
  return new TextDecoder().decode(plain);
}

export function extractTotpSecret(raw: string): string {
  if (!raw) return '';
  const s = raw.trim();
  if (!s) return '';
  if (/^otpauth:\/\//i.test(s)) {
    try {
      const u = new URL(s);
      return (u.searchParams.get('secret') || '').toUpperCase().replace(/[\s-]/g, '').replace(/=+$/g, '');
    } catch {
      return '';
    }
  }
  return s.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/g, '');
}

function base32ToBytes(input: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = input.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (let i = 0; i < clean.length; i += 1) {
    const idx = alphabet.indexOf(clean.charAt(i));
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export async function calcTotpNow(rawSecret: string): Promise<{ code: string; remain: number } | null> {
  const secret = extractTotpSecret(rawSecret);
  if (!secret) return null;
  const keyBytes = base32ToBytes(secret);
  if (!keyBytes.length) return null;
  const step = 30;
  const epoch = Math.floor(Date.now() / 1000);
  const counter = Math.floor(epoch / step);
  const remain = step - (epoch % step);

  const message = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i -= 1) {
    message[i] = c & 0xff;
    c = Math.floor(c / 256);
  }
  const key = await crypto.subtle.importKey('raw', toBufferSource(keyBytes), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const hs = new Uint8Array(await crypto.subtle.sign('HMAC', key, toBufferSource(message)));
  const offset = hs[hs.length - 1] & 0x0f;
  const bin = ((hs[offset] & 0x7f) << 24) | ((hs[offset + 1] & 0xff) << 16) | ((hs[offset + 2] & 0xff) << 8) | (hs[offset + 3] & 0xff);
  const code = (bin % 1000000).toString().padStart(6, '0');
  return { code, remain };
}
