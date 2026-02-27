export function bytesToBase64(bytes) {
  var s = '';
  for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export function base64ToBytes(b64) {
  var bin = atob(b64);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export function concatBytes(a, b) {
  var o = new Uint8Array(a.length + b.length);
  o.set(a, 0);
  o.set(b, a.length);
  return o;
}

export async function pbkdf2(passwordOrBytes, saltOrBytes, iterations, keyLen) {
  var pwdBytes = typeof passwordOrBytes === 'string' ? new TextEncoder().encode(passwordOrBytes) : passwordOrBytes;
  var saltBytes = typeof saltOrBytes === 'string' ? new TextEncoder().encode(saltOrBytes) : saltOrBytes;
  var key = await crypto.subtle.importKey('raw', pwdBytes, 'PBKDF2', false, ['deriveBits']);
  var bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations: iterations }, key, keyLen * 8);
  return new Uint8Array(bits);
}

export async function hkdfExpand(prk, info, length) {
  var enc = new TextEncoder();
  var key = await crypto.subtle.importKey('raw', prk, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  var infoBytes = enc.encode(info || '');
  var result = new Uint8Array(length);
  var prev = new Uint8Array(0);
  var off = 0;
  var cnt = 1;
  while (off < length) {
    var inp = new Uint8Array(prev.length + infoBytes.length + 1);
    inp.set(prev, 0);
    inp.set(infoBytes, prev.length);
    inp[inp.length - 1] = cnt & 0xff;
    prev = new Uint8Array(await crypto.subtle.sign('HMAC', key, inp));
    var c = Math.min(prev.length, length - off);
    result.set(prev.slice(0, c), off);
    off += c;
    cnt += 1;
  }
  return result;
}

export async function hmacSha256(keyBytes, dataBytes) {
  var key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, dataBytes));
}

export async function encryptAesCbc(data, key, iv) {
  var ck = await crypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['encrypt']);
  return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: iv }, ck, data));
}

export async function decryptAesCbc(data, key, iv) {
  var ck = await crypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv: iv }, ck, data));
}

export async function encryptBw(data, encKey, macKey) {
  var iv = crypto.getRandomValues(new Uint8Array(16));
  var cipher = await encryptAesCbc(data, encKey, iv);
  var mac = await hmacSha256(macKey, concatBytes(iv, cipher));
  return '2.' + bytesToBase64(iv) + '|' + bytesToBase64(cipher) + '|' + bytesToBase64(mac);
}

export function parseCipherString(s) {
  if (!s || typeof s !== 'string') throw new Error('invalid encrypted string');
  if (s === 'null' || s === 'undefined') throw new Error('invalid encrypted string');
  var p = s.indexOf('.');
  if (p <= 0) throw new Error('invalid encrypted string');
  var type = Number(s.slice(0, p));
  var body = s.slice(p + 1);
  var parts = body.split('|');
  if (type === 2 && parts.length === 3) return { type: 2, iv: base64ToBytes(parts[0]), ct: base64ToBytes(parts[1]), mac: base64ToBytes(parts[2]) };
  if ((type === 0 || type === 1 || type === 4) && parts.length >= 2) return { type: type, iv: base64ToBytes(parts[0]), ct: base64ToBytes(parts[1]), mac: null };
  throw new Error('unsupported enc type or format');
}

export async function decryptBw(cipherString, encKey, macKey) {
  var parsed = parseCipherString(cipherString);
  if (parsed.type === 2 && macKey && parsed.mac) {
    var expect = await hmacSha256(macKey, concatBytes(parsed.iv, parsed.ct));
    if (bytesToBase64(expect) !== bytesToBase64(parsed.mac)) throw new Error('MAC mismatch');
  }
  return decryptAesCbc(parsed.ct, encKey, parsed.iv);
}

export async function decryptStr(cipherString, encKey, macKey) {
  if (!cipherString || typeof cipherString !== 'string') return '';
  var plain = await decryptBw(cipherString, encKey, macKey);
  return new TextDecoder().decode(plain);
}

export function extractTotpSecret(raw) {
  if (!raw) return '';
  var s = String(raw).trim();
  if (!s) return '';
  if (/^otpauth:\/\//i.test(s)) {
    try {
      var u = new URL(s);
      var qp = u.searchParams.get('secret') || '';
      return qp.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/g, '');
    } catch (_) {}
  }
  return s.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/g, '');
}

export function base32ToBytes(input) {
  var alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  var clean = String(input || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  var bits = 0, value = 0, out = [];
  for (var i = 0; i < clean.length; i++) {
    var idx = alphabet.indexOf(clean.charAt(i));
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

export async function calcTotpNow(rawSecret) {
  var secret = extractTotpSecret(rawSecret);
  if (!secret) return null;
  var keyBytes = base32ToBytes(secret);
  if (!keyBytes.length) return null;
  var step = 30;
  var epoch = Math.floor(Date.now() / 1000);
  var counter = Math.floor(epoch / step);
  var remain = step - (epoch % step);
  var msg = new Uint8Array(8);
  var c = counter;
  for (var i = 7; i >= 0; i--) { msg[i] = c & 0xff; c = Math.floor(c / 256); }
  var key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  var hs = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  var off = hs[hs.length - 1] & 0x0f;
  var bin = ((hs[off] & 0x7f) << 24) | ((hs[off + 1] & 0xff) << 16) | ((hs[off + 2] & 0xff) << 8) | (hs[off + 3] & 0xff);
  var code = (bin % 1000000).toString().padStart(6, '0');
  return { code: code, remain: remain };
}
