export function parseFieldType(v) {
  if (v === null || v === undefined) return 0;
  if (typeof v === 'number' && isFinite(v)) return v === 1 || v === 2 || v === 3 ? v : 0;
  var s = String(v).trim().toLowerCase();
  if (s === '1' || s === 'hidden') return 1;
  if (s === '2' || s === 'boolean' || s === 'checkbox') return 2;
  if (s === '3' || s === 'linked' || s === 'link') return 3;
  return 0;
}

export function selectedCount(selectedMap) {
  var n = 0;
  for (var k in selectedMap) if (selectedMap[k]) n++;
  return n;
}

export function cipherTypeKey(c) {
  var tnum = Number(c && c.type || 1);
  if (tnum === 1) return 'login';
  if (tnum === 3) return 'card';
  if (tnum === 4) return 'identity';
  if (tnum === 2) return 'note';
  return 'other';
}

export function hostFromUri(uri) {
  if (!uri) return '';
  try {
    var normalized = /^https?:\/\//i.test(uri) ? uri : ('https://' + uri);
    return new URL(normalized).hostname || '';
  } catch (_) {
    return '';
  }
}

export function firstCipherUri(c) {
  var uris = c && c.login && Array.isArray(c.login.uris) ? c.login.uris : [];
  for (var i = 0; i < uris.length; i++) {
    var u = uris[i] && (uris[i].decUri || uris[i].uri);
    if (u) return u;
  }
  return '';
}

