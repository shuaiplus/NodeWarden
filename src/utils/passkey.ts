export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64UrlToBytes(input: string): Uint8Array {
  const normalized = String(input || '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

export function randomChallenge(size: number = 32): string {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(size)));
}

export function parseClientDataJSON(base64Url: string): { type?: string; challenge?: string; origin?: string } | null {
  try {
    const raw = base64UrlToBytes(base64Url);
    const text = new TextDecoder().decode(raw);
    const parsed = JSON.parse(text) as { type?: string; challenge?: string; origin?: string };
    if (!parsed || typeof parsed !== 'object') return null;
    return parsed;
  } catch {
    return null;
  }
}
