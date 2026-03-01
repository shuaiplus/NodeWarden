const RECOVERY_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function normalizeRecoveryCode(raw: string): string {
  return String(raw || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
}

function formatRecoveryCode(compact: string): string {
  return compact.replace(/(.{4})/g, '$1 ').trim();
}

export function createRecoveryCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let compact = '';
  for (const b of bytes) {
    compact += RECOVERY_ALPHABET[b % RECOVERY_ALPHABET.length];
  }
  // 20 bytes -> 20 chars in this simple mapping. Expand to 32 chars for friendlier grouping.
  while (compact.length < 32) {
    const extra = crypto.getRandomValues(new Uint8Array(1))[0];
    compact += RECOVERY_ALPHABET[extra % RECOVERY_ALPHABET.length];
  }
  return formatRecoveryCode(compact.slice(0, 32));
}

export function recoveryCodeEquals(input: string, storedCode: string | null | undefined): boolean {
  if (!storedCode) return false;
  const a = new TextEncoder().encode(normalizeRecoveryCode(input));
  const b = new TextEncoder().encode(normalizeRecoveryCode(storedCode));
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
