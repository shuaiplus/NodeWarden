import type { CiphersImportPayload } from '@/lib/api/vault';

export type CsvRow = Record<string, string>;

export function txt(v: unknown): string {
  if (v === null || v === undefined) return '';
  return String(v).trim();
}

export function val(v: unknown, fallback: string | null = null): string | null {
  const s = txt(v);
  return s ? s : fallback;
}

export function normalizeUri(raw: string): string | null {
  const s = txt(raw);
  if (!s) return null;
  if (!s.includes('://') && s.includes('.')) return (`http://${s}`).slice(0, 1000);
  return s.slice(0, 1000);
}

export function parseSerializedUris(raw: string): string[] {
  const source = txt(raw);
  if (!source) return [];

  const newlineParts = source
    .split(/\r?\n/)
    .map((part) => txt(part))
    .filter(Boolean);

  const parts =
    newlineParts.length > 1
      ? newlineParts
      : source.includes(',')
        ? source
            .split(/,(?=\s*(?:[a-z][a-z0-9+.-]*:\/\/|www\.|[a-z0-9.-]+\.[a-z]{2,}(?:[/:?#]|$)))/i)
            .map((part) => txt(part))
            .filter(Boolean)
        : [source];

  const seen = new Set<string>();
  const uris: string[] = [];
  for (const part of parts) {
    const normalized = normalizeUri(part);
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    uris.push(normalized);
  }
  return uris;
}

export function nameFromUrl(raw: string): string | null {
  const uri = normalizeUri(raw);
  if (!uri) return null;
  try {
    const host = new URL(uri).hostname || '';
    if (!host) return null;
    return host.startsWith('www.') ? host.slice(4) : host;
  } catch {
    return null;
  }
}

export function convertToNoteIfNeeded(cipher: Record<string, unknown>): void {
  if (Number(cipher.type || 1) !== 1) return;
  const login = cipher.login as Record<string, unknown> | null;
  const hasLoginData =
    !!txt(login?.username) ||
    !!txt(login?.password) ||
    !!txt(login?.totp) ||
    (Array.isArray(login?.uris) && login!.uris.length > 0);
  if (hasLoginData) return;
  cipher.type = 2;
  cipher.login = null;
  cipher.secureNote = { type: 0 };
}

export function splitFullName(
  fullName: string | null
): { firstName: string | null; middleName: string | null; lastName: string | null } {
  const parts = txt(fullName).split(/\s+/).filter(Boolean);
  return {
    firstName: parts[0] || null,
    middleName: parts.length > 2 ? parts.slice(1, -1).join(' ') : null,
    lastName: parts.length > 1 ? parts[parts.length - 1] : null,
  };
}

export function parseEpochMaybe(epoch: unknown): string | null {
  const n = Number(epoch);
  if (!Number.isFinite(n) || n <= 0) return null;
  const ms = n >= 1_000_000_000_000 ? n : n * 1000;
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString();
}

export function parseCardExpiry(raw: string): { month: string | null; year: string | null } {
  const s = txt(raw);
  if (!s) return { month: null, year: null };
  const yyyymm = s.match(/^(\d{4})(\d{2})$/);
  if (yyyymm) return { month: String(Number(yyyymm[2])), year: yyyymm[1] };
  const mmYYYY = s.match(/^(\d{1,2})\/(\d{4})$/);
  if (mmYYYY) return { month: String(Number(mmYYYY[1])), year: mmYYYY[2] };
  const mmYY = s.match(/^(\d{1,2})\/(\d{2})$/);
  if (mmYY) return { month: String(Number(mmYY[1])), year: `20${mmYY[2]}` };
  const dashed = s.match(/^(\d{4})-(\d{2})/);
  if (dashed) return { month: String(Number(dashed[2])), year: dashed[1] };
  return { month: null, year: null };
}

export function parseCsv(raw: string): CsvRow[] {
  const rows: string[][] = [];
  let cell = '';
  let row: string[] = [];
  let inQuotes = false;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (inQuotes) {
      if (ch === '"') {
        if (raw[i + 1] === '"') {
          cell += '"';
          i++;
        } else inQuotes = false;
      } else cell += ch;
      continue;
    }
    if (ch === '"') {
      inQuotes = true;
      continue;
    }
    if (ch === ',') {
      row.push(cell);
      cell = '';
      continue;
    }
    if (ch === '\n') {
      row.push(cell);
      rows.push(row);
      row = [];
      cell = '';
      continue;
    }
    if (ch === '\r') continue;
    cell += ch;
  }
  row.push(cell);
  rows.push(row);
  const nonEmpty = rows.filter((r) => r.some((c) => txt(c)));
  if (!nonEmpty.length) return [];
  const headers = nonEmpty[0].map((h) => txt(h));
  const out: CsvRow[] = [];
  for (let i = 1; i < nonEmpty.length; i++) {
    const values = nonEmpty[i];
    const obj: CsvRow = {};
    for (let c = 0; c < headers.length; c++) {
      if (headers[c]) obj[headers[c]] = values[c] ?? '';
    }
    out.push(obj);
  }
  return out;
}

export function parseCsvRows(raw: string): string[][] {
  const rows: string[][] = [];
  let cell = '';
  let row: string[] = [];
  let inQuotes = false;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (inQuotes) {
      if (ch === '"') {
        if (raw[i + 1] === '"') {
          cell += '"';
          i++;
        } else inQuotes = false;
      } else cell += ch;
      continue;
    }
    if (ch === '"') {
      inQuotes = true;
      continue;
    }
    if (ch === ',') {
      row.push(cell);
      cell = '';
      continue;
    }
    if (ch === '\n') {
      row.push(cell);
      rows.push(row);
      row = [];
      cell = '';
      continue;
    }
    if (ch === '\r') continue;
    cell += ch;
  }
  row.push(cell);
  rows.push(row);
  return rows.filter((r) => r.some((c) => txt(c)));
}

export function processKvp(cipher: Record<string, unknown>, key: string, value: string, hidden = false): void {
  const k = txt(key);
  const v = txt(value);
  if (!v) return;
  const fields = Array.isArray(cipher.fields) ? (cipher.fields as Array<Record<string, unknown>>) : [];
  if (v.length > 200 || /\r\n|\r|\n/.test(v)) {
    const existing = txt(cipher.notes);
    cipher.notes = `${existing}${existing ? '\n' : ''}${k ? `${k}: ` : ''}${v}`;
    return;
  }
  fields.push({ type: hidden ? 1 : 0, name: k, value: v, linkedId: null });
  cipher.fields = fields;
}

export function makeLoginCipher(): Record<string, unknown> {
  return {
    type: 1,
    name: '--',
    notes: null,
    favorite: false,
    reprompt: 0,
    key: null,
    login: { username: null, password: null, totp: null, uris: null },
    card: null,
    identity: null,
    secureNote: null,
    fields: [],
    passwordHistory: null,
    sshKey: null,
  };
}

export function addFolder(result: CiphersImportPayload, folderName: string, cipherIndex: number): void {
  const name = txt(folderName).replace(/\\/g, '/');
  if (!name || name === '(none)') return;
  let i = result.folders.findIndex((f) => f.name === name);
  if (i < 0) {
    i = result.folders.length;
    result.folders.push({ name });
  }
  result.folderRelationships.push({ key: cipherIndex, value: i });
}

export function cardBrand(number: string | null): string | null {
  const n = txt(number).replace(/\s+/g, '');
  if (!n) return null;
  if (/^4/.test(n)) return 'Visa';
  if (/^(5[1-5]|2[2-7])/.test(n)) return 'Mastercard';
  if (/^3[47]/.test(n)) return 'Amex';
  if (/^6(?:011|5)/.test(n)) return 'Discover';
  return null;
}
