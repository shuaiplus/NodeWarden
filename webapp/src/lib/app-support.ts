import { hkdf } from '@/lib/crypto';
import { t } from '@/lib/i18n';
import type { Cipher, VaultDraft } from '@/lib/types';
import type { ImportResultSummary } from '@/components/ImportPage';

const SEND_KEY_SALT = 'bitwarden-send';
const SEND_KEY_PURPOSE = 'send';
const SIGNALR_RECORD_SEPARATOR = String.fromCharCode(0x1e);

export interface WebVaultSignalRInvocation {
  type?: number;
  target?: string;
  arguments?: Array<{
    ContextId?: string | null;
    Type?: number;
    Payload?: {
      UserId?: string;
      Date?: string;
      RevisionDate?: string;
    };
  }>;
}

export function looksLikeCipherString(value: string): boolean {
  return /^\d+\.[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+(?:\|[A-Za-z0-9+/=]+)?$/.test(String(value || '').trim());
}

export function asText(value: unknown): string {
  if (value === null || value === undefined) return '';
  return String(value);
}

export function readInviteCodeFromUrl(): string {
  if (typeof window === 'undefined') return '';

  const searchInvite = new URLSearchParams(window.location.search || '').get('invite');
  if (searchInvite && searchInvite.trim()) return searchInvite.trim();

  const rawHash = String(window.location.hash || '');
  const queryIndex = rawHash.indexOf('?');
  if (queryIndex >= 0) {
    const hashInvite = new URLSearchParams(rawHash.slice(queryIndex + 1)).get('invite');
    if (hashInvite && hashInvite.trim()) return hashInvite.trim();
  }

  return '';
}

export function summarizeImportResult(
  ciphers: Array<Record<string, unknown>>,
  folderCount: number,
  attachmentSummary?: {
    total: number;
    imported: number;
    failed: Array<{ fileName: string; reason: string }>;
  }
): ImportResultSummary {
  const typeLabel = (type: number): string => {
    if (type === 1) return t('txt_login');
    if (type === 2) return t('txt_secure_note');
    if (type === 3) return t('txt_card');
    if (type === 4) return t('txt_identity');
    if (type === 5) return t('txt_ssh_key');
    return t('txt_other');
  };
  const counter = new Map<number, number>();
  for (const raw of ciphers) {
    const cipherType = Number(raw?.type || 1) || 1;
    counter.set(cipherType, (counter.get(cipherType) || 0) + 1);
  }
  const order = [1, 2, 3, 4, 5];
  const seen = new Set<number>(order);
  const typeCounts = order
    .filter((type) => (counter.get(type) || 0) > 0)
    .map((type) => ({ label: typeLabel(type), count: counter.get(type) || 0 }));
  for (const [type, count] of counter.entries()) {
    if (!seen.has(type) && count > 0) typeCounts.push({ label: typeLabel(type), count });
  }
  return {
    totalItems: ciphers.length,
    folderCount: Math.max(0, folderCount),
    typeCounts,
    attachmentCount: Math.max(0, attachmentSummary?.total || 0),
    importedAttachmentCount: Math.max(0, attachmentSummary?.imported || 0),
    failedAttachments: attachmentSummary?.failed || [],
  };
}

export function buildEmptyImportDraft(type: number): VaultDraft {
  return {
    type,
    favorite: false,
    name: '',
    folderId: '',
    notes: '',
    reprompt: false,
    loginUsername: '',
    loginPassword: '',
    loginTotp: '',
    loginUris: [{ uri: '', match: null }],
    loginFido2Credentials: [],
    cardholderName: '',
    cardNumber: '',
    cardBrand: '',
    cardExpMonth: '',
    cardExpYear: '',
    cardCode: '',
    identTitle: '',
    identFirstName: '',
    identMiddleName: '',
    identLastName: '',
    identUsername: '',
    identCompany: '',
    identSsn: '',
    identPassportNumber: '',
    identLicenseNumber: '',
    identEmail: '',
    identPhone: '',
    identAddress1: '',
    identAddress2: '',
    identAddress3: '',
    identCity: '',
    identState: '',
    identPostalCode: '',
    identCountry: '',
    sshPrivateKey: '',
    sshPublicKey: '',
    sshFingerprint: '',
    customFields: [],
  };
}

export function importCipherToDraft(cipher: Record<string, unknown>, folderId: string | null): VaultDraft {
  const type = Number(cipher.type || 1) || 1;
  const draft = buildEmptyImportDraft(type);
  draft.name = asText(cipher.name).trim() || 'Untitled';
  draft.notes = asText(cipher.notes);
  draft.favorite = !!cipher.favorite;
  draft.reprompt = Number(cipher.reprompt || 0) === 1;
  draft.folderId = folderId || '';

  const customFieldsRaw = Array.isArray(cipher.fields) ? cipher.fields : [];
  draft.customFields = customFieldsRaw
    .map((raw) => {
      const field = (raw || {}) as Record<string, unknown>;
      const label = asText(field.name).trim();
      if (!label) return null;
      const parsedType = Number(field.type ?? 0);
      const fieldType = parsedType === 1 || parsedType === 2 || parsedType === 3 ? (parsedType as 1 | 2 | 3) : 0;
      return {
        type: fieldType,
        label,
        value: asText(field.value),
      };
    })
    .filter((x): x is VaultDraft['customFields'][number] => !!x);

  if (type === 1) {
    const login = (cipher.login || {}) as Record<string, unknown>;
    draft.loginUsername = asText(login.username);
    draft.loginPassword = asText(login.password);
    draft.loginTotp = asText(login.totp);
    draft.loginFido2Credentials = Array.isArray(login.fido2Credentials)
      ? login.fido2Credentials
          .filter((credential): credential is Record<string, unknown> => !!credential && typeof credential === 'object')
          .map((credential) => ({ ...credential }))
      : [];
    const urisRaw = Array.isArray(login.uris) ? login.uris : [];
    const uris = urisRaw
      .map((u) => {
        const row = (u || {}) as Record<string, unknown>;
        const uri = asText(row.uri).trim();
        const matchRaw = row.match;
        return {
          uri,
          match: typeof matchRaw === 'number' && Number.isFinite(matchRaw) ? matchRaw : null,
        };
      })
      .filter((u) => !!u.uri);
    draft.loginUris = uris.length ? uris : [{ uri: '', match: null }];
  } else if (type === 3) {
    const card = (cipher.card || {}) as Record<string, unknown>;
    draft.cardholderName = asText(card.cardholderName);
    draft.cardNumber = asText(card.number);
    draft.cardBrand = asText(card.brand);
    draft.cardExpMonth = asText(card.expMonth);
    draft.cardExpYear = asText(card.expYear);
    draft.cardCode = asText(card.code);
  } else if (type === 4) {
    const identity = (cipher.identity || {}) as Record<string, unknown>;
    draft.identTitle = asText(identity.title);
    draft.identFirstName = asText(identity.firstName);
    draft.identMiddleName = asText(identity.middleName);
    draft.identLastName = asText(identity.lastName);
    draft.identUsername = asText(identity.username);
    draft.identCompany = asText(identity.company);
    draft.identSsn = asText(identity.ssn);
    draft.identPassportNumber = asText(identity.passportNumber);
    draft.identLicenseNumber = asText(identity.licenseNumber);
    draft.identEmail = asText(identity.email);
    draft.identPhone = asText(identity.phone);
    draft.identAddress1 = asText(identity.address1);
    draft.identAddress2 = asText(identity.address2);
    draft.identAddress3 = asText(identity.address3);
    draft.identCity = asText(identity.city);
    draft.identState = asText(identity.state);
    draft.identPostalCode = asText(identity.postalCode);
    draft.identCountry = asText(identity.country);
  } else if (type === 5) {
    const sshKey = (cipher.sshKey || {}) as Record<string, unknown>;
    draft.sshPrivateKey = asText(sshKey.privateKey);
    draft.sshPublicKey = asText(sshKey.publicKey);
    draft.sshFingerprint = asText(sshKey.keyFingerprint ?? sshKey.fingerprint);
  }

  return draft;
}

export function buildPublicSendUrl(origin: string, accessId: string, keyPart: string): string {
  return `${origin}/#/send/${accessId}/${keyPart}`;
}

export function parseSignalRTextFrames(raw: string): WebVaultSignalRInvocation[] {
  return raw
    .split(SIGNALR_RECORD_SEPARATOR)
    .map((frame) => frame.trim())
    .filter(Boolean)
    .map((frame) => {
      try {
        return JSON.parse(frame) as WebVaultSignalRInvocation;
      } catch {
        return null;
      }
    })
    .filter((frame): frame is WebVaultSignalRInvocation => !!frame);
}

export async function deriveSendKeyParts(sendKeyMaterial: Uint8Array): Promise<{ enc: Uint8Array; mac: Uint8Array }> {
  if (sendKeyMaterial.length >= 64) {
    return { enc: sendKeyMaterial.slice(0, 32), mac: sendKeyMaterial.slice(32, 64) };
  }
  const derived = await hkdf(sendKeyMaterial, SEND_KEY_SALT, SEND_KEY_PURPOSE, 64);
  return { enc: derived.slice(0, 32), mac: derived.slice(32, 64) };
}

export function findCipherById(ciphers: Cipher[], id: string): Cipher | null {
  return ciphers.find((cipher) => cipher.id === id) || null;
}
