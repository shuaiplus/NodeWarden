import { useState } from 'preact/hooks';
import {
  CreditCard,
  FileKey2,
  Globe,
  KeyRound,
  ShieldUser,
  StickyNote,
} from 'lucide-preact';
import { copyTextToClipboard } from '@/lib/clipboard';
import { t } from '@/lib/i18n';
import type { Cipher, CipherAttachment, CustomFieldType, VaultDraft, VaultDraftField, VaultDraftLoginUri } from '@/lib/types';

export type TypeFilter = 'login' | 'card' | 'identity' | 'note' | 'ssh';
export type VaultSortMode = 'edited' | 'created' | 'name';
export type SidebarFilter =
  | { kind: 'all' }
  | { kind: 'favorite' }
  | { kind: 'archive' }
  | { kind: 'trash' }
  | { kind: 'duplicates' }
  | { kind: 'type'; value: TypeFilter }
  | { kind: 'folder'; folderId: string | null };

interface TypeOption {
  type: number;
  label: string;
}

export const CREATE_TYPE_OPTIONS: TypeOption[] = [
  { type: 1, label: t('txt_login') },
  { type: 3, label: t('txt_card') },
  { type: 4, label: t('txt_identity') },
  { type: 2, label: t('txt_note') },
  { type: 5, label: t('txt_ssh_key') },
];

export const VAULT_SORT_STORAGE_KEY = 'nodewarden.vault.sort.v1';
export const MOBILE_LAYOUT_QUERY = '(max-width: 900px)';
export const VAULT_LIST_ROW_HEIGHT = 66;
export const VAULT_LIST_OVERSCAN = 10;
export const VAULT_SORT_OPTIONS: Array<{ value: VaultSortMode; label: string }> = [
  { value: 'edited', label: t('txt_sort_last_edited') },
  { value: 'created', label: t('txt_sort_created') },
  { value: 'name', label: t('txt_sort_name') },
];

export const FIELD_TYPE_OPTIONS: Array<{ value: CustomFieldType; label: string }> = [
  { value: 0, label: t('txt_text') },
  { value: 1, label: t('txt_hidden') },
  { value: 2, label: t('txt_boolean') },
];

export const WEBSITE_MATCH_OPTIONS: Array<{ value: number | null; label: string }> = [
  { value: null, label: t('txt_uri_match_default_base_domain') },
  { value: 0, label: t('txt_uri_match_base_domain') },
  { value: 1, label: t('txt_uri_match_host') },
  { value: 3, label: t('txt_uri_match_exact') },
  { value: 5, label: t('txt_uri_match_never') },
  { value: 2, label: t('txt_uri_match_starts_with') },
  { value: 4, label: t('txt_uri_match_regular_expression') },
];

export const TOTP_PERIOD_SECONDS = 30;
export const TOTP_RING_RADIUS = 14;
export const TOTP_RING_CIRCUMFERENCE = 2 * Math.PI * TOTP_RING_RADIUS;

export function CreateTypeIcon({ type }: { type: number }) {
  if (type === 1) return <Globe size={15} />;
  if (type === 3) return <CreditCard size={15} />;
  if (type === 4) return <ShieldUser size={15} />;
  if (type === 2) return <StickyNote size={15} />;
  if (type === 5) return <KeyRound size={15} />;
  return <FileKey2 size={15} />;
}

export function cipherTypeKey(type: number): TypeFilter {
  if (type === 1) return 'login';
  if (type === 3) return 'card';
  if (type === 4) return 'identity';
  if (type === 2) return 'note';
  return 'ssh';
}

function cipherDeletedValue(cipher: Cipher): boolean {
  return !!(cipher.deletedDate || (cipher as { deletedAt?: string | null }).deletedAt);
}

function cipherArchivedValue(cipher: Cipher): boolean {
  return !!(cipher.archivedDate || (cipher as { archivedAt?: string | null }).archivedAt);
}

export function isCipherDeleted(cipher: Cipher): boolean {
  return cipherDeletedValue(cipher);
}

export function isCipherArchived(cipher: Cipher): boolean {
  return cipherArchivedValue(cipher) && !cipherDeletedValue(cipher);
}

export function isCipherVisibleInNormalVault(cipher: Cipher): boolean {
  return !cipherDeletedValue(cipher) && !cipherArchivedValue(cipher);
}

export function isCipherVisibleInArchive(cipher: Cipher): boolean {
  return !cipherDeletedValue(cipher) && cipherArchivedValue(cipher);
}

export function isCipherVisibleInTrash(cipher: Cipher): boolean {
  return cipherDeletedValue(cipher);
}

export function cipherTypeLabel(type: number): string {
  if (type === 1) return t('txt_login');
  if (type === 3) return t('txt_card');
  if (type === 4) return t('txt_identity');
  if (type === 2) return t('txt_secure_note');
  if (type === 5) return t('txt_ssh_key');
  return t('txt_item');
}

export function TypeIcon({ type }: { type: number }) {
  if (type === 1) return <Globe size={18} />;
  if (type === 3) return <CreditCard size={18} />;
  if (type === 4) return <ShieldUser size={18} />;
  if (type === 2) return <StickyNote size={18} />;
  if (type === 5) return <KeyRound size={18} />;
  return <FileKey2 size={18} />;
}

export function parseFieldType(value: number | string | null | undefined): CustomFieldType {
  if (value === 1 || value === 2 || value === 3) return value;
  if (value === '1' || String(value).toLowerCase() === 'hidden') return 1;
  if (value === '2' || String(value).toLowerCase() === 'boolean') return 2;
  if (value === '3' || String(value).toLowerCase() === 'linked') return 3;
  return 0;
}

export function toBooleanFieldValue(raw: string): boolean {
  const v = String(raw || '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

export function firstCipherUri(cipher: Cipher): string {
  const uris = cipher.login?.uris || [];
  for (const uri of uris) {
    const raw = uri.decUri || uri.uri || '';
    if (raw.trim()) return raw.trim();
  }
  return '';
}

export function hostFromUri(uri: string): string {
  if (!uri.trim()) return '';
  try {
    const normalized = /^https?:\/\//i.test(uri) ? uri : `https://${uri}`;
    return new URL(normalized).hostname || '';
  } catch {
    return '';
  }
}

export function websiteIconUrl(host: string): string {
  return `/icons/${encodeURIComponent(host)}/icon.png`;
}

export function createEmptyLoginUri(): VaultDraftLoginUri {
  return { uri: '', match: null };
}

export function websiteMatchLabel(value: number | null | undefined): string {
  const normalized = typeof value === 'number' && Number.isFinite(value) ? value : null;
  return WEBSITE_MATCH_OPTIONS.find((option) => option.value === normalized)?.label || t('txt_uri_match_default_base_domain');
}

function valueOrFallback(value: string | null | undefined): string {
  return String(value || '');
}

export function buildCipherDuplicateSignature(cipher: Cipher): string {
  const normalized = {
    type: Number(cipher.type || 1),
    folderId: cipher.folderId || null,
    favorite: !!cipher.favorite,
    reprompt: Number(cipher.reprompt || 0),
    name: valueOrFallback(cipher.decName ?? cipher.name),
    notes: valueOrFallback(cipher.decNotes ?? cipher.notes),
    login: cipher.login
      ? {
          username: valueOrFallback(cipher.login.decUsername ?? cipher.login.username),
          password: valueOrFallback(cipher.login.decPassword ?? cipher.login.password),
          totp: valueOrFallback(cipher.login.decTotp ?? cipher.login.totp),
          uris: (cipher.login.uris || []).map((uri) => ({
            uri: valueOrFallback(uri.decUri ?? uri.uri),
            match: uri.match ?? null,
          })),
          fido2Credentials: (cipher.login.fido2Credentials || []).map((credential) => ({
            creationDate: valueOrFallback(credential.creationDate),
          })),
        }
      : null,
    card: cipher.card
      ? {
          cardholderName: valueOrFallback(cipher.card.decCardholderName ?? cipher.card.cardholderName),
          number: valueOrFallback(cipher.card.decNumber ?? cipher.card.number),
          brand: valueOrFallback(cipher.card.decBrand ?? cipher.card.brand),
          expMonth: valueOrFallback(cipher.card.decExpMonth ?? cipher.card.expMonth),
          expYear: valueOrFallback(cipher.card.decExpYear ?? cipher.card.expYear),
          code: valueOrFallback(cipher.card.decCode ?? cipher.card.code),
        }
      : null,
    identity: cipher.identity
      ? {
          title: valueOrFallback(cipher.identity.decTitle ?? cipher.identity.title),
          firstName: valueOrFallback(cipher.identity.decFirstName ?? cipher.identity.firstName),
          middleName: valueOrFallback(cipher.identity.decMiddleName ?? cipher.identity.middleName),
          lastName: valueOrFallback(cipher.identity.decLastName ?? cipher.identity.lastName),
          username: valueOrFallback(cipher.identity.decUsername ?? cipher.identity.username),
          company: valueOrFallback(cipher.identity.decCompany ?? cipher.identity.company),
          ssn: valueOrFallback(cipher.identity.decSsn ?? cipher.identity.ssn),
          passportNumber: valueOrFallback(cipher.identity.decPassportNumber ?? cipher.identity.passportNumber),
          licenseNumber: valueOrFallback(cipher.identity.decLicenseNumber ?? cipher.identity.licenseNumber),
          email: valueOrFallback(cipher.identity.decEmail ?? cipher.identity.email),
          phone: valueOrFallback(cipher.identity.decPhone ?? cipher.identity.phone),
          address1: valueOrFallback(cipher.identity.decAddress1 ?? cipher.identity.address1),
          address2: valueOrFallback(cipher.identity.decAddress2 ?? cipher.identity.address2),
          address3: valueOrFallback(cipher.identity.decAddress3 ?? cipher.identity.address3),
          city: valueOrFallback(cipher.identity.decCity ?? cipher.identity.city),
          state: valueOrFallback(cipher.identity.decState ?? cipher.identity.state),
          postalCode: valueOrFallback(cipher.identity.decPostalCode ?? cipher.identity.postalCode),
          country: valueOrFallback(cipher.identity.decCountry ?? cipher.identity.country),
        }
      : null,
    sshKey: cipher.sshKey
      ? {
          privateKey: valueOrFallback(cipher.sshKey.decPrivateKey ?? cipher.sshKey.privateKey),
          publicKey: valueOrFallback(cipher.sshKey.decPublicKey ?? cipher.sshKey.publicKey),
          fingerprint: valueOrFallback(cipher.sshKey.decFingerprint ?? cipher.sshKey.keyFingerprint ?? cipher.sshKey.fingerprint),
        }
      : null,
    secureNoteType: cipher.secureNote?.type ?? null,
    fields: (cipher.fields || []).map((field) => ({
      type: field.type ?? null,
      name: valueOrFallback(field.decName ?? field.name),
      value: valueOrFallback(field.decValue ?? field.value),
      linkedId: field.linkedId ?? null,
    })),
    passwordHistory: (cipher.passwordHistory || []).map((entry) => ({
      password: valueOrFallback(entry.password),
      lastUsedDate: valueOrFallback(entry.lastUsedDate),
    })),
  };
  return JSON.stringify(normalized);
}

export function createEmptyDraft(type: number): VaultDraft {
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
    loginUris: [createEmptyLoginUri()],
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

export function draftFromCipher(cipher: Cipher): VaultDraft {
  const draft = createEmptyDraft(Number(cipher.type || 1));
  draft.id = cipher.id;
  draft.favorite = !!cipher.favorite;
  draft.name = cipher.decName || '';
  draft.folderId = cipher.folderId || '';
  draft.notes = cipher.decNotes || '';
  draft.reprompt = Number(cipher.reprompt || 0) === 1;

  if (cipher.login) {
    draft.loginUsername = cipher.login.decUsername || '';
    draft.loginPassword = cipher.login.decPassword || '';
    draft.loginTotp = cipher.login.decTotp || '';
    draft.loginUris = (cipher.login.uris || []).map((x) => ({
      uri: x.decUri || x.uri || '',
      match: x.match ?? null,
    }));
    draft.loginFido2Credentials = Array.isArray(cipher.login.fido2Credentials)
      ? cipher.login.fido2Credentials.map((credential) => ({ ...credential }))
      : [];
    if (!draft.loginUris.length) draft.loginUris = [createEmptyLoginUri()];
  }
  if (cipher.card) {
    draft.cardholderName = cipher.card.decCardholderName || '';
    draft.cardNumber = cipher.card.decNumber || '';
    draft.cardBrand = cipher.card.decBrand || '';
    draft.cardExpMonth = cipher.card.decExpMonth || '';
    draft.cardExpYear = cipher.card.decExpYear || '';
    draft.cardCode = cipher.card.decCode || '';
  }
  if (cipher.identity) {
    draft.identTitle = cipher.identity.decTitle || '';
    draft.identFirstName = cipher.identity.decFirstName || '';
    draft.identMiddleName = cipher.identity.decMiddleName || '';
    draft.identLastName = cipher.identity.decLastName || '';
    draft.identUsername = cipher.identity.decUsername || '';
    draft.identCompany = cipher.identity.decCompany || '';
    draft.identSsn = cipher.identity.decSsn || '';
    draft.identPassportNumber = cipher.identity.decPassportNumber || '';
    draft.identLicenseNumber = cipher.identity.decLicenseNumber || '';
    draft.identEmail = cipher.identity.decEmail || '';
    draft.identPhone = cipher.identity.decPhone || '';
    draft.identAddress1 = cipher.identity.decAddress1 || '';
    draft.identAddress2 = cipher.identity.decAddress2 || '';
    draft.identAddress3 = cipher.identity.decAddress3 || '';
    draft.identCity = cipher.identity.decCity || '';
    draft.identState = cipher.identity.decState || '';
    draft.identPostalCode = cipher.identity.decPostalCode || '';
    draft.identCountry = cipher.identity.decCountry || '';
  }
  if (cipher.sshKey) {
    draft.sshPrivateKey = cipher.sshKey.decPrivateKey || '';
    draft.sshPublicKey = cipher.sshKey.decPublicKey || '';
    draft.sshFingerprint = cipher.sshKey.decFingerprint || '';
  }
  draft.customFields = (cipher.fields || []).map((field) => ({
    type: parseFieldType(field.type),
    label: field.decName || '',
    value: field.decValue || '',
  }));

  return draft;
}

export function maskSecret(value: string): string {
  if (!value) return '';
  return '*'.repeat(Math.max(8, Math.min(24, value.length)));
}

export function formatTotp(code: string): string {
  if (!code) return code;
  if (code.length === 5) return `${code.slice(0, 2)} ${code.slice(2)}`;
  if (code.length < 6) return code;
  return `${code.slice(0, 3)} ${code.slice(3, 6)}`;
}

export function formatHistoryTime(value: string | null | undefined): string {
  if (!value) return t('txt_dash');
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return value;
  return date.toLocaleString();
}

export function parseAttachmentSizeBytes(attachment: CipherAttachment): number {
  const raw = attachment?.size;
  if (typeof raw === 'number' && Number.isFinite(raw) && raw >= 0) return raw;
  const parsed = Number(raw);
  if (Number.isFinite(parsed) && parsed >= 0) return parsed;
  return 0;
}

export function formatAttachmentSize(attachment: CipherAttachment): string {
  const sizeName = String(attachment?.sizeName || '').trim();
  if (sizeName) return sizeName;
  const bytes = parseAttachmentSizeBytes(attachment);
  if (bytes <= 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function sortTimeValue(cipher: Cipher): number {
  const candidates = [cipher.revisionDate, cipher.creationDate];
  for (const value of candidates) {
    const time = new Date(String(value || '')).getTime();
    if (Number.isFinite(time)) return time;
  }
  return 0;
}

export function creationTimeValue(cipher: Cipher): number {
  const time = new Date(String(cipher.creationDate || '')).getTime();
  return Number.isFinite(time) ? time : 0;
}

export function firstPasskeyCreationTime(cipher: Cipher | null): string | null {
  const credentials = cipher?.login?.fido2Credentials;
  if (!Array.isArray(credentials) || credentials.length === 0) return null;
  for (const credential of credentials) {
    const raw = String(credential?.creationDate || '').trim();
    if (raw) return raw;
  }
  return null;
}

const failedIconHosts = new Set<string>();

export function VaultListIcon({ cipher }: { cipher: Cipher }) {
  const uri = firstCipherUri(cipher);
  const host = hostFromUri(uri);
  const [errored, setErrored] = useState(() => (host ? failedIconHosts.has(host) : false));
  if (host && !errored) {
    return (
      <img
        className="list-icon"
        src={websiteIconUrl(host)}
        alt=""
        loading="lazy"
        referrerPolicy="no-referrer"
        onError={() => {
          failedIconHosts.add(host);
          setErrored(true);
        }}
      />
    );
  }
  return (
    <span className="list-icon-fallback">
      <TypeIcon type={Number(cipher.type || 1)} />
    </span>
  );
}

export function copyToClipboard(value: string): void {
  if (!value.trim()) return;
  void copyTextToClipboard(value);
}

export function openUri(raw: string): void {
  const value = raw.trim();
  if (!value) return;
  const url = /^https?:\/\//i.test(value) ? value : `https://${value}`;
  window.open(url, '_blank', 'noopener');
}
