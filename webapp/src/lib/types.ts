export type AppPhase = 'register' | 'login' | 'locked' | 'app';

export interface SessionState {
  accessToken: string;
  refreshToken: string;
  email: string;
  symEncKey?: string;
  symMacKey?: string;
}

export interface Profile {
  id: string;
  email: string;
  name: string;
  key: string;
  masterPasswordHint?: string | null;
  privateKey?: string | null;
  publicKey?: string | null;
  role: 'admin' | 'user';
  [k: string]: unknown;
}

export interface Folder {
  id: string;
  name: string;
  decName?: string;
}

export interface CipherLoginUri {
  uri?: string | null;
  decUri?: string;
}

export interface CipherAttachment {
  id?: string;
  url?: string | null;
  fileName?: string | null;
  decFileName?: string;
  key?: string | null;
  size?: string | number | null;
  sizeName?: string | null;
  object?: string;
}

export interface CipherLoginPasskey {
  creationDate?: string | null;
  [key: string]: unknown;
}

export interface CipherLogin {
  username?: string | null;
  password?: string | null;
  totp?: string | null;
  uris?: CipherLoginUri[] | null;
  fido2Credentials?: CipherLoginPasskey[] | null;
  decUsername?: string;
  decPassword?: string;
  decTotp?: string;
}

export interface CipherCard {
  cardholderName?: string | null;
  number?: string | null;
  brand?: string | null;
  expMonth?: string | null;
  expYear?: string | null;
  code?: string | null;
  decCardholderName?: string;
  decNumber?: string;
  decBrand?: string;
  decExpMonth?: string;
  decExpYear?: string;
  decCode?: string;
}

export interface CipherIdentity {
  title?: string | null;
  firstName?: string | null;
  middleName?: string | null;
  lastName?: string | null;
  username?: string | null;
  company?: string | null;
  ssn?: string | null;
  passportNumber?: string | null;
  licenseNumber?: string | null;
  email?: string | null;
  phone?: string | null;
  address1?: string | null;
  address2?: string | null;
  address3?: string | null;
  city?: string | null;
  state?: string | null;
  postalCode?: string | null;
  country?: string | null;
  decTitle?: string;
  decFirstName?: string;
  decMiddleName?: string;
  decLastName?: string;
  decUsername?: string;
  decCompany?: string;
  decSsn?: string;
  decPassportNumber?: string;
  decLicenseNumber?: string;
  decEmail?: string;
  decPhone?: string;
  decAddress1?: string;
  decAddress2?: string;
  decAddress3?: string;
  decCity?: string;
  decState?: string;
  decPostalCode?: string;
  decCountry?: string;
}

export interface CipherSshKey {
  privateKey?: string | null;
  publicKey?: string | null;
  keyFingerprint?: string | null;
  fingerprint?: string | null;
  decPrivateKey?: string;
  decPublicKey?: string;
  decFingerprint?: string;
}

export interface CipherField {
  type?: number | string | null;
  name?: string | null;
  value?: string | null;
  linkedId?: number | null;
  decName?: string;
  decValue?: string;
}

export interface Cipher {
  id: string;
  type: number;
  folderId?: string | null;
  favorite?: boolean;
  reprompt?: number;
  name?: string | null;
  notes?: string | null;
  key?: string | null;
  creationDate?: string;
  revisionDate?: string;
  deletedDate?: string | null;
  attachments?: CipherAttachment[] | null;
  login?: CipherLogin | null;
  card?: CipherCard | null;
  identity?: CipherIdentity | null;
  sshKey?: CipherSshKey | null;
  secureNote?: { type?: number | null } | null;
  passwordHistory?: Array<{ password?: string | null; lastUsedDate?: string | null }> | null;
  fields?: CipherField[] | null;
  decName?: string;
  decNotes?: string;
}

export interface SendTextData {
  text?: string | null;
  hidden?: boolean;
}

export interface Send {
  id: string;
  accessId: string;
  type: number;
  name?: string | null;
  notes?: string | null;
  text?: SendTextData | null;
  key?: string | null;
  maxAccessCount?: number | null;
  accessCount?: number;
  disabled?: boolean;
  revisionDate?: string;
  expirationDate?: string | null;
  deletionDate?: string;
  decName?: string;
  decNotes?: string;
  decText?: string;
  decShareKey?: string;
  shareUrl?: string;
  file?: {
    id?: string;
    fileName?: string;
    size?: string | number;
    sizeName?: string;
  } | null;
}

export interface SendDraft {
  id?: string;
  type: 'text' | 'file';
  name: string;
  notes: string;
  text: string;
  file: File | null;
  deletionDays: string;
  expirationDays: string;
  maxAccessCount: string;
  password: string;
  disabled: boolean;
}

export type CustomFieldType = 0 | 1 | 2 | 3;

export interface VaultDraftField {
  type: CustomFieldType;
  label: string;
  value: string;
}

export interface VaultDraft {
  id?: string;
  type: number;
  favorite: boolean;
  name: string;
  folderId: string;
  notes: string;
  reprompt: boolean;
  loginUsername: string;
  loginPassword: string;
  loginTotp: string;
  loginUris: string[];
  loginFido2Credentials: Array<Record<string, unknown>>;
  cardholderName: string;
  cardNumber: string;
  cardBrand: string;
  cardExpMonth: string;
  cardExpYear: string;
  cardCode: string;
  identTitle: string;
  identFirstName: string;
  identMiddleName: string;
  identLastName: string;
  identUsername: string;
  identCompany: string;
  identSsn: string;
  identPassportNumber: string;
  identLicenseNumber: string;
  identEmail: string;
  identPhone: string;
  identAddress1: string;
  identAddress2: string;
  identAddress3: string;
  identCity: string;
  identState: string;
  identPostalCode: string;
  identCountry: string;
  sshPrivateKey: string;
  sshPublicKey: string;
  sshFingerprint: string;
  customFields: VaultDraftField[];
}

export interface ListResponse<T> {
  object: 'list';
  data: T[];
}

export interface WebBootstrapResponse {
  defaultKdfIterations?: number;
  jwtUnsafeReason?: 'missing' | 'default' | 'too_short' | null;
  jwtSecretMinLength?: number;
}

export interface TokenSuccess {
  access_token: string;
  refresh_token: string;
  expires_in?: number;
  token_type?: string;
  TwoFactorToken?: string;
  Key?: string;
  PrivateKey?: string | null;
  AccountKeys?: unknown | null;
  accountKeys?: unknown | null;
  Kdf?: number;
  KdfIterations?: number;
  KdfMemory?: number | null;
  KdfParallelism?: number | null;
  ForcePasswordReset?: boolean;
  ResetMasterPassword?: boolean;
  scope?: string;
  unofficialServer?: boolean;
  UserDecryptionOptions?: unknown;
  userDecryptionOptions?: unknown;
}

export interface TokenError {
  error?: string;
  error_description?: string;
  TwoFactorProviders?: unknown;
}

export interface ToastMessage {
  id: string;
  type: 'success' | 'error' | 'warning';
  text: string;
}

export interface AdminUser {
  id: string;
  email: string;
  name?: string;
  role: string;
  status: string;
}

export interface AdminInvite {
  code: string;
  inviteLink?: string;
  status: string;
  expiresAt?: string;
}

export interface AuthorizedDevice {
  id: string;
  name: string;
  identifier: string;
  type: number;
  creationDate: string | null;
  revisionDate: string | null;
  online: boolean;
  trusted: boolean;
  trustedTokenCount: number;
  trustedUntil: string | null;
}
