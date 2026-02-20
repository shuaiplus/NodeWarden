// Environment bindings
export interface Env {
  DB: D1Database;
  ATTACHMENTS: R2Bucket;
  JWT_SECRET: string;
  TOTP_SECRET?: string;
}

// Sample JWT secret used by `.dev.vars.example`.
// If runtime JWT_SECRET equals this value, treat it as unsafe.
export const DEFAULT_DEV_SECRET = 'Enter-your-JWT-key-here-at-least-32-characters';

// Attachment model
export interface Attachment {
  id: string;
  cipherId: string;
  fileName: string;  // encrypted
  size: number;
  sizeName: string;
  key: string | null;  // encrypted attachment key
}

// User model
export interface User {
  id: string;
  email: string;
  name: string | null;
  masterPasswordHash: string;
  key: string;
  privateKey: string | null;
  publicKey: string | null;
  kdfType: number;
  kdfIterations: number;
  kdfMemory?: number;
  kdfParallelism?: number;
  securityStamp: string;
  createdAt: string;
  updatedAt: string;
}

// Cipher types
export enum CipherType {
  Login = 1,
  SecureNote = 2,
  Card = 3,
  Identity = 4,
}

export interface CipherLoginUri {
  uri: string | null;
  uriChecksum: string | null;
  match: number | null;
}

export interface CipherLogin {
  username: string | null;
  password: string | null;
  uris: CipherLoginUri[] | null;
  totp: string | null;
  autofillOnPageLoad: boolean | null;
  fido2Credentials: any[] | null;
  uri: string | null;
  passwordRevisionDate: string | null;
}

export interface CipherCard {
  cardholderName: string | null;
  brand: string | null;
  number: string | null;
  expMonth: string | null;
  expYear: string | null;
  code: string | null;
}

export interface CipherSshKey {
  publicKey: string;
  privateKey: string;
  keyFingerprint: string;
}

export interface CipherIdentity {
  title: string | null;
  firstName: string | null;
  middleName: string | null;
  lastName: string | null;
  address1: string | null;
  address2: string | null;
  address3: string | null;
  city: string | null;
  state: string | null;
  postalCode: string | null;
  country: string | null;
  company: string | null;
  email: string | null;
  phone: string | null;
  ssn: string | null;
  username: string | null;
  passportNumber: string | null;
  licenseNumber: string | null;
}

export interface CipherSecureNote {
  type: number;
}

export interface CipherField {
  name: string | null;
  value: string | null;
  type: number;
  linkedId: number | null;
}

export interface PasswordHistory {
  password: string;
  lastUsedDate: string;
}

export interface Cipher {
  id: string;
  userId: string;
  type: CipherType;
  folderId: string | null;
  name: string | null;
  notes: string | null;
  favorite: boolean;
  login: CipherLogin | null;
  card: CipherCard | null;
  identity: CipherIdentity | null;
  secureNote: CipherSecureNote | null;
  sshKey: CipherSshKey | null;
  fields: CipherField[] | null;
  passwordHistory: PasswordHistory[] | null;
  reprompt: number;
  key: string | null;
  createdAt: string;
  updatedAt: string;
  deletedAt: string | null;
  /** Allow unknown fields from Bitwarden clients to be stored and passed through transparently. */
  [key: string]: any;
}

// Folder model
export interface Folder {
  id: string;
  userId: string;
  name: string;
  createdAt: string;
  updatedAt: string;
}

export interface Device {
  userId: string;
  deviceIdentifier: string;
  name: string;
  type: number;
  createdAt: string;
  updatedAt: string;
}

// JWT Payload
export interface JWTPayload {
  sub: string;      // user id
  email: string;
  name: string | null;
  email_verified: boolean; // required by mobile client
  amr: string[];    // authentication methods reference - required by mobile client
  sstamp: string;   // security stamp - invalidates token when user changes password
  iat: number;
  exp: number;
  iss: string;
  premium: boolean;
}

// UserDecryptionOptions types for mobile client compatibility
export interface MasterPasswordUnlockKdf {
  KdfType: number;
  Iterations: number;
  Memory: number | null;
  Parallelism: number | null;
}

export interface MasterPasswordUnlock {
  Kdf: MasterPasswordUnlockKdf;
  MasterKeyEncryptedUserKey: string;
  MasterKeyWrappedUserKey: string;
  Salt: string;
  Object: string;
}

export interface UserDecryptionOptions {
  HasMasterPassword: boolean;
  Object: string;
  // Bitwarden Android 2026.1.x expects this to exist; missing it breaks unlock when the vault is empty.
  MasterPasswordUnlock: MasterPasswordUnlock;
}

// API Response types
export interface TokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
  refresh_token: string;
  TwoFactorToken?: string;
  Key: string;
  PrivateKey: string | null;
  Kdf: number;
  KdfIterations: number;
  KdfMemory?: number;
  KdfParallelism?: number;
  ForcePasswordReset: boolean;
  ResetMasterPassword: boolean;
  scope: string;
  unofficialServer: boolean;
  UserDecryptionOptions: UserDecryptionOptions;
}

export interface ProfileResponse {
  id: string;
  name: string | null;
  email: string;
  emailVerified: boolean;
  premium: boolean;
  premiumFromOrganization: boolean;
  usesKeyConnector: boolean;
  masterPasswordHint: string | null;
  culture: string;
  twoFactorEnabled: boolean;
  key: string;
  privateKey: string | null;
  accountKeys: any | null;
  securityStamp: string;
  organizations: any[];
  providers: any[];
  providerOrganizations: any[];
  forcePasswordReset: boolean;
  avatarColor: string | null;
  creationDate: string;
  object: string;
}

export interface CipherResponse {
  id: string;
  organizationId: string | null;
  folderId: string | null;
  type: number;
  name: string | null;
  notes: string | null;
  favorite: boolean;
  login: CipherLogin | null;
  card: CipherCard | null;
  identity: CipherIdentity | null;
  secureNote: CipherSecureNote | null;
  sshKey: CipherSshKey | null;
  fields: CipherField[] | null;
  passwordHistory: PasswordHistory[] | null;
  reprompt: number;
  organizationUseTotp: boolean;
  creationDate: string;
  revisionDate: string;
  deletedDate: string | null;
  archivedDate: string | null;
  edit: boolean;
  viewPassword: boolean;
  permissions: CipherPermissions | null;
  object: string;
  collectionIds: string[];
  attachments: any[] | null;
  key: string | null;
  encryptedFor: string | null;
  /** Allow unknown fields to pass through to clients transparently. */
  [key: string]: any;
}

export interface CipherPermissions {
  delete: boolean;
  restore: boolean;
}

export interface FolderResponse {
  id: string;
  name: string;
  revisionDate: string;
  object: string;
}

export interface SyncResponse {
  profile: ProfileResponse;
  folders: FolderResponse[];
  collections: any[];
  ciphers: CipherResponse[];
  domains: any;
  policies: any[];
  sends: any[];
  // PascalCase for desktop/browser clients
  UserDecryptionOptions: UserDecryptionOptions | null;
  // camelCase for Android client (SyncResponseJson uses @SerialName("userDecryption"))
  userDecryption: {
    masterPasswordUnlock: {
      kdf: {
        kdfType: number;
        iterations: number;
        memory: number | null;
        parallelism: number | null;
      };
      masterKeyWrappedUserKey: string;
      masterKeyEncryptedUserKey: string;
      salt: string;
    } | null;
  } | null;
  object: string;
}
