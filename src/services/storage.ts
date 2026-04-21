import { User, Cipher, Folder, Attachment, Device, Invite, AuditLog, Send, TrustedDeviceTokenSummary, RefreshTokenRecord } from '../types';
import { LIMITS } from '../config/limits';
import { ensureStorageSchema } from './storage-schema';
import {
  getConfigValue as getStoredConfigValue,
  isRegistered as getRegisteredFlag,
  setConfigValue as saveConfigValue,
  setRegistered as saveRegisteredFlag,
} from './storage-config-repo';
import {
  createFirstUser as createFirstStoredUser,
  createUser as createStoredUser,
  deleteUserById as deleteStoredUserById,
  getAllUsers as listStoredUsers,
  getUser as findStoredUserByEmail,
  getUserById as findStoredUserById,
  getUserCount as countStoredUsers,
  saveUser as saveStoredUser,
} from './storage-user-repo';
import {
  createAuditLog as createStoredAuditLog,
  createInvite as createStoredInvite,
  deleteAllInvites as deleteStoredInvites,
  getInvite as findStoredInvite,
  listInvites as listStoredInvites,
  markInviteUsed as markStoredInviteUsed,
  revokeInvite as revokeStoredInvite,
} from './storage-admin-repo';
import {
  bulkDeleteFolders as deleteStoredFolders,
  clearFolderFromCiphers as clearStoredFolderFromCiphers,
  deleteFolder as deleteStoredFolder,
  getAllFolders as listStoredFolders,
  getFolder as findStoredFolder,
  getFoldersPage as listStoredFoldersPage,
  saveFolder as saveStoredFolder,
} from './storage-folder-repo';
import {
  bulkArchiveCiphers as archiveStoredCiphers,
  bulkDeleteCiphers as deleteStoredCiphers,
  bulkMoveCiphers as moveStoredCiphers,
  bulkRestoreCiphers as restoreStoredCiphers,
  bulkSoftDeleteCiphers as softDeleteStoredCiphers,
  bulkUnarchiveCiphers as unarchiveStoredCiphers,
  getAllCiphers as listStoredCiphers,
  getCipher as findStoredCipher,
  getCiphersByIds as listStoredCiphersByIds,
  getCiphersPage as listStoredCiphersPage,
  saveCipher as saveStoredCipher,
  deleteCipher as deleteStoredCipher,
} from './storage-cipher-repo';
import {
  addAttachmentToCipher as attachStoredAttachmentToCipher,
  deleteAllAttachmentsByCipher as deleteStoredAttachmentsByCipher,
  deleteAttachment as deleteStoredAttachment,
  getAttachment as findStoredAttachment,
  getAttachmentsByCipher as listStoredAttachmentsByCipher,
  getAttachmentsByCipherIds as listStoredAttachmentsByCipherIds,
  getAttachmentsByUserId as listStoredAttachmentsByUserId,
  removeAttachmentFromCipher as detachStoredAttachmentFromCipher,
  saveAttachment as saveStoredAttachment,
  updateCipherRevisionDate as updateStoredCipherRevisionDate,
} from './storage-attachment-repo';
import {
  bulkDeleteSends as deleteStoredSends,
  deleteSend as deleteStoredSend,
  getAllSends as listStoredSends,
  getSend as findStoredSend,
  getSendsByIds as listStoredSendsByIds,
  getSendsPage as listStoredSendsPage,
  incrementSendAccessCount as incrementStoredSendAccessCount,
  saveSend as saveStoredSend,
} from './storage-send-repo';
import {
  constrainRefreshTokenExpiry as constrainStoredRefreshTokenExpiry,
  deleteRefreshToken as deleteStoredRefreshToken,
  deleteRefreshTokensByDevice as deleteStoredRefreshTokensByDevice,
  deleteRefreshTokensByUserId as deleteStoredRefreshTokensByUserId,
  getRefreshTokenRecord as findStoredRefreshTokenRecord,
  saveRefreshToken as saveStoredRefreshToken,
} from './storage-refresh-token-repo';
import {
  deleteDevice as deleteStoredDevice,
  deleteDevicesByUserId as deleteStoredDevicesByUserId,
  clearDeviceKeys as clearStoredDeviceKeys,
  deleteTrustedTwoFactorTokensByDevice as deleteStoredTrustedTokensByDevice,
  deleteTrustedTwoFactorTokensByUserId as deleteStoredTrustedTokensByUserId,
  getDevice as findStoredDevice,
  getDevicesByUserId as listStoredDevicesByUserId,
  getTrustedDeviceTokenSummariesByUserId as listStoredTrustedTokenSummaries,
  getTrustedTwoFactorDeviceTokenUserId as findStoredTrustedTokenUserId,
  isKnownDevice as getKnownStoredDevice,
  isKnownDeviceByEmail as getKnownStoredDeviceByEmail,
  saveTrustedTwoFactorDeviceToken as saveStoredTrustedDeviceToken,
  touchDeviceLastSeen as touchStoredDeviceLastSeen,
  upsertDevice as saveStoredDevice,
  updateDeviceName as updateStoredDeviceName,
  updateDeviceKeys as updateStoredDeviceKeys,
} from './storage-device-repo';
import {
  ensureUsedAttachmentDownloadTokenTable as ensureStoredAttachmentTokenTable,
  consumeAttachmentDownloadToken as consumeStoredAttachmentDownloadToken,
} from './storage-attachment-token-repo';
import {
  getRevisionDate as getStoredRevisionDate,
  updateRevisionDate as updateStoredRevisionDate,
} from './storage-revision-repo';

const TWO_FACTOR_REMEMBER_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const YUBIKEY_OTP_REPLAY_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const STORAGE_SCHEMA_VERSION_KEY = 'schema.version';
const STORAGE_SCHEMA_VERSION = '2026-04-21.1';

// D1-backed storage.
// Contract:
// - All methods are scoped by userId where applicable.
// - Uses SQL constraints (PK/unique/FK) to avoid KV-style index race conditions.
// - Revision date is maintained per user for Bitwarden sync.

export class StorageService {
  private static attachmentTokenTableReady = false;
  private static schemaVerified = false;
  private static lastRefreshTokenCleanupAt = 0;
  private static lastAttachmentTokenCleanupAt = 0;
  private static lastYubikeyOtpCleanupAt = 0;
  private static readonly MAX_D1_SQL_VARIABLES = 100;

  private static readonly REFRESH_TOKEN_CLEANUP_INTERVAL_MS = LIMITS.cleanup.refreshTokenCleanupIntervalMs;
  private static readonly ATTACHMENT_TOKEN_CLEANUP_INTERVAL_MS = LIMITS.cleanup.attachmentTokenCleanupIntervalMs;
  private static readonly YUBIKEY_OTP_CLEANUP_INTERVAL_MS = 6 * 60 * 60 * 1000;
  private static readonly PERIODIC_CLEANUP_PROBABILITY = LIMITS.cleanup.cleanupProbability;

  constructor(private db: D1Database) {}

  /**
   * D1 .bind() throws on `undefined` values. This helper converts every
   * `undefined` in the argument list to `null` so we never hit that runtime
   * error - especially important after the opaque-passthrough change where
   * client-supplied JSON may omit fields we later reference as columns.
   */
  private safeBind(stmt: D1PreparedStatement, ...values: any[]): D1PreparedStatement {
    return stmt.bind(...values.map(v => v === undefined ? null : v));
  }

  private sqlChunkSize(fixedBindCount: number): number {
    return Math.max(
      1,
      Math.min(LIMITS.performance.bulkMoveChunkSize, StorageService.MAX_D1_SQL_VARIABLES - fixedBindCount)
    );
  }

  private async sha256Hex(input: string): Promise<string> {
    const bytes = new TextEncoder().encode(input);
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  private async refreshTokenKey(token: string): Promise<string> {
    const digest = await this.sha256Hex(token);
    return `sha256:${digest}`;
  }

  private shouldRunPeriodicCleanup(lastRunAt: number, intervalMs: number): boolean {
    const now = Date.now();
    if (now - lastRunAt < intervalMs) return false;
    return Math.random() < StorageService.PERIODIC_CLEANUP_PROBABILITY;
  }

  private async maybeCleanupExpiredRefreshTokens(nowMs: number): Promise<void> {
    if (!this.shouldRunPeriodicCleanup(StorageService.lastRefreshTokenCleanupAt, StorageService.REFRESH_TOKEN_CLEANUP_INTERVAL_MS)) {
      return;
    }

    await this.db.prepare('DELETE FROM refresh_tokens WHERE expires_at < ?').bind(nowMs).run();
    StorageService.lastRefreshTokenCleanupAt = nowMs;
  }

  // --- Database initialization ---
  // Strategy:
  // - Run only once per isolate.
  // - Execute idempotent schema SQL on first request in each isolate.
  // - Keep statements idempotent so updates are safe.
  async initializeDatabase(): Promise<void> {
    if (StorageService.schemaVerified) return;

    await this.db.prepare('CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)').run();
    const schemaVersion = await getStoredConfigValue(this.db, STORAGE_SCHEMA_VERSION_KEY);
    if (schemaVersion !== STORAGE_SCHEMA_VERSION) {
      await ensureStorageSchema(this.db);
      await saveConfigValue(this.db, STORAGE_SCHEMA_VERSION_KEY, STORAGE_SCHEMA_VERSION);
    }

    StorageService.schemaVerified = true;
  }

  // --- Config / setup ---

  async isRegistered(): Promise<boolean> {
    return getRegisteredFlag(this.db);
  }

  async getConfigValue(key: string): Promise<string | null> {
    return getStoredConfigValue(this.db, key);
  }

  async setConfigValue(key: string, value: string): Promise<void> {
    await saveConfigValue(this.db, key, value);
  }

  async setRegistered(): Promise<void> {
    await saveRegisteredFlag(this.db);
  }

  // --- Users ---

  async getUser(email: string): Promise<User | null> {
    return findStoredUserByEmail(this.db, email);
  }

  async getUserById(id: string): Promise<User | null> {
    return findStoredUserById(this.db, id);
  }

  async getUserCount(): Promise<number> {
    return countStoredUsers(this.db);
  }

  async getAllUsers(): Promise<User[]> {
    return listStoredUsers(this.db);
  }

  async saveUser(user: User): Promise<void> {
    await saveStoredUser(this.db, this.safeBind.bind(this), user);
  }

  async createUser(user: User): Promise<void> {
    await createStoredUser(this.db, this.safeBind.bind(this), user);
  }

  async createFirstUser(user: User): Promise<boolean> {
    return createFirstStoredUser(this.db, this.safeBind.bind(this), user);
  }

  async deleteUserById(id: string): Promise<boolean> {
    return deleteStoredUserById(this.db, id);
  }

  async createInvite(invite: Invite): Promise<void> {
    await createStoredInvite(this.db, invite);
  }

  async getInvite(code: string): Promise<Invite | null> {
    return findStoredInvite(this.db, code);
  }

  async listInvites(includeInactive: boolean = false): Promise<Invite[]> {
    return listStoredInvites(this.db, includeInactive);
  }

  async markInviteUsed(code: string, userId: string): Promise<boolean> {
    return markStoredInviteUsed(this.db, code, userId);
  }

  async revokeInvite(code: string): Promise<boolean> {
    return revokeStoredInvite(this.db, code);
  }

  async deleteAllInvites(): Promise<number> {
    return deleteStoredInvites(this.db);
  }

  async createAuditLog(log: AuditLog): Promise<void> {
    await createStoredAuditLog(this.db, log);
  }

  // --- Ciphers ---

  async getCipher(id: string): Promise<Cipher | null> {
    return findStoredCipher(this.db, id);
  }

  async saveCipher(cipher: Cipher): Promise<void> {
    await saveStoredCipher(this.db, this.safeBind.bind(this), cipher);
  }

  async deleteCipher(id: string, userId: string): Promise<void> {
    await deleteStoredCipher(this.db, id, userId);
  }

  async bulkSoftDeleteCiphers(ids: string[], userId: string): Promise<string | null> {
    return softDeleteStoredCiphers(this.db, this.sqlChunkSize.bind(this), this.updateRevisionDate.bind(this), ids, userId);
  }

  async bulkRestoreCiphers(ids: string[], userId: string): Promise<string | null> {
    return restoreStoredCiphers(this.db, this.sqlChunkSize.bind(this), this.updateRevisionDate.bind(this), ids, userId);
  }

  async bulkArchiveCiphers(ids: string[], userId: string): Promise<string | null> {
    return archiveStoredCiphers(this.db, this.sqlChunkSize.bind(this), this.updateRevisionDate.bind(this), ids, userId);
  }

  async bulkUnarchiveCiphers(ids: string[], userId: string): Promise<string | null> {
    return unarchiveStoredCiphers(this.db, this.sqlChunkSize.bind(this), this.updateRevisionDate.bind(this), ids, userId);
  }

  async bulkDeleteCiphers(ids: string[], userId: string): Promise<string | null> {
    return deleteStoredCiphers(this.db, this.sqlChunkSize.bind(this), this.updateRevisionDate.bind(this), ids, userId);
  }

  async getAllCiphers(userId: string): Promise<Cipher[]> {
    return listStoredCiphers(this.db, userId);
  }

  async getCiphersPage(userId: string, includeDeleted: boolean, limit: number, offset: number): Promise<Cipher[]> {
    return listStoredCiphersPage(this.db, userId, includeDeleted, limit, offset);
  }

  async getCiphersByIds(ids: string[], userId: string): Promise<Cipher[]> {
    return listStoredCiphersByIds(this.db, this.sqlChunkSize.bind(this), ids, userId);
  }

  async bulkMoveCiphers(ids: string[], folderId: string | null, userId: string): Promise<string | null> {
    return moveStoredCiphers(this.db, this.sqlChunkSize.bind(this), this.updateRevisionDate.bind(this), ids, folderId, userId);
  }

  // --- Folders ---

  async getFolder(id: string): Promise<Folder | null> {
    return findStoredFolder(this.db, id);
  }

  async saveFolder(folder: Folder): Promise<void> {
    await saveStoredFolder(this.db, folder);
  }

  async deleteFolder(id: string, userId: string): Promise<void> {
    await deleteStoredFolder(this.db, id, userId);
  }

  async bulkDeleteFolders(ids: string[], userId: string): Promise<string | null> {
    return deleteStoredFolders(
      this.db,
      userId,
      ids,
      this.sqlChunkSize.bind(this),
      this.saveCipher.bind(this),
      this.updateRevisionDate.bind(this)
    );
  }

  // Clear folder references from all ciphers owned by the user.
  // Without this, deleting a folder leaves stale folderId values in cipher JSON.
  async clearFolderFromCiphers(userId: string, folderId: string): Promise<void> {
    await clearStoredFolderFromCiphers(this.db, userId, folderId, this.saveCipher.bind(this));
  }

  async getAllFolders(userId: string): Promise<Folder[]> {
    return listStoredFolders(this.db, userId);
  }

  async getFoldersPage(userId: string, limit: number, offset: number): Promise<Folder[]> {
    return listStoredFoldersPage(this.db, userId, limit, offset);
  }

  // --- Attachments ---

  async getAttachment(id: string): Promise<Attachment | null> {
    return findStoredAttachment(this.db, id);
  }

  async saveAttachment(attachment: Attachment): Promise<void> {
    await saveStoredAttachment(this.db, this.safeBind.bind(this), attachment);
  }

  async deleteAttachment(id: string): Promise<void> {
    await deleteStoredAttachment(this.db, id);
  }

  async getAttachmentsByCipher(cipherId: string): Promise<Attachment[]> {
    return listStoredAttachmentsByCipher(this.db, cipherId);
  }

  async getAttachmentsByCipherIds(cipherIds: string[]): Promise<Map<string, Attachment[]>> {
    return listStoredAttachmentsByCipherIds(this.db, this.sqlChunkSize.bind(this), cipherIds);
  }

  async getAttachmentsByUserId(userId: string): Promise<Map<string, Attachment[]>> {
    return listStoredAttachmentsByUserId(this.db, userId);
  }

  async addAttachmentToCipher(cipherId: string, attachmentId: string): Promise<void> {
    await attachStoredAttachmentToCipher(this.db, cipherId, attachmentId);
  }

  async removeAttachmentFromCipher(cipherId: string, attachmentId: string): Promise<void> {
    await detachStoredAttachmentFromCipher(cipherId, attachmentId);
  }

  async deleteAllAttachmentsByCipher(cipherId: string): Promise<void> {
    await deleteStoredAttachmentsByCipher(this.db, cipherId);
  }

  async updateCipherRevisionDate(cipherId: string): Promise<{ userId: string; revisionDate: string } | null> {
    return updateStoredCipherRevisionDate(
      this.getCipher.bind(this),
      this.saveCipher.bind(this),
      this.updateRevisionDate.bind(this),
      cipherId
    );
  }

  // --- Refresh tokens ---

  async saveRefreshToken(
    token: string,
    userId: string,
    expiresAtMs?: number,
    deviceIdentifier?: string | null,
    deviceSessionStamp?: string | null
  ): Promise<void> {
    const expiresAt = expiresAtMs ?? (Date.now() + LIMITS.auth.refreshTokenTtlMs);
    await saveStoredRefreshToken(
      this.db,
      this.refreshTokenKey.bind(this),
      this.maybeCleanupExpiredRefreshTokens.bind(this),
      token,
      userId,
      expiresAt,
      deviceIdentifier,
      deviceSessionStamp
    );
  }

  async getRefreshTokenRecord(token: string): Promise<RefreshTokenRecord | null> {
    return findStoredRefreshTokenRecord(
      this.db,
      this.refreshTokenKey.bind(this),
      this.maybeCleanupExpiredRefreshTokens.bind(this),
      this.saveRefreshToken.bind(this),
      this.deleteRefreshToken.bind(this),
      token
    );
  }

  async getRefreshTokenUserId(token: string): Promise<string | null> {
    const record = await this.getRefreshTokenRecord(token);
    return record?.userId ?? null;
  }

  async deleteRefreshToken(token: string): Promise<void> {
    await deleteStoredRefreshToken(this.db, this.refreshTokenKey.bind(this), token);
  }

  // --- Sends ---

  async getSend(id: string): Promise<Send | null> {
    return findStoredSend(this.db, id);
  }

  async saveSend(send: Send): Promise<void> {
    await saveStoredSend(this.db, this.safeBind.bind(this), send);
  }

  /**
   * Atomically increment access_count and update updated_at.
   * Returns true if the row was updated (send still available),
   * false if max_access_count has already been reached.
   */
  async incrementSendAccessCount(sendId: string): Promise<boolean> {
    return incrementStoredSendAccessCount(this.db, sendId);
  }

  async deleteSend(id: string, userId: string): Promise<void> {
    await deleteStoredSend(this.db, id, userId);
  }

  async getSendsByIds(ids: string[], userId: string): Promise<Send[]> {
    return listStoredSendsByIds(this.db, this.sqlChunkSize.bind(this), ids, userId);
  }

  async bulkDeleteSends(ids: string[], userId: string): Promise<string | null> {
    return deleteStoredSends(this.db, this.sqlChunkSize.bind(this), this.updateRevisionDate.bind(this), ids, userId);
  }

  async getAllSends(userId: string): Promise<Send[]> {
    return listStoredSends(this.db, userId);
  }

  async getSendsPage(userId: string, limit: number, offset: number): Promise<Send[]> {
    return listStoredSendsPage(this.db, userId, limit, offset);
  }

  async deleteRefreshTokensByUserId(userId: string): Promise<number> {
    return deleteStoredRefreshTokensByUserId(this.db, userId);
  }

  async deleteRefreshTokensByDevice(userId: string, deviceIdentifier: string): Promise<number> {
    return deleteStoredRefreshTokensByDevice(this.db, userId, deviceIdentifier);
  }

  // Keep a short overlap window for rotated refresh token to reduce
  // multi-context refresh races (e.g. browser extension popup/background).
  // Expiry is only tightened, never extended.
  async constrainRefreshTokenExpiry(token: string, maxExpiresAtMs: number): Promise<void> {
    await constrainStoredRefreshTokenExpiry(this.db, this.refreshTokenKey.bind(this), token, maxExpiresAtMs);
  }

  private async trustedTwoFactorTokenKey(token: string): Promise<string> {
    const digest = await this.sha256Hex(token);
    return `sha256:${digest}`;
  }

  private async maybeCleanupUsedYubikeyOtps(nowMs: number): Promise<void> {
    if (!this.shouldRunPeriodicCleanup(StorageService.lastYubikeyOtpCleanupAt, StorageService.YUBIKEY_OTP_CLEANUP_INTERVAL_MS)) {
      return;
    }
    await this.db
      .prepare('DELETE FROM used_yubikey_otps WHERE used_at < ?')
      .bind(nowMs - YUBIKEY_OTP_REPLAY_TTL_MS)
      .run();
    StorageService.lastYubikeyOtpCleanupAt = nowMs;
  }

  // --- Devices ---

  async upsertDevice(
    userId: string,
    deviceIdentifier: string,
    name: string,
    type: number,
    sessionStamp?: string,
    keys?: {
      encryptedUserKey?: string | null;
      encryptedPublicKey?: string | null;
      encryptedPrivateKey?: string | null;
    }
  ): Promise<void> {
    await saveStoredDevice(this.db, this.getDevice.bind(this), userId, deviceIdentifier, name, type, sessionStamp, keys);
  }

  async isKnownDevice(userId: string, deviceIdentifier: string): Promise<boolean> {
    return getKnownStoredDevice(this.db, userId, deviceIdentifier);
  }

  async isKnownDeviceByEmail(email: string, deviceIdentifier: string): Promise<boolean> {
    return getKnownStoredDeviceByEmail(this.getUser.bind(this), this.isKnownDevice.bind(this), email, deviceIdentifier);
  }

  async getDevicesByUserId(userId: string): Promise<Device[]> {
    return listStoredDevicesByUserId(this.db, userId);
  }

  async getDevice(userId: string, deviceIdentifier: string): Promise<Device | null> {
    return findStoredDevice(this.db, userId, deviceIdentifier);
  }

  async updateDeviceKeys(
    userId: string,
    deviceIdentifier: string,
    keys: {
      encryptedUserKey?: string | null;
      encryptedPublicKey?: string | null;
      encryptedPrivateKey?: string | null;
    }
  ): Promise<boolean> {
    return updateStoredDeviceKeys(this.db, userId, deviceIdentifier, keys);
  }

  async updateDeviceName(userId: string, deviceIdentifier: string, name: string): Promise<boolean> {
    return updateStoredDeviceName(this.db, userId, deviceIdentifier, name);
  }

  async touchDeviceLastSeen(userId: string, deviceIdentifier: string): Promise<boolean> {
    return touchStoredDeviceLastSeen(this.db, userId, deviceIdentifier);
  }

  async clearDeviceKeys(userId: string, deviceIdentifiers: string[]): Promise<number> {
    return clearStoredDeviceKeys(this.db, userId, deviceIdentifiers);
  }

  async deleteDevice(userId: string, deviceIdentifier: string): Promise<boolean> {
    return deleteStoredDevice(this.db, userId, deviceIdentifier);
  }

  async deleteDevicesByUserId(userId: string): Promise<number> {
    return deleteStoredDevicesByUserId(this.db, userId);
  }

  async getTrustedDeviceTokenSummariesByUserId(userId: string): Promise<TrustedDeviceTokenSummary[]> {
    return listStoredTrustedTokenSummaries(this.db, userId);
  }

  async deleteTrustedTwoFactorTokensByDevice(userId: string, deviceIdentifier: string): Promise<number> {
    return deleteStoredTrustedTokensByDevice(this.db, userId, deviceIdentifier);
  }

  async deleteTrustedTwoFactorTokensByUserId(userId: string): Promise<number> {
    return deleteStoredTrustedTokensByUserId(this.db, userId);
  }

  // --- Trusted 2FA remember tokens (device-bound) ---

  async saveTrustedTwoFactorDeviceToken(
    token: string,
    userId: string,
    deviceIdentifier: string,
    expiresAtMs?: number
  ): Promise<void> {
    const expiresAt = expiresAtMs ?? (Date.now() + TWO_FACTOR_REMEMBER_TTL_MS);
    await saveStoredTrustedDeviceToken(this.db, this.trustedTwoFactorTokenKey.bind(this), token, userId, deviceIdentifier, expiresAt);
  }

  async getTrustedTwoFactorDeviceTokenUserId(token: string, deviceIdentifier: string): Promise<string | null> {
    return findStoredTrustedTokenUserId(this.db, this.trustedTwoFactorTokenKey.bind(this), token, deviceIdentifier);
  }

  async isYubikeyOtpAlreadyUsed(otp: string): Promise<boolean> {
    const now = Date.now();
    await this.maybeCleanupUsedYubikeyOtps(now);
    const digest = await this.sha256Hex(otp);
    const row = await this.db.prepare('SELECT otp_hash FROM used_yubikey_otps WHERE otp_hash = ?').bind(`sha256:${digest}`).first<{ otp_hash: string }>();
    return !!row?.otp_hash;
  }

  async markYubikeyOtpUsed(otp: string): Promise<boolean> {
    const now = Date.now();
    await this.maybeCleanupUsedYubikeyOtps(now);
    const digest = await this.sha256Hex(otp);
    const result = await this.db
      .prepare('INSERT INTO used_yubikey_otps(otp_hash, used_at) VALUES(?, ?) ON CONFLICT(otp_hash) DO NOTHING')
      .bind(`sha256:${digest}`, now)
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  // --- Revision dates ---

  async getRevisionDate(userId: string): Promise<string> {
    return getStoredRevisionDate(this.db, userId);
  }

  async updateRevisionDate(userId: string): Promise<string> {
    return updateStoredRevisionDate(this.db, userId);
  }

  // --- One-time attachment download tokens ---

  private async ensureUsedAttachmentDownloadTokenTable(): Promise<void> {
    if (StorageService.attachmentTokenTableReady) return;
    await ensureStoredAttachmentTokenTable(this.db);

    StorageService.attachmentTokenTableReady = true;
  }

  // Marks an attachment download token JTI as consumed.
  // Returns true only on first use. Reuse returns false.
  async consumeAttachmentDownloadToken(jti: string, expUnixSeconds: number): Promise<boolean> {
    await this.ensureUsedAttachmentDownloadTokenTable();
    const result = await consumeStoredAttachmentDownloadToken(
      this.db,
      this.shouldRunPeriodicCleanup.bind(this),
      StorageService.lastAttachmentTokenCleanupAt,
      StorageService.ATTACHMENT_TOKEN_CLEANUP_INTERVAL_MS,
      jti,
      expUnixSeconds
    );
    if (result.cleanedUpAt !== null) {
      StorageService.lastAttachmentTokenCleanupAt = result.cleanedUpAt;
    }
    return result.consumed;
  }
}
