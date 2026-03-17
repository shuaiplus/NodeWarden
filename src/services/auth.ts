import { Env, JWTPayload, User } from '../types';
import { verifyJWT, createJWT, createRefreshToken } from '../utils/jwt';
import { StorageService } from './storage';

// Server-side iterations for second-layer hashing.
// The client already does heavy PBKDF2 (600k iterations).
// This second layer only needs to be non-trivial, not expensive.
const SERVER_HASH_ITERATIONS = 100_000;

export interface VerifiedAccessContext {
  payload: JWTPayload;
  user: User;
}

export class AuthService {
  private storage: StorageService;

  constructor(private env: Env) {
    this.storage = new StorageService(env.DB);
  }

  // Second-layer hash: PBKDF2-SHA256(clientHash, email-salt, iterations).
  // Ensures database contents alone cannot be used to authenticate (pass-the-hash defense).
  // Result is prefixed with "$s$" to distinguish from legacy raw client hashes.
  async hashPasswordServer(clientHash: string, email: string): Promise<string> {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(clientHash),
      'PBKDF2',
      false,
      ['deriveBits']
    );
    const salt = new TextEncoder().encode(email.toLowerCase().trim());
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: SERVER_HASH_ITERATIONS },
      keyMaterial,
      256
    );
    const bytes = new Uint8Array(bits);
    let binary = '';
    for (const b of bytes) binary += String.fromCharCode(b);
    return '$s$' + btoa(binary);
  }

  // Verify password: hash the input the same way, then constant-time compare.
  async verifyPassword(inputHash: string, storedHash: string, email?: string): Promise<boolean> {
    // New server-hashed passwords are prefixed with "$s$".
    // Legacy accounts (created before the upgrade) store raw client hashes without prefix.
    if (email && storedHash.startsWith('$s$')) {
      const serverHash = await this.hashPasswordServer(inputHash, email);
      return this.constantTimeEquals(serverHash, storedHash);
    }
    // Legacy path: direct constant-time comparison of raw client hashes.
    return this.constantTimeEquals(inputHash, storedHash);
  }

  private constantTimeEquals(a: string, b: string): boolean {
    const encA = new TextEncoder().encode(a);
    const encB = new TextEncoder().encode(b);
    if (encA.length !== encB.length) return false;
    let diff = 0;
    for (let i = 0; i < encA.length; i++) {
      diff |= encA[i] ^ encB[i];
    }
    return diff === 0;
  }

  // Generate access token
  async generateAccessToken(user: User, device?: { identifier: string; sessionStamp: string } | null): Promise<string> {
    return createJWT(
      {
        sub: user.id,
        email: user.email,
        name: user.name,
        sstamp: user.securityStamp,
        ...(device?.identifier ? { did: device.identifier, dstamp: device.sessionStamp } : {}),
      },
      this.env.JWT_SECRET
    );
  }

  // Generate refresh token
  async generateRefreshToken(userId: string, device?: { identifier: string; sessionStamp: string } | null): Promise<string> {
    const token = createRefreshToken();
    await this.storage.saveRefreshToken(token, userId, undefined, device?.identifier ?? null, device?.sessionStamp ?? null);
    return token;
  }

  async verifyAccessTokenWithUser(authHeader: string | null): Promise<VerifiedAccessContext | null> {
    if (!authHeader) return null;

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
      return null;
    }

    const payload = await verifyJWT(parts[1], this.env.JWT_SECRET);
    if (!payload) return null;

    const user = await this.storage.getUserById(payload.sub);
    if (!user) return null;

    if (payload.sstamp !== user.securityStamp) {
      return null;
    }

    if (payload.did) {
      const device = await this.storage.getDevice(user.id, payload.did);
      if (!device) return null;
      if (!payload.dstamp || payload.dstamp !== device.sessionStamp) return null;
    }

    return { payload, user };
  }

  // Verify access token from Authorization header
  async verifyAccessToken(authHeader: string | null): Promise<JWTPayload | null> {
    const verified = await this.verifyAccessTokenWithUser(authHeader);
    return verified?.payload ?? null;
  }

  // Refresh access token
  async refreshAccessToken(
    refreshToken: string
  ): Promise<{ accessToken: string; user: User; device: { identifier: string; sessionStamp: string } | null } | null> {
    const record = await this.storage.getRefreshTokenRecord(refreshToken);
    if (!record?.userId) return null;

    const user = await this.storage.getUserById(record.userId);
    if (!user) return null;
    if (user.status !== 'active') {
      await this.storage.deleteRefreshToken(refreshToken);
      return null;
    }

    let device: { identifier: string; sessionStamp: string } | null = null;
    if (record.deviceIdentifier) {
      const boundDevice = await this.storage.getDevice(user.id, record.deviceIdentifier);
      if (!boundDevice) {
        await this.storage.deleteRefreshToken(refreshToken);
        return null;
      }
      if (!record.deviceSessionStamp || boundDevice.sessionStamp !== record.deviceSessionStamp) {
        await this.storage.deleteRefreshToken(refreshToken);
        return null;
      }
      device = { identifier: boundDevice.deviceIdentifier, sessionStamp: boundDevice.sessionStamp };
    }

    const accessToken = await this.generateAccessToken(user, device);
    return { accessToken, user, device };
  }
}
