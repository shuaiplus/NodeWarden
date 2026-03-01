import { Env, JWTPayload, User } from '../types';
import { verifyJWT, createJWT, createRefreshToken } from '../utils/jwt';
import { StorageService } from './storage';

// Server-side iterations for second-layer hashing.
// The client already does heavy PBKDF2 (600k iterations).
// This second layer only needs to be non-trivial, not expensive.
const SERVER_HASH_ITERATIONS = 100_000;

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
  async generateAccessToken(user: User): Promise<string> {
    return createJWT(
      {
        sub: user.id,
        email: user.email,
        name: user.name,
        sstamp: user.securityStamp,
      },
      this.env.JWT_SECRET
    );
  }

  // Generate refresh token
  async generateRefreshToken(userId: string): Promise<string> {
    const token = createRefreshToken();
    await this.storage.saveRefreshToken(token, userId);
    return token;
  }

  // Verify access token from Authorization header
  async verifyAccessToken(authHeader: string | null): Promise<JWTPayload | null> {
    if (!authHeader) return null;

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
      return null;
    }

    const payload = await verifyJWT(parts[1], this.env.JWT_SECRET);
    if (!payload) return null;

    // Verify security stamp - ensures token is invalidated after password change
    const user = await this.storage.getUserById(payload.sub);
    if (!user) return null;
    
    if (payload.sstamp !== user.securityStamp) {
      return null; // Token was issued before password change
    }

    return payload;
  }

  // Refresh access token
  async refreshAccessToken(refreshToken: string): Promise<{ accessToken: string; user: User } | null> {
    const userId = await this.storage.getRefreshTokenUserId(refreshToken);
    if (!userId) return null;

    const user = await this.storage.getUserById(userId);
    if (!user) return null;
    if (user.status !== 'active') {
      await this.storage.deleteRefreshToken(refreshToken);
      return null;
    }

    const accessToken = await this.generateAccessToken(user);
    return { accessToken, user };
  }
}
