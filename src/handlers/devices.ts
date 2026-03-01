import { Env } from '../types';
import { StorageService } from '../services/storage';
import { errorResponse, jsonResponse } from '../utils/response';
import { readKnownDeviceProbe } from '../utils/device';

// GET /api/devices/knowndevice
// Compatible with Bitwarden/Vaultwarden behavior:
// - X-Request-Email: base64url(email) without padding
// - X-Device-Identifier: client device identifier
export async function handleKnownDevice(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);
  const { email, deviceIdentifier } = readKnownDeviceProbe(request);

  if (!email || !deviceIdentifier) {
    return jsonResponse(false);
  }

  const known = await storage.isKnownDeviceByEmail(email, deviceIdentifier);
  return jsonResponse(known);
}

// GET /api/devices
export async function handleGetDevices(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const devices = await storage.getDevicesByUserId(userId);

  return jsonResponse({
    data: devices.map(device => ({
      id: device.deviceIdentifier,
      name: device.name,
      identifier: device.deviceIdentifier,
      type: device.type,
      creationDate: device.createdAt,
      revisionDate: device.updatedAt,
      object: 'device',
    })),
    object: 'list',
    continuationToken: null,
  });
}

// GET /api/devices/authorized
// Returns known devices together with active 2FA remember-token expiry.
export async function handleGetAuthorizedDevices(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const [devices, trusted] = await Promise.all([
    storage.getDevicesByUserId(userId),
    storage.getTrustedDeviceTokenSummariesByUserId(userId),
  ]);

  const trustedByIdentifier = new Map<string, { expiresAt: number; tokenCount: number }>();
  for (const row of trusted) {
    trustedByIdentifier.set(row.deviceIdentifier, { expiresAt: row.expiresAt, tokenCount: row.tokenCount });
  }

  const knownIdentifiers = new Set<string>();
  const data = devices.map(device => {
    knownIdentifiers.add(device.deviceIdentifier);
    const trustedInfo = trustedByIdentifier.get(device.deviceIdentifier);
    return {
      id: device.deviceIdentifier,
      name: device.name,
      identifier: device.deviceIdentifier,
      type: device.type,
      creationDate: device.createdAt,
      revisionDate: device.updatedAt,
      trusted: !!trustedInfo,
      trustedTokenCount: trustedInfo?.tokenCount || 0,
      trustedUntil: trustedInfo?.expiresAt ? new Date(trustedInfo.expiresAt).toISOString() : null,
      object: 'device',
    };
  });

  for (const row of trusted) {
    if (knownIdentifiers.has(row.deviceIdentifier)) continue;
    data.push({
      id: row.deviceIdentifier,
      name: 'Unknown device',
      identifier: row.deviceIdentifier,
      type: 14,
      creationDate: '',
      revisionDate: '',
      trusted: true,
      trustedTokenCount: row.tokenCount,
      trustedUntil: row.expiresAt ? new Date(row.expiresAt).toISOString() : null,
      object: 'device',
    });
  }

  return jsonResponse({
    data,
    object: 'list',
    continuationToken: null,
  });
}

// DELETE /api/devices/authorized
export async function handleRevokeAllTrustedDevices(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const removed = await storage.deleteTrustedTwoFactorTokensByUserId(userId);
  return jsonResponse({ success: true, removed });
}

// DELETE /api/devices/authorized/:deviceIdentifier
export async function handleRevokeTrustedDevice(
  request: Request,
  env: Env,
  userId: string,
  deviceIdentifier: string
): Promise<Response> {
  void request;
  const normalized = String(deviceIdentifier || '').trim();
  if (!normalized) return errorResponse('Invalid device identifier', 400);

  const storage = new StorageService(env.DB);
  const removed = await storage.deleteTrustedTwoFactorTokensByDevice(userId, normalized);
  return jsonResponse({ success: true, removed });
}

// DELETE /api/devices/:deviceIdentifier
export async function handleDeleteDevice(
  request: Request,
  env: Env,
  userId: string,
  deviceIdentifier: string
): Promise<Response> {
  void request;
  const normalized = String(deviceIdentifier || '').trim();
  if (!normalized) return errorResponse('Invalid device identifier', 400);

  const storage = new StorageService(env.DB);
  await storage.deleteTrustedTwoFactorTokensByDevice(userId, normalized);
  const deleted = await storage.deleteDevice(userId, normalized);
  return jsonResponse({ success: deleted });
}

// PUT /api/devices/identifier/{deviceIdentifier}/token
// Bitwarden mobile reports push token updates to this endpoint.
// NodeWarden does not implement push notifications, so accept and no-op.
export async function handleUpdateDeviceToken(
  request: Request,
  env: Env,
  userId: string,
  deviceIdentifier: string
): Promise<Response> {
  void request;
  void env;
  void userId;
  void deviceIdentifier;
  return new Response(null, { status: 200 });
}

