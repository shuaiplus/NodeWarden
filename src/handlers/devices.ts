import type { Device, DevicePendingAuthRequest, DeviceResponse, ProtectedDeviceResponse as ProtectedDeviceWireResponse } from '../types';
import { Env } from '../types';
import { getOnlineUserDevices, notifyUserLogout } from '../durable/notifications-hub';
import { StorageService } from '../services/storage';
import { errorResponse, jsonResponse } from '../utils/response';
import { readKnownDeviceProbe } from '../utils/device';
import { generateUUID } from '../utils/uuid';

function normalizeIdentifier(value: string | null | undefined): string {
  return String(value || '').trim();
}

function buildDevicePendingAuthRequest(value?: { id?: string | null; creationDate?: string | null } | null): DevicePendingAuthRequest | null {
  if (!value?.id || !value.creationDate) return null;
  return {
    id: String(value.id),
    creationDate: String(value.creationDate),
  };
}

function isTrustedDevice(device: Pick<Device, 'encryptedUserKey' | 'encryptedPublicKey'>): boolean {
  return !!(device.encryptedUserKey && device.encryptedPublicKey);
}

function buildDeviceResponse(device: Device): DeviceResponse {
  const response = {
    Id: device.deviceIdentifier,
    id: device.deviceIdentifier,
    UserId: device.userId,
    userId: device.userId,
    Name: device.name,
    name: device.name,
    Identifier: device.deviceIdentifier,
    identifier: device.deviceIdentifier,
    Type: device.type,
    type: device.type,
    CreationDate: device.createdAt,
    creationDate: device.createdAt,
    RevisionDate: device.updatedAt,
    revisionDate: device.updatedAt,
    IsTrusted: isTrustedDevice(device),
    isTrusted: isTrustedDevice(device),
    EncryptedUserKey: device.encryptedUserKey,
    encryptedUserKey: device.encryptedUserKey,
    EncryptedPublicKey: device.encryptedPublicKey,
    encryptedPublicKey: device.encryptedPublicKey,
    DevicePendingAuthRequest: buildDevicePendingAuthRequest(device.devicePendingAuthRequest),
    devicePendingAuthRequest: buildDevicePendingAuthRequest(device.devicePendingAuthRequest),
    object: 'device',
  };
  return response as DeviceResponse;
}

function buildProtectedDeviceResponse(device: Device): ProtectedDeviceWireResponse {
  const response = {
    Id: device.deviceIdentifier,
    id: device.deviceIdentifier,
    Name: device.name,
    name: device.name,
    Identifier: device.deviceIdentifier,
    identifier: device.deviceIdentifier,
    Type: device.type,
    type: device.type,
    CreationDate: device.createdAt,
    creationDate: device.createdAt,
    EncryptedUserKey: device.encryptedUserKey,
    encryptedUserKey: device.encryptedUserKey,
    EncryptedPublicKey: device.encryptedPublicKey,
    encryptedPublicKey: device.encryptedPublicKey,
    object: 'protectedDevice',
  };
  return response as ProtectedDeviceWireResponse;
}

function parseKeysBody(body: any, fallback?: Device): {
  encryptedUserKey?: string | null;
  encryptedPublicKey?: string | null;
  encryptedPrivateKey?: string | null;
} {
  return {
    encryptedUserKey:
      Object.prototype.hasOwnProperty.call(body || {}, 'encryptedUserKey')
        ? body?.encryptedUserKey ?? null
        : fallback?.encryptedUserKey ?? null,
    encryptedPublicKey:
      Object.prototype.hasOwnProperty.call(body || {}, 'encryptedPublicKey')
        ? body?.encryptedPublicKey ?? null
        : fallback?.encryptedPublicKey ?? null,
    encryptedPrivateKey:
      Object.prototype.hasOwnProperty.call(body || {}, 'encryptedPrivateKey')
        ? body?.encryptedPrivateKey ?? null
        : fallback?.encryptedPrivateKey ?? null,
  };
}

async function readJsonBody(request: Request): Promise<any> {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

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
    data: devices.map((device) => buildDeviceResponse(device)),
    object: 'list',
    continuationToken: null,
  });
}

// GET /api/devices/identifier/:deviceIdentifier
export async function handleGetDeviceByIdentifier(
  request: Request,
  env: Env,
  userId: string,
  deviceIdentifier: string
): Promise<Response> {
  void request;
  const normalized = normalizeIdentifier(deviceIdentifier);
  if (!normalized) return errorResponse('Invalid device identifier', 400);

  const storage = new StorageService(env.DB);
  const device = await storage.getDevice(userId, normalized);
  if (!device) {
    return errorResponse('Device not found', 404);
  }

  return jsonResponse(buildDeviceResponse(device));
}

// GET /api/devices/:deviceIdentifier
export async function handleGetDevice(
  request: Request,
  env: Env,
  userId: string,
  deviceIdentifier: string
): Promise<Response> {
  return handleGetDeviceByIdentifier(request, env, userId, deviceIdentifier);
}

// GET /api/devices/authorized
// Returns known devices together with active 2FA remember-token expiry.
export async function handleGetAuthorizedDevices(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const [devices, trusted, onlineDeviceIdentifiers] = await Promise.all([
    storage.getDevicesByUserId(userId),
    storage.getTrustedDeviceTokenSummariesByUserId(userId),
    getOnlineUserDevices(env, userId),
  ]);
  const onlineSet = new Set(onlineDeviceIdentifiers);

  const trustedByIdentifier = new Map<string, { expiresAt: number; tokenCount: number }>();
  for (const row of trusted) {
    trustedByIdentifier.set(row.deviceIdentifier, { expiresAt: row.expiresAt, tokenCount: row.tokenCount });
  }

  const knownIdentifiers = new Set<string>();
  const data = devices.map(device => {
    knownIdentifiers.add(device.deviceIdentifier);
    const trustedInfo = trustedByIdentifier.get(device.deviceIdentifier);
    return {
      ...buildDeviceResponse(device),
      online: onlineSet.has(device.deviceIdentifier),
      trusted: !!trustedInfo,
      trustedTokenCount: trustedInfo?.tokenCount || 0,
      trustedUntil: trustedInfo?.expiresAt ? new Date(trustedInfo.expiresAt).toISOString() : null,
      object: 'device',
    };
  });

  for (const row of trusted) {
    if (knownIdentifiers.has(row.deviceIdentifier)) continue;
    const placeholderDevice: Device = {
      userId,
      deviceIdentifier: row.deviceIdentifier,
      name: 'Unknown device',
      type: 14,
      sessionStamp: '',
      encryptedUserKey: null,
      encryptedPublicKey: null,
      encryptedPrivateKey: null,
      devicePendingAuthRequest: null,
      createdAt: '',
      updatedAt: '',
    };
    data.push({
      ...buildDeviceResponse(placeholderDevice),
      isTrusted: true,
      online: onlineSet.has(row.deviceIdentifier),
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
  await storage.deleteRefreshTokensByDevice(userId, normalized);
  const deleted = await storage.deleteDevice(userId, normalized);
  if (deleted) {
    await notifyUserLogout(env, userId, normalized);
  }
  return jsonResponse({ success: deleted });
}

// DELETE /api/devices
export async function handleDeleteAllDevices(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  const [removedTrusted, removedSessions, removedDevices] = await Promise.all([
    storage.deleteTrustedTwoFactorTokensByUserId(userId),
    storage.deleteRefreshTokensByUserId(userId),
    storage.deleteDevicesByUserId(userId),
  ]);
  user.securityStamp = generateUUID();
  user.updatedAt = new Date().toISOString();
  await storage.saveUser(user);
  await notifyUserLogout(env, userId, null);
  return jsonResponse({ success: true, removedTrusted, removedSessions: removedSessions ?? 0, removedDevices });
}

// PUT/POST /api/devices/identifier/:deviceIdentifier/keys
export async function handleUpdateDeviceKeys(
  request: Request,
  env: Env,
  userId: string,
  deviceIdentifier: string
): Promise<Response> {
  const normalized = normalizeIdentifier(deviceIdentifier);
  if (!normalized) return errorResponse('Invalid device identifier', 400);

  const body = await readJsonBody(request);
  const storage = new StorageService(env.DB);
  const device = await storage.getDevice(userId, normalized);
  if (!device) {
    return errorResponse('Device not found', 404);
  }

  const updated = await storage.updateDeviceKeys(userId, normalized, parseKeysBody(body, device));
  if (!updated) {
    return errorResponse('Device not found', 404);
  }

  const nextDevice = await storage.getDevice(userId, normalized);
  return jsonResponse(buildDeviceResponse(nextDevice || device));
}

// POST /api/devices/update-trust
export async function handleUpdateDeviceTrust(
  request: Request,
  env: Env,
  userId: string
): Promise<Response> {
  const body = await readJsonBody(request);
  const storage = new StorageService(env.DB);
  const currentDeviceIdentifier =
    normalizeIdentifier(request.headers.get('Device-Identifier')) ||
    normalizeIdentifier(request.headers.get('X-Device-Identifier'));

  const updates: Array<{
    deviceIdentifier: string;
    keys: {
      encryptedUserKey?: string | null;
      encryptedPublicKey?: string | null;
      encryptedPrivateKey?: string | null;
    };
  }> = [];

  if (currentDeviceIdentifier && body?.currentDevice) {
    updates.push({
      deviceIdentifier: currentDeviceIdentifier,
      keys: parseKeysBody(body.currentDevice, await storage.getDevice(userId, currentDeviceIdentifier) || undefined),
    });
  }

  if (Array.isArray(body?.otherDevices)) {
    for (const item of body.otherDevices) {
      const deviceIdentifier = normalizeIdentifier(item?.deviceId);
      if (!deviceIdentifier) continue;
      updates.push({
        deviceIdentifier,
        keys: parseKeysBody(item, await storage.getDevice(userId, deviceIdentifier) || undefined),
      });
    }
  }

  let updatedCount = 0;
  for (const update of updates) {
    const ok = await storage.updateDeviceKeys(userId, update.deviceIdentifier, update.keys);
    if (ok) updatedCount++;
  }

  return jsonResponse({ success: true, updated: updatedCount });
}

// POST /api/devices/untrust
export async function handleUntrustDevices(
  request: Request,
  env: Env,
  userId: string
): Promise<Response> {
  const body = await readJsonBody(request);
  const storage = new StorageService(env.DB);
  const devices = Array.isArray(body?.devices) ? body.devices.map((id: unknown) => normalizeIdentifier(String(id))) : [];
  const removed = await storage.clearDeviceKeys(userId, devices);
  for (const deviceIdentifier of devices) {
    if (!deviceIdentifier) continue;
    await storage.deleteTrustedTwoFactorTokensByDevice(userId, deviceIdentifier);
  }
  return jsonResponse({ success: true, removed });
}

// POST /api/devices/:deviceIdentifier/retrieve-keys
export async function handleRetrieveDeviceKeys(
  request: Request,
  env: Env,
  userId: string,
  deviceIdentifier: string
): Promise<Response> {
  void request;
  const normalized = normalizeIdentifier(deviceIdentifier);
  if (!normalized) return errorResponse('Invalid device identifier', 400);

  const storage = new StorageService(env.DB);
  const device = await storage.getDevice(userId, normalized);
  if (!device) {
    return errorResponse('Device not found', 404);
  }

  return jsonResponse(buildProtectedDeviceResponse(device));
}

// POST /api/devices/:id/deactivate
export async function handleDeactivateDevice(
  request: Request,
  env: Env,
  userId: string,
  deviceIdentifier: string
): Promise<Response> {
  void request;
  const normalized = normalizeIdentifier(deviceIdentifier);
  if (!normalized) return errorResponse('Invalid device identifier', 400);

  const storage = new StorageService(env.DB);
  await storage.deleteTrustedTwoFactorTokensByDevice(userId, normalized);
  await storage.deleteRefreshTokensByDevice(userId, normalized);
  const deleted = await storage.deleteDevice(userId, normalized);
  if (deleted) {
    await notifyUserLogout(env, userId, normalized);
  }
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

// PUT/POST /api/devices/:deviceIdentifier/web-push-auth
export async function handleUpdateDeviceWebPushAuth(
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

// PUT/POST /api/devices/:deviceIdentifier/clear-token
export async function handleClearDeviceToken(
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

