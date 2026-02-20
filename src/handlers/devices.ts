import { Env } from '../types';
import { StorageService } from '../services/storage';
import { jsonResponse } from '../utils/response';
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

