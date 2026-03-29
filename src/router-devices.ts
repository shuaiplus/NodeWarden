import type { Env } from './types';
import {
  handleGetAuthorizedDevices,
  handleGetDevice,
  handleGetDevices,
  handleGetDeviceByIdentifier,
  handleUpdateDeviceKeys,
  handleUpdateDeviceTrust,
  handleUntrustDevices,
  handleRetrieveDeviceKeys,
  handleDeactivateDevice,
  handleRevokeAllTrustedDevices,
  handleRevokeTrustedDevice,
  handleDeleteAllDevices,
  handleDeleteDevice,
  handleUpdateDeviceToken,
  handleUpdateDeviceWebPushAuth,
  handleClearDeviceToken,
} from './handlers/devices';

export async function handleAuthenticatedDeviceRoute(
  request: Request,
  env: Env,
  userId: string,
  path: string,
  method: string
): Promise<Response | null> {
  if (path === '/api/devices') {
    if (method === 'GET') return handleGetDevices(request, env, userId);
    if (method === 'DELETE') return handleDeleteAllDevices(request, env, userId);
    return null;
  }

  if (path === '/api/devices/authorized') {
    if (method === 'GET') return handleGetAuthorizedDevices(request, env, userId);
    if (method === 'DELETE') return handleRevokeAllTrustedDevices(request, env, userId);
    return null;
  }

  const authorizedDeviceMatch = path.match(/^\/api\/devices\/authorized\/([^/]+)$/i);
  if (authorizedDeviceMatch && method === 'DELETE') {
    const deviceIdentifier = decodeURIComponent(authorizedDeviceMatch[1]);
    return handleRevokeTrustedDevice(request, env, userId, deviceIdentifier);
  }

  const deleteDeviceMatch = path.match(/^\/api\/devices\/([^/]+)$/i);
  if (deleteDeviceMatch && method === 'GET') {
    const deviceIdentifier = decodeURIComponent(deleteDeviceMatch[1]);
    return handleGetDevice(request, env, userId, deviceIdentifier);
  }
  if (deleteDeviceMatch && method === 'DELETE') {
    const deviceIdentifier = decodeURIComponent(deleteDeviceMatch[1]);
    return handleDeleteDevice(request, env, userId, deviceIdentifier);
  }

  const identifierMatch = path.match(/^\/api\/devices\/identifier\/([^/]+)$/i);
  if (identifierMatch && method === 'GET') {
    const deviceIdentifier = decodeURIComponent(identifierMatch[1]);
    return handleGetDeviceByIdentifier(request, env, userId, deviceIdentifier);
  }

  const deviceKeysMatch = path.match(/^\/api\/devices\/([^/]+)\/keys$/i) || path.match(/^\/api\/devices\/identifier\/([^/]+)\/keys$/i);
  if (deviceKeysMatch && (method === 'PUT' || method === 'POST')) {
    const deviceIdentifier = decodeURIComponent(deviceKeysMatch[1]);
    return handleUpdateDeviceKeys(request, env, userId, deviceIdentifier);
  }

  const identifierTokenMatch = path.match(/^\/api\/devices\/identifier\/([^/]+)\/token$/i);
  if (identifierTokenMatch && (method === 'PUT' || method === 'POST')) {
    const deviceIdentifier = decodeURIComponent(identifierTokenMatch[1]);
    return handleUpdateDeviceToken(request, env, userId, deviceIdentifier);
  }

  const identifierWebPushMatch = path.match(/^\/api\/devices\/identifier\/([^/]+)\/web-push-auth$/i);
  if (identifierWebPushMatch && (method === 'PUT' || method === 'POST')) {
    const deviceIdentifier = decodeURIComponent(identifierWebPushMatch[1]);
    return handleUpdateDeviceWebPushAuth(request, env, userId, deviceIdentifier);
  }

  const identifierClearTokenMatch = path.match(/^\/api\/devices\/identifier\/([^/]+)\/clear-token$/i);
  if (identifierClearTokenMatch && (method === 'PUT' || method === 'POST')) {
    const deviceIdentifier = decodeURIComponent(identifierClearTokenMatch[1]);
    return handleClearDeviceToken(request, env, userId, deviceIdentifier);
  }

  const identifierRetrieveKeysMatch = path.match(/^\/api\/devices\/([^/]+)\/retrieve-keys$/i);
  if (identifierRetrieveKeysMatch && method === 'POST') {
    const deviceIdentifier = decodeURIComponent(identifierRetrieveKeysMatch[1]);
    return handleRetrieveDeviceKeys(request, env, userId, deviceIdentifier);
  }

  const identifierDeactivateMatch = path.match(/^\/api\/devices\/([^/]+)\/deactivate$/i);
  if (identifierDeactivateMatch && (method === 'POST' || method === 'DELETE')) {
    const deviceIdentifier = decodeURIComponent(identifierDeactivateMatch[1]);
    return handleDeactivateDevice(request, env, userId, deviceIdentifier);
  }

  if (path === '/api/devices/update-trust' && method === 'POST') {
    return handleUpdateDeviceTrust(request, env, userId);
  }

  if (path === '/api/devices/untrust' && method === 'POST') {
    return handleUntrustDevices(request, env, userId);
  }

  return null;
}
