import { DurableObject } from 'cloudflare:workers';
import type { Env } from '../types';

const SIGNALR_RECORD_SEPARATOR = 0x1e;
const SIGNALR_HANDSHAKE_ACK = new Uint8Array([0x7b, 0x7d, SIGNALR_RECORD_SEPARATOR]);
const SIGNALR_UPDATE_TYPE_SYNC_VAULT = 5;
const SIGNALR_UPDATE_TYPE_LOG_OUT = 11;
const SIGNALR_UPDATE_TYPE_DEVICE_STATUS = 12;
const SIGNALR_UPDATE_TYPE_BACKUP_RESTORE_PROGRESS = 13;

type HubProtocol = 'json' | 'messagepack';

interface WsAttachment {
  userId: string;
  handshakeComplete: boolean;
  protocol: HubProtocol;
  deviceIdentifier: string | null;
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function encodeUtf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function decodeIncomingMessage(data: string | ArrayBuffer | ArrayBufferView): string {
  if (typeof data === 'string') return data;
  if (data instanceof ArrayBuffer) return new TextDecoder().decode(new Uint8Array(data));
  return new TextDecoder().decode(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
}

function encodeMsgPackInteger(value: number): Uint8Array {
  const normalized = Math.trunc(value);
  if (normalized >= 0 && normalized <= 0x7f) {
    return new Uint8Array([normalized]);
  }
  if (normalized >= 0 && normalized <= 0xff) {
    return new Uint8Array([0xcc, normalized]);
  }
  if (normalized >= 0 && normalized <= 0xffff) {
    return new Uint8Array([0xcd, normalized >> 8, normalized & 0xff]);
  }
  const safe = normalized >>> 0;
  return new Uint8Array([
    0xce,
    (safe >>> 24) & 0xff,
    (safe >>> 16) & 0xff,
    (safe >>> 8) & 0xff,
    safe & 0xff,
  ]);
}

function encodeMsgPackString(value: string): Uint8Array {
  const bytes = encodeUtf8(value);
  const len = bytes.length;
  if (len < 32) {
    return concatBytes([new Uint8Array([0xa0 | len]), bytes]);
  }
  if (len <= 0xff) {
    return concatBytes([new Uint8Array([0xd9, len]), bytes]);
  }
  return concatBytes([new Uint8Array([0xda, (len >> 8) & 0xff, len & 0xff]), bytes]);
}

function encodeMsgPackTimestamp(date: Date): Uint8Array {
  const seconds = BigInt(Math.floor(date.getTime() / 1000));
  const nanos = BigInt(date.getMilliseconds()) * 1000000n;
  const timestamp = (nanos << 34n) | seconds;
  const payload = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    payload[i] = Number((timestamp >> BigInt((7 - i) * 8)) & 0xffn);
  }
  return concatBytes([new Uint8Array([0xc7, 0x08, 0xff]), payload]);
}

function encodeMsgPackArray(values: unknown[]): Uint8Array {
  const items = values.map(encodeMsgPack);
  const len = items.length;
  const header =
    len < 16
      ? new Uint8Array([0x90 | len])
      : new Uint8Array([0xdc, (len >> 8) & 0xff, len & 0xff]);
  return concatBytes([header, ...items]);
}

function encodeMsgPackMap(value: Record<string, unknown>): Uint8Array {
  const entries = Object.entries(value);
  const len = entries.length;
  const header =
    len < 16
      ? new Uint8Array([0x80 | len])
      : new Uint8Array([0xde, (len >> 8) & 0xff, len & 0xff]);
  const chunks: Uint8Array[] = [header];
  for (const [key, entryValue] of entries) {
    chunks.push(encodeMsgPackString(key), encodeMsgPack(entryValue));
  }
  return concatBytes(chunks);
}

function encodeMsgPack(value: unknown): Uint8Array {
  if (value === null || value === undefined) return new Uint8Array([0xc0]);
  if (value instanceof Date) return encodeMsgPackTimestamp(value);
  if (typeof value === 'string') return encodeMsgPackString(value);
  if (typeof value === 'number') return encodeMsgPackInteger(value);
  if (typeof value === 'boolean') return new Uint8Array([value ? 0xc3 : 0xc2]);
  if (Array.isArray(value)) return encodeMsgPackArray(value);
  if (value instanceof Uint8Array) {
    const len = value.length;
    if (len <= 0xff) return concatBytes([new Uint8Array([0xc4, len]), value]);
    return concatBytes([new Uint8Array([0xc5, (len >> 8) & 0xff, len & 0xff]), value]);
  }
  return encodeMsgPackMap(value as Record<string, unknown>);
}

function frameSignalRBinary(payload: Uint8Array): Uint8Array {
  const len = payload.length;
  const prefix: number[] = [];
  let value = len;
  do {
    let current = value & 0x7f;
    value >>>= 7;
    if (value > 0) current |= 0x80;
    prefix.push(current);
  } while (value > 0);
  return concatBytes([new Uint8Array(prefix), payload]);
}

function buildSignalRJsonInvocation(
  updateType: number,
  payload: Record<string, unknown>,
  contextId: string | null
): string {
  return JSON.stringify({
    type: 1,
    target: 'ReceiveMessage',
    arguments: [
        {
          ContextId: contextId,
          Type: updateType,
          Payload: payload,
        },
      ],
    }) + String.fromCharCode(SIGNALR_RECORD_SEPARATOR);
}

function buildSignalRMessagePackInvocation(
  updateType: number,
  messagePayload: Record<string, unknown>,
  contextId: string | null
): Uint8Array {
  // SignalR MessagePack hub protocol uses an array-based invocation shape:
  // [type, headers, invocationId, target, arguments]
  const encodedPayload = encodeMsgPack([
    1,
    {},
    null,
    'ReceiveMessage',
    [
      {
        ContextId: contextId,
        Type: updateType,
        Payload: messagePayload,
      },
    ],
  ]);
  return frameSignalRBinary(encodedPayload);
}

export class NotificationsHub extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.setWebSocketAutoResponse(
      new WebSocketRequestResponsePair(
        JSON.stringify({ type: 6 }) + String.fromCharCode(SIGNALR_RECORD_SEPARATOR),
        JSON.stringify({ type: 6 }) + String.fromCharCode(SIGNALR_RECORD_SEPARATOR)
      )
    );
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/internal/notify' && request.method === 'POST') {
      const body = (await request.json().catch(() => null)) as {
        revisionDate?: string;
        userId?: string;
        contextId?: string | null;
        updateType?: number;
        targetDeviceIdentifier?: string | null;
        payload?: Record<string, unknown> | null;
      } | null;
      const revisionDate = String(body?.revisionDate || '').trim() || new Date().toISOString();
      const userId = String(request.headers.get('X-NodeWarden-UserId') || body?.userId || '').trim();
      const contextId = String(body?.contextId || '').trim() || null;
      const updateType = Number(body?.updateType || SIGNALR_UPDATE_TYPE_SYNC_VAULT) || SIGNALR_UPDATE_TYPE_SYNC_VAULT;
      const targetDeviceIdentifier = String(body?.targetDeviceIdentifier || '').trim() || null;
      const payload = body?.payload && typeof body.payload === 'object'
        ? body.payload
        : {
          UserId: userId,
          Date: revisionDate,
        };
      this.broadcastMessage(updateType, payload, contextId, targetDeviceIdentifier);
      return new Response(null, { status: 204 });
    }

    if (url.pathname === '/internal/online' && request.method === 'GET') {
      return new Response(JSON.stringify({ deviceIdentifiers: this.getOnlineDeviceIdentifiers() }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
        },
      });
    }

    if (url.pathname !== '/notifications/hub') {
      return new Response('Not found', { status: 404 });
    }

    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
      return new Response('Expected websocket', { status: 426 });
    }

    const requestUserId = String(url.searchParams.get('nw_uid') || '').trim();
    const requestDeviceIdentifier = String(url.searchParams.get('nw_did') || '').trim() || null;

    if (!requestUserId) {
      return new Response('Unauthorized', { status: 401 });
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];

    const tags: string[] = [];
    if (requestDeviceIdentifier) {
      tags.push(`device:${requestDeviceIdentifier}`);
    }
    this.ctx.acceptWebSocket(server, tags);

    server.serializeAttachment({
      userId: requestUserId,
      handshakeComplete: false,
      protocol: 'messagepack',
      deviceIdentifier: requestDeviceIdentifier,
    } satisfies WsAttachment);

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer | ArrayBufferView): Promise<void> {
    const attachment = ws.deserializeAttachment() as WsAttachment | null;
    if (!attachment) return;

    if (!attachment.handshakeComplete) {
      const text = decodeIncomingMessage(message);
      const frames = text.split(String.fromCharCode(SIGNALR_RECORD_SEPARATOR)).filter(Boolean);
      for (const frame of frames) {
        try {
          const handshake = JSON.parse(frame) as { protocol?: string };
          attachment.protocol = handshake.protocol === 'json' ? 'json' : 'messagepack';
          attachment.handshakeComplete = true;
          ws.serializeAttachment(attachment);
          ws.send(SIGNALR_HANDSHAKE_ACK);
          this.broadcastDeviceStatus(attachment.userId);
          return;
        } catch {
          // Ignore malformed pre-handshake payloads.
        }
      }
      return;
    }

    if (typeof message !== 'string') {
      try {
        ws.send(message);
      } catch {
        // ignore send errors on echo
      }
    }
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean): Promise<void> {
    const attachment = ws.deserializeAttachment() as WsAttachment | null;
    const shouldBroadcast = !!attachment?.handshakeComplete;
    if (shouldBroadcast && attachment?.userId) {
      this.broadcastDeviceStatus(attachment.userId);
    }
  }

  async webSocketError(ws: WebSocket, error: unknown): Promise<void> {
    const attachment = ws.deserializeAttachment() as WsAttachment | null;
    const shouldBroadcast = !!attachment?.handshakeComplete;
    if (shouldBroadcast && attachment?.userId) {
      this.broadcastDeviceStatus(attachment.userId);
    }
  }

  private getOnlineDeviceIdentifiers(): string[] {
    const out = new Set<string>();
    for (const ws of this.ctx.getWebSockets()) {
      const attachment = ws.deserializeAttachment() as WsAttachment | null;
      if (!attachment?.handshakeComplete || !attachment.deviceIdentifier) continue;
      out.add(attachment.deviceIdentifier);
    }
    return Array.from(out);
  }

  private broadcastMessage(
    updateType: number,
    payload: Record<string, unknown>,
    contextId: string | null,
    targetDeviceIdentifier: string | null
  ): void {
    const sockets = targetDeviceIdentifier
      ? this.ctx.getWebSockets(`device:${targetDeviceIdentifier}`)
      : this.ctx.getWebSockets();

    if (sockets.length === 0) return;

    for (const ws of sockets) {
      const attachment = ws.deserializeAttachment() as WsAttachment | null;
      if (!attachment?.handshakeComplete) continue;
      try {
        if (attachment.protocol === 'json') {
          ws.send(buildSignalRJsonInvocation(updateType, payload, contextId));
        } else {
          ws.send(buildSignalRMessagePackInvocation(updateType, payload, contextId));
        }
      } catch {
        try {
          ws.close(1011, 'Notification send failed');
        } catch {
          // ignore close races
        }
      }
    }
  }

  private broadcastDeviceStatus(userId: string): void {
    this.broadcastMessage(
      SIGNALR_UPDATE_TYPE_DEVICE_STATUS,
      {
        UserId: userId,
        Date: new Date().toISOString(),
      },
      null,
      null
    );
  }
}

export async function notifyUserVaultSync(
  env: Env,
  userId: string,
  revisionDate: string,
  contextId?: string | null
): Promise<void> {
  return notifyUserUpdate(env, userId, SIGNALR_UPDATE_TYPE_SYNC_VAULT, revisionDate, contextId ?? null, null);
}

export async function notifyUserLogout(
  env: Env,
  userId: string,
  targetDeviceIdentifier?: string | null
): Promise<void> {
  return notifyUserUpdate(env, userId, SIGNALR_UPDATE_TYPE_LOG_OUT, new Date().toISOString(), null, targetDeviceIdentifier ?? null);
}

export async function getOnlineUserDevices(env: Env, userId: string): Promise<string[]> {
  try {
    const id = env.NOTIFICATIONS_HUB.idFromName(userId);
    const stub = env.NOTIFICATIONS_HUB.get(id);
    const response = await stub.fetch('https://notifications/internal/online');
    if (!response.ok) return [];
    const body = (await response.json().catch(() => null)) as { deviceIdentifiers?: string[] } | null;
    return Array.isArray(body?.deviceIdentifiers) ? body.deviceIdentifiers.filter((value) => !!String(value || '').trim()) : [];
  } catch {
    return [];
  }
}

async function notifyUserUpdate(
  env: Env,
  userId: string,
  updateType: number,
  revisionDate: string,
  contextId: string | null,
  targetDeviceIdentifier: string | null
): Promise<void> {
  try {
    const id = env.NOTIFICATIONS_HUB.idFromName(userId);
    const stub = env.NOTIFICATIONS_HUB.get(id);
    await stub.fetch('https://notifications/internal/notify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-NodeWarden-UserId': userId,
      },
      body: JSON.stringify({
        revisionDate,
        contextId: contextId || null,
        updateType,
        targetDeviceIdentifier: targetDeviceIdentifier || null,
        payload: {
          UserId: userId,
          Date: revisionDate,
        },
      }),
    });
  } catch (error) {
    console.error('Failed to broadcast realtime notification:', error);
  }
}

export async function notifyUserBackupProgress(
  env: Env,
  userId: string,
  progress: {
    operation: 'backup-restore' | 'backup-export' | 'backup-remote-run';
    source?: 'local' | 'remote';
    step: string;
    fileName: string;
    stageTitle?: string;
    stageDetail?: string;
    replaceExisting?: boolean;
    done?: boolean;
    ok?: boolean;
    error?: string | null;
    timestamp?: string;
  },
  targetDeviceIdentifier?: string | null
): Promise<void> {
  const revisionDate = progress.timestamp || new Date().toISOString();
  try {
    const id = env.NOTIFICATIONS_HUB.idFromName(userId);
    const stub = env.NOTIFICATIONS_HUB.get(id);
    await stub.fetch('https://notifications/internal/notify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-NodeWarden-UserId': userId,
      },
      body: JSON.stringify({
        revisionDate,
        contextId: null,
        updateType: SIGNALR_UPDATE_TYPE_BACKUP_RESTORE_PROGRESS,
        targetDeviceIdentifier: targetDeviceIdentifier || null,
        payload: {
          UserId: userId,
          Date: revisionDate,
          ...progress,
        },
      }),
    });
  } catch (error) {
    console.error('Failed to broadcast backup progress:', error);
  }
}

export async function notifyUserBackupRestoreProgress(
  env: Env,
  userId: string,
  progress: {
    operation: 'backup-restore';
    source: 'local' | 'remote';
    step: string;
    fileName: string;
    stageTitle?: string;
    stageDetail?: string;
    replaceExisting?: boolean;
    done?: boolean;
    ok?: boolean;
    error?: string | null;
    timestamp?: string;
  },
  targetDeviceIdentifier?: string | null
): Promise<void> {
  return notifyUserBackupProgress(env, userId, progress, targetDeviceIdentifier);
}
