import { Env } from '../types';

const DEFAULT_CONTENT_TYPE = 'application/octet-stream';
export const KV_MAX_OBJECT_BYTES = 25 * 1024 * 1024;

interface KVBlobMetadata {
  size?: number;
  contentType?: string;
  customMetadata?: Record<string, string> | null;
}

export interface BlobObject {
  body: ReadableStream | null;
  size: number;
  contentType: string;
}

export interface PutBlobOptions {
  size: number;
  contentType?: string;
  customMetadata?: Record<string, string>;
}

function hasR2Storage(env: Env): env is Env & { ATTACHMENTS: R2Bucket } {
  return !!env.ATTACHMENTS;
}

function hasKvStorage(env: Env): env is Env & { ATTACHMENTS_KV: KVNamespace } {
  return !!env.ATTACHMENTS_KV;
}

function hasLocalStorage(env: Env): env is Env & { LOCAL_ATTACHMENTS_DIR: string } {
  return !!env.LOCAL_ATTACHMENTS_DIR;
}

export function getBlobStorageKind(env: Env): 'r2' | 'kv' | 'local' | null {
  // Prefer local when configured
  if (hasLocalStorage(env)) return 'local';
  // Keep R2 as preferred backend when both are bound.
  if (hasR2Storage(env)) return 'r2';
  if (hasKvStorage(env)) return 'kv';
  return null;
}

export function getBlobStorageMaxBytes(env: Env, configuredLimit: number): number {
  if (getBlobStorageKind(env) === 'kv') {
    return Math.min(configuredLimit, KV_MAX_OBJECT_BYTES);
  }
  return configuredLimit;
}

export function getAttachmentObjectKey(cipherId: string, attachmentId: string): string {
  return `${cipherId}/${attachmentId}`;
}

export function getSendFileObjectKey(sendId: string, fileId: string): string {
  return `sends/${sendId}/${fileId}`;
}

export async function putBlobObject(
  env: Env,
  key: string,
  value: string | ArrayBuffer | ArrayBufferView | ReadableStream,
  options: PutBlobOptions
): Promise<void> {
  const contentType = options.contentType || DEFAULT_CONTENT_TYPE;

  if (hasR2Storage(env)) {
    await env.ATTACHMENTS.put(key, value, {
      httpMetadata: { contentType },
      customMetadata: options.customMetadata,
    });
    return;
  }

  if (hasKvStorage(env)) {
    if (options.size > KV_MAX_OBJECT_BYTES) {
      throw new Error('KV object too large');
    }
    const metadata: KVBlobMetadata = {
      size: options.size,
      contentType,
      customMetadata: options.customMetadata || null,
    };
    await env.ATTACHMENTS_KV.put(key, value, { metadata });
    return;
  }

  if (hasLocalStorage(env)) {
    const fs = await import('fs/promises');
    const path = await import('path');
    const fullPath = path.join(env.LOCAL_ATTACHMENTS_DIR, key);
    let buffer: Buffer;
    if (value instanceof ReadableStream) {
      // Consume the stream into memory since Node doesn't naturally write Web Streams to fs easily in all versions without util.stream
      const reader = value.getReader();
      const chunks: Uint8Array[] = [];
      while (true) {
        const { done, value: chunk } = await reader.read();
        if (done) break;
        if (chunk) chunks.push(chunk);
      }
      buffer = Buffer.concat(chunks);
    } else if (typeof value === 'string') {
      buffer = Buffer.from(value);
    } else if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
      buffer = Buffer.from(value as ArrayBuffer);
    } else {
      throw new Error('Unsupported body type for local blob storage');
    }

    await fs.mkdir(path.dirname(fullPath), { recursive: true });
    await fs.writeFile(fullPath, buffer);

    const metaPath = fullPath + '.meta.json';
    const metadata: KVBlobMetadata = {
      size: options.size,
      contentType,
      customMetadata: options.customMetadata || null,
    };
    await fs.writeFile(metaPath, JSON.stringify(metadata), 'utf-8');
    return;
  }

  throw new Error('Attachment storage is not configured');
}

export async function getBlobObject(env: Env, key: string): Promise<BlobObject | null> {
  if (hasR2Storage(env)) {
    const object = await env.ATTACHMENTS.get(key);
    if (!object) return null;
    return {
      body: object.body,
      size: Number(object.size) || 0,
      contentType: object.httpMetadata?.contentType || DEFAULT_CONTENT_TYPE,
    };
  }

  if (hasKvStorage(env)) {
    const result = await env.ATTACHMENTS_KV.getWithMetadata<KVBlobMetadata>(key, 'arrayBuffer');
    if (!result.value) return null;

    const sizeFromMeta = Number(result.metadata?.size || 0);
    const size = sizeFromMeta > 0 ? sizeFromMeta : result.value.byteLength;
    const body = new Response(result.value).body;

    return {
      body,
      size,
      contentType: result.metadata?.contentType || DEFAULT_CONTENT_TYPE,
    };
  }

  if (hasLocalStorage(env)) {
    const fs = await import('fs/promises');
    const path = await import('path');
    const fullPath = path.join(env.LOCAL_ATTACHMENTS_DIR, key);
    const metaPath = fullPath + '.meta.json';
    try {
      const buffer = await fs.readFile(fullPath);
      let contentType = DEFAULT_CONTENT_TYPE;
      let size = buffer.length;
      try {
        const metaResult = await fs.readFile(metaPath, 'utf-8');
        const metadata = JSON.parse(metaResult) as KVBlobMetadata;
        if (metadata.contentType) contentType = metadata.contentType;
        if (metadata.size) size = metadata.size;
      } catch {
        // Missing metadata is fine
      }
      return {
        body: new Response(buffer).body,
        size,
        contentType,
      };
    } catch {
      return null;
    }
  }

  return null;
}

export async function deleteBlobObject(env: Env, key: string): Promise<void> {
  if (hasR2Storage(env)) {
    await env.ATTACHMENTS.delete(key);
    return;
  }
  if (hasKvStorage(env)) {
    await env.ATTACHMENTS_KV.delete(key);
    return;
  }
  if (hasLocalStorage(env)) {
    const fs = await import('fs/promises');
    const path = await import('path');
    const fullPath = path.join(env.LOCAL_ATTACHMENTS_DIR, key);
    const metaPath = fullPath + '.meta.json';
    try { await fs.unlink(fullPath); } catch { }
    try { await fs.unlink(metaPath); } catch { }
    return;
  }
}
