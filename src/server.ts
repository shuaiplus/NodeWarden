import express from 'express';
import cors from 'cors';
import * as fs from 'fs/promises';
import { mkdirSync } from 'fs';
import * as path from 'path';
import { WebSocketServer, WebSocket } from 'ws';
import * as dotenv from 'dotenv';
import { SqliteDatabase } from './services/sqlite-adapter';
import { Env } from './types';
import { StorageService } from './services/storage';
import { seedDefaultBackupSettings, runScheduledBackupIfDue } from './handlers/backup';
import { handleRequest } from './router';
import { buildWebBootstrapResponse } from './router-public';

import { applyCors } from './utils/response';

// Minimal in-memory implementation of the Cache API for RateLimitService
class MockCache {
  private map = new Map<string, { value: string; expires: number }>();

  async match(request: string | Request): Promise<Response | undefined> {
    const url = typeof request === 'string' ? request : request.url;
    const entry = this.map.get(url);
    if (!entry) return undefined;
    if (Date.now() > entry.expires) {
      this.map.delete(url);
      return undefined;
    }
    return new Response(entry.value);
  }

  async put(request: string | Request, response: Response): Promise<void> {
    const url = typeof request === 'string' ? request : request.url;
    const cacheControl = response.headers.get('Cache-Control') || '';
    const match = cacheControl.match(/max-age=(\d+)/);
    const maxAge = match ? parseInt(match[1], 10) : 60;
    const text = await response.text();
    this.map.set(url, {
      value: text,
      expires: Date.now() + maxAge * 1000,
    });
  }
}

(global as any).caches = {
  open: async () => new MockCache(),
};

dotenv.config();

const PORT = process.env.PORT || 8787;
const DB_PATH = process.env.DB_PATH || '/nodewarden/db.sqlite';
const ATTACHMENTS_DIR = process.env.LOCAL_ATTACHMENTS_DIR || '/nodewarden/attachments';

// Ensure data dirs exist
mkdirSync(path.dirname(DB_PATH), { recursive: true });
mkdirSync(ATTACHMENTS_DIR, { recursive: true });

const db = new SqliteDatabase(DB_PATH);

const wsClients = new Set<WebSocket>();

// Mock Durable Object Namespace for Notifications
const mockDurableObjectNamespace: any = {
  idFromName: () => ({}),
  get: () => ({
    fetch: async (req: Request) => {
      // Backend calls this to broadcast
      const bodyStr = await req.text();
      for (const client of wsClients) {
        if (client.readyState === WebSocket.OPEN) {
          client.send(bodyStr);
        }
      }
      return new Response('OK');
    }
  })
};

const env = {
  DB: db as any,
  NOTIFICATIONS_HUB: mockDurableObjectNamespace,
  get JWT_SECRET() { return process.env.JWT_SECRET; },
  get TOTP_SECRET() { return process.env.TOTP_SECRET; },
  get LOCAL_ATTACHMENTS_DIR() { return ATTACHMENTS_DIR; },
} as Env;

// Initialize DB and background schedules
async function initServer() {
  const storage = new StorageService(env.DB);
  await storage.initializeDatabase();
  await seedDefaultBackupSettings(env);

  // Start cron to run every 5 minutes
  setInterval(() => {
    runScheduledBackupIfDue(env).catch(e => console.error('Cron error', e));
  }, 5 * 60 * 1000);
}

initServer().catch(console.error);

const app = express();

app.use(cors());

function isWorkerHandledPath(pathname: string): boolean {
  return (
    pathname.startsWith('/api/') ||
    pathname.startsWith('/identity/') ||
    pathname.startsWith('/icons/') ||
    pathname.startsWith('/notifications/') ||
    pathname.startsWith('/.well-known/') ||
    pathname === '/config' ||
    pathname === '/api/config' ||
    pathname === '/api/version'
  );
}

function injectBootstrapIntoHtml(html: string): string {
  const payload = JSON.stringify(buildWebBootstrapResponse(env)).replace(/</g, '\\u003c');
  const script = `<script>window.__NW_BOOT__=${payload};</script>`;
  if (html.includes('</head>')) {
    return html.replace('</head>', `${script}</head>`);
  }
  return `${script}${html}`;
}

app.use(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  console.log('Incoming req:', req.method, url.pathname);
  if (!isWorkerHandledPath(url.pathname)) {
    // Attempt to serve asset
    const publicDir = path.join(process.cwd(), 'dist');
    const filePath = path.join(publicDir, url.pathname === '/' ? 'index.html' : url.pathname);
    console.log('Attempting to serve:', filePath);
    try {
      const stats = await fs.stat(filePath);
      if (stats.isFile()) {
        if (filePath.endsWith('.html')) {
          const html = await fs.readFile(filePath, 'utf-8');
          res.setHeader('Content-Type', 'text/html');
          return res.send(injectBootstrapIntoHtml(html));
        } else {
          try {
            return res.sendFile(filePath);
          } catch (sendErr) {
            console.error('Send file err:', sendErr);
          }
        }
      }
    } catch (e) {
      console.error('Static serve error:', e);
      // Fallback to index.html for SPA if not an api path
      if (!isWorkerHandledPath(url.pathname)) {
        try {
          const html = await fs.readFile(path.join(publicDir, 'index.html'), 'utf-8');
          res.setHeader('Content-Type', 'text/html');
          return res.send(injectBootstrapIntoHtml(html));
        } catch (e2) {
          console.error('Fallback read error:', e2);
          // Ignore, proceed to handleRequest or 404
        }
      }
    }
  }

  // Transform Express req to standard Request
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (typeof value === 'string') headers.set(key, value);
    else if (Array.isArray(value)) value.forEach(v => headers.append(key, v));
  }

  // Real IP
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  headers.set('cf-connecting-ip', Array.isArray(clientIp) ? clientIp[0] : clientIp);

  console.log('Proceeding to handleRequest for:', url.pathname);
  const reqInit: RequestInit = {
    method: req.method,
    headers,
  };

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(chunk as Buffer);
    }
    reqInit.body = Buffer.concat(chunks);
  }

  const standardReq = new Request(url.toString(), reqInit);

  try {
    let standardRes = await handleRequest(standardReq, env);
    standardRes = applyCors(standardReq, standardRes);

    // Transform standard Response to Express res
    standardRes.headers.forEach((value, key) => {
      res.setHeader(key, value);
    });
    res.status(standardRes.status);

    if (standardRes.body) {
      // Using arrayBuffer since streaming might be tricky, or stream chunk by chunk
      const arrayBuf = await standardRes.arrayBuffer();
      res.end(Buffer.from(arrayBuf));
    } else {
      res.end();
    }
  } catch (err) {
    console.error('Bridge error', err);
    res.status(500).send('Bridge error');
  }
});

const server = app.listen(PORT, () => {
  console.log(`NodeWarden local server running on port ${PORT}`);
});

// SignalR Notifications Mock Hub
const wss = new WebSocketServer({ noServer: true });

wss.on('connection', (ws) => {
  wsClients.add(ws);

  ws.on('message', (msg) => {
    const str = msg.toString();
    if (str.includes('"protocol":"json"')) {
      ws.send('{}' + String.fromCharCode(0x1e));
    }
  });

  ws.on('close', () => {
    wsClients.delete(ws);
  });
});

server.on('upgrade', (request, socket, head) => {
  const pathname = new URL(request.url || '', `http://${request.headers.host}`).pathname;
  if (pathname === '/notifications/hub') {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  } else {
    socket.destroy();
  }
});
