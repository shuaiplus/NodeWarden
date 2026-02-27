import { startNodewardenApp } from './app.js';

async function ensureQrLibrary() {
  if (typeof window.qrcode === 'function') return;
  await new Promise((resolve) => {
    const s = document.createElement('script');
    s.src = '/web/vendor/qrcode-generator.min.js';
    s.async = true;
    s.onload = () => resolve(null);
    s.onerror = () => resolve(null);
    document.head.appendChild(s);
  });
}

async function loadRuntimeConfig() {
  try {
    const resp = await fetch('/api/web/config', { method: 'GET' });
    if (!resp.ok) throw new Error('runtime config request failed');
    return await resp.json();
  } catch {
    return { defaultKdfIterations: 600000 };
  }
}

await ensureQrLibrary();
const cfg = await loadRuntimeConfig();
startNodewardenApp(cfg || { defaultKdfIterations: 600000 });
