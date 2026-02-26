import { startNodewardenApp } from './app.js';

async function loadRuntimeConfig() {
  try {
    const resp = await fetch('/api/web/config', { method: 'GET' });
    if (!resp.ok) throw new Error('runtime config request failed');
    return await resp.json();
  } catch {
    return { defaultKdfIterations: 600000 };
  }
}

const cfg = await loadRuntimeConfig();
startNodewardenApp(cfg || { defaultKdfIterations: 600000 });

