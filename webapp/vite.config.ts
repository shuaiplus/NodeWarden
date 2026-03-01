import { fileURLToPath } from 'node:url';
import path from 'node:path';
import preact from '@preact/preset-vite';
import { defineConfig } from 'vite';

const rootDir = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig({
  root: rootDir,
  plugins: [preact()],
  resolve: {
    alias: {
      '@': path.resolve(rootDir, 'src'),
    },
  },
  build: {
    outDir: path.resolve(rootDir, '../dist'),
    emptyOutDir: true,
    sourcemap: false,
    target: 'esnext',
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['preact', 'preact/hooks', 'preact/jsx-runtime'],
          query: ['@tanstack/react-query'],
          icons: ['lucide-preact'],
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8787',
      '/identity': 'http://127.0.0.1:8787',
      '/setup': 'http://127.0.0.1:8787',
      '/icons': 'http://127.0.0.1:8787',
      '/config': 'http://127.0.0.1:8787',
      '/notifications': 'http://127.0.0.1:8787',
      '/.well-known': 'http://127.0.0.1:8787',
    },
  },
});
