import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

// The dashboard talks to the API through this proxy, so no CORS and the API
// stays bound to loopback. Set SECSCAN_API_URL to point elsewhere.
export default defineConfig({
  plugins: [vue()],
  resolve: { alias: { '@secscan/shared': fileURLToPath(new URL('../../packages/shared/src/index.ts', import.meta.url)) } },
  server: {
    proxy: {
      '/api': {
        target: process.env.SECSCAN_API_URL ?? 'http://127.0.0.1:3001',
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ''),
      },
    },
  },
});
