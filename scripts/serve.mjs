#!/usr/bin/env node
/**
 * Single-process production server: one URL serves the whole app.
 *
 * Starts the API in-process (dev-trust local mode) and a front server that
 * serves the built web console and proxies `/api/*` to the API (stripping the
 * prefix) — the same contract the Vite dev-proxy gives, but packaged. This is
 * what the Windows desktop shell wraps, and what `npm run serve` runs.
 *
 * Export: `startServer()` returns { url, close } so the Electron main can boot
 * it and point a window at `url`.
 */
import { createServer, request as httpRequest } from 'node:http';
import { createReadStream, existsSync, statSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { resolve, normalize } from 'node:path';
import { buildApp, LabPolicy } from '@secscan/api';
import { createHttpSender, SecretStore, loadIdentities } from '@secscan/engine';
import { readFileSync } from 'node:fs';

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.map': 'application/json' };

export async function startServer(opts = {}) {
  const root = resolve(import.meta.dirname, '..');
  const webDir = opts.webDir ?? resolve(root, 'apps/web/dist');
  const apiPort = opts.apiPort ?? 3001;
  const webPort = opts.webPort ?? 5173;

  const store = new SecretStore();
  const idFile = opts.identitiesFile ?? resolve(root, 'identities.json');
  const loaded = existsSync(idFile) ? loadIdentities(JSON.parse(readFileSync(idFile, 'utf-8')), store) : null;

  const api = await buildApp({
    lab: new LabPolicy(false, [], { allowPrivateTargets: true }),
    sender: createHttpSender({ store }),
    fingerprintSecret: randomBytes(24).toString('hex'),
    identities: loaded?.identities, liveness: loaded?.liveness,
    devTrust: true,
  });
  await api.listen(apiPort, '127.0.0.1');

  const front = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    // proxy /api/* -> API (strip the prefix)
    if (url.pathname.startsWith('/api/') || url.pathname === '/api') {
      const path = (url.pathname.replace(/^\/api/, '') || '/') + url.search;
      const chunks = [];
      req.on('data', (c) => chunks.push(c)).on('end', () => {
        const body = Buffer.concat(chunks);
        const pr = httpRequest({ hostname: '127.0.0.1', port: apiPort, path, method: req.method, headers: req.headers }, (pres) => {
          res.writeHead(pres.statusCode ?? 502, pres.headers); pres.pipe(res);
        });
        pr.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end('api unreachable'); });
        if (body.length) pr.write(body);
        pr.end();
      });
      return;
    }
    // static web (SPA fallback to index.html)
    if (req.method !== 'GET') { res.writeHead(405); return res.end(); }
    let rel = normalize(decodeURIComponent(url.pathname)).replace(/^(\.\.(\/|\\|$))+/, '').replace(/^\/+/, '');
    let file = resolve(webDir, rel || 'index.html');
    if (!file.startsWith(resolve(webDir))) file = resolve(webDir, 'index.html');
    if (!existsSync(file) || !statSync(file).isFile()) file = resolve(webDir, 'index.html');
    const ext = file.slice(file.lastIndexOf('.'));
    res.writeHead(200, { 'content-type': MIME[ext] ?? 'application/octet-stream' });
    createReadStream(file).pipe(res);
  });
  await new Promise((r) => front.listen(webPort, '127.0.0.1', r));

  const url = `http://127.0.0.1:${webPort}`;
  return { url, close: async () => { front.close(); await api.close(); } };
}

// Run directly: npm run serve
if (import.meta.url === `file://${process.argv[1]}`) {
  const { url } = await startServer();
  console.log(`[serve] SecScan running at ${url} (single process, dev-trust)`);
}
