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
import { resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { buildApp, LabPolicy } from '@secscan/api';
import { createHttpSender, SecretStore, loadIdentities } from '@secscan/engine';
import { readFileSync } from 'node:fs';
import { networkInterfaces } from 'node:os';

function localLanIp() {
  for (const addrs of Object.values(networkInterfaces())) for (const a of addrs ?? []) {
    if (a.family === 'IPv4' && !a.internal) return a.address;
  }
  return undefined;
}

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.map': 'application/json' };

// The receiver page any device opens to display messages the console broadcasts.
const DISPLAY_PAGE = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SecScan Display</title>
<style>html,body{margin:0;height:100%;background:#0b1020;color:#e8eefc;font:16px/1.5 system-ui,sans-serif}
.wrap{min-height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;padding:24px;box-sizing:border-box}
.msg{background:#16203c;border:1px solid #2b3a63;border-radius:14px;padding:18px 22px;max-width:680px;width:100%;box-shadow:0 8px 40px rgba(0,0,0,.4)}
.msg .t{font-size:22px;font-weight:600}.msg .a{opacity:.6;font-size:12px;margin-top:6px}
.idle{opacity:.55}.dot{width:8px;height:8px;border-radius:50%;background:#4cc9f0;display:inline-block;margin-right:6px;animation:p 1.4s infinite}@keyframes p{50%{opacity:.3}}</style></head>
<body><div class="wrap" id="w"><div class="idle"><span class="dot"></span>connected — waiting for a message…</div></div>
<script>const w=document.getElementById('w');const es=new EventSource('/api/messages/stream');
es.onmessage=e=>{try{const m=JSON.parse(e.data);const d=document.createElement('div');d.className='msg';d.innerHTML='<div class="t"></div><div class="a"></div>';d.querySelector('.t').textContent=m.text;d.querySelector('.a').textContent=new Date(m.at).toLocaleTimeString();w.innerHTML='';w.appendChild(d);}catch(_){}};
es.onerror=()=>{};</script></body></html>`;

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
    store, devTrust: true,
  });
  await api.listen(apiPort, '127.0.0.1');

  // Device messaging: Server-Sent Events hub. Any device opens /display in a
  // browser and subscribes; the console POSTs /api/messages/broadcast and every
  // open receiver shows the message. Plain HTTP, no extra deps, no install.
  const receivers = new Set();
  const broadcast = (text) => {
    const payload = `data: ${JSON.stringify({ text, at: new Date().toISOString() })}\n\n`;
    for (const r of receivers) { try { r.write(payload); } catch { receivers.delete(r); } }
    return receivers.size;
  };

  // Exposure hardening: loopback by default. Binding off-loopback (e.g.
  // SECSCAN_HOST=0.0.0.0 for device messaging) exposes the dev-trust console —
  // which has no auth and the lab lock off — to the whole network. So when bound
  // off-loopback we REQUIRE an access token for the console + /api; only the
  // receiver (/display) and its SSE stream stay open so devices can still
  // receive broadcasts. On loopback, no token is needed.
  const host = opts.host ?? process.env.SECSCAN_HOST ?? '127.0.0.1';
  const isLoopback = host === '127.0.0.1' || host === 'localhost' || host === '::1';
  const accessToken = process.env.SECSCAN_ACCESS_TOKEN;
  if (!isLoopback && !accessToken) {
    throw new Error(`refusing to bind to ${host}: that exposes the no-auth dev-trust console on the network. Set SECSCAN_ACCESS_TOKEN=<secret> to allow it (then open the URL with ?token=<secret>), or keep the default loopback bind.`);
  }
  const openPath = (p) => p === '/display' || p === '/api/messages/stream';
  const authed = (req, url) =>
    isLoopback ||
    (req.headers.cookie ?? '').split(';').some((c) => c.trim() === `secscan_access=${accessToken}`) ||
    url.searchParams.get('token') === accessToken;

  const front = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');

    // token gate (only active when bound off-loopback)
    if (!isLoopback && !openPath(url.pathname)) {
      if (url.searchParams.get('token') === accessToken) {
        res.writeHead(302, { 'set-cookie': `secscan_access=${accessToken}; HttpOnly; SameSite=Strict; Path=/`, location: url.pathname });
        return res.end();
      }
      if (!authed(req, url)) {
        res.writeHead(401, { 'content-type': 'text/html' });
        return res.end('<p style="font:16px system-ui;margin:40px">Access token required. Open this URL with <code>?token=YOUR_TOKEN</code> (the value of SECSCAN_ACCESS_TOKEN).</p>');
      }
    }

    if (url.pathname === '/api/messages/stream' && req.method === 'GET') {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' });
      res.write('retry: 2000\n\n');
      receivers.add(res);
      req.on('close', () => receivers.delete(res));
      return;
    }
    if (url.pathname === '/api/messages/broadcast' && req.method === 'POST') {
      const chunks = [];
      req.on('data', (c) => chunks.push(c)).on('end', () => {
        let text = ''; try { text = JSON.parse(Buffer.concat(chunks).toString() || '{}').text ?? ''; } catch { /* ignore */ }
        const delivered = text ? broadcast(String(text).slice(0, 2000)) : 0;
        res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ delivered }));
      });
      return;
    }
    if (url.pathname === '/display') {
      res.writeHead(200, { 'content-type': 'text/html' });
      return res.end(DISPLAY_PAGE);
    }

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
    // static web (SPA fallback to index.html). URL paths are always forward-slash;
    // strip the leading slash and join under webDir (no path.normalize — it would
    // introduce backslashes on Windows and break the join).
    if (req.method !== 'GET') { res.writeHead(405); return res.end(); }
    const rel = decodeURIComponent(url.pathname).replace(/\\/g, '/').replace(/^\/+/, '') || 'index.html';
    let file = resolve(webDir, rel);
    const base = resolve(webDir);
    const inside = file === base || file.startsWith(base + sep);
    if (!inside || !existsSync(file) || !statSync(file).isFile()) file = resolve(webDir, 'index.html');
    const ext = file.slice(file.lastIndexOf('.')).toLowerCase();
    res.writeHead(200, { 'content-type': MIME[ext] ?? 'application/octet-stream' });
    createReadStream(file).pipe(res);
  });
  await new Promise((r) => front.listen(webPort, host, r));

  const shown = host === '0.0.0.0' ? (localLanIp() ?? host) : host;
  const url = `http://${shown}:${webPort}`;
  return { url, host, close: async () => { front.close(); await api.close(); } };
}

// Run directly: npm run serve. pathToFileURL makes the "is this the entry
// script?" check work on Windows too (a C:\… path vs a file:/// URL).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { url, host } = await startServer();
  console.log(`[serve] SecScan running at ${url} (single process, dev-trust)`);
  console.log('[serve] state is IN MEMORY — grants, scans and history are lost on restart. Use the Postgres path (npm run local -- --full) to persist.');
  if (host !== '127.0.0.1' && host !== 'localhost' && host !== '::1') {
    console.log('[serve] exposed on the network: open the console with ?token=<SECSCAN_ACCESS_TOKEN>; /display stays open for receivers.');
  }
}
