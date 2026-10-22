#!/usr/bin/env node
/**
 * `npm run demo` — the fastest way to see the FULL suite work locally.
 *
 * Boots a deliberately vulnerable lab app + the dev-trust API (pre-loaded with
 * matching test accounts) + the web console, runs the whole non-destructive
 * suite against the lab with labelled flows (so authorization findings are
 * CONFIRMED, not just candidates), prints the summary, and opens your browser.
 * In-memory, no Docker. For local use only — the lab app is intentionally weak.
 */
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const LAB_PORT = '7799';
const API_PORT = '3001';
const WEB_PORT = '5173';
const labUrl = `http://127.0.0.1:${LAB_PORT}/`;
const api = `http://127.0.0.1:${API_PORT}`;
const web = `http://localhost:${WEB_PORT}`;

const children = [];
const shutdown = () => { for (const c of children) { try { c.kill(); } catch { /* gone */ } } process.exit(0); };
process.on('SIGINT', shutdown); process.on('SIGTERM', shutdown);

function run(label, cmd, args, env) {
  const p = spawn(cmd, args, { cwd: root, env, shell: process.platform === 'win32' });
  const tag = (l) => `[${label}] ${l}`;
  const pipe = (s, out) => s.on('data', (d) => d.toString().split('\n').filter(Boolean).forEach((l) => out(tag(l))));
  pipe(p.stdout, console.log); pipe(p.stderr, console.error);
  p.on('exit', (c) => { console.error(tag(`exited (${c})`)); shutdown(); });
  return p;
}
async function waitFor(url, timeoutMs = 60_000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) { try { const r = await fetch(url); if (r.status < 500) return true; } catch { /* wait */ } await new Promise((r) => setTimeout(r, 400)); }
  return false;
}
function openBrowser(url) {
  const [cmd, args] = process.platform === 'darwin' ? ['open', [url]] : process.platform === 'win32' ? ['cmd', ['/c', 'start', '', url]] : ['xdg-open', [url]];
  try { spawn(cmd, args, { stdio: 'ignore', detached: true }).unref(); } catch { /* open manually */ }
}

const apiEnv = {
  ...process.env,
  SECSCAN_DEV_TRUST: 'true', SECSCAN_BIND: '127.0.0.1', PORT: API_PORT,
  SECSCAN_ALLOW_PRIVATE_TARGETS: 'true', SECSCAN_MAILER: 'console',
  SECSCAN_IDENTITIES_FILE: resolve(root, 'scripts/lab/identities.json'),
  SECSCAN_FINGERPRINT_SECRET: randomBytes(24).toString('hex'),
};

console.log('[demo] building…');
if (spawnSync('npm', ['run', 'build'], { cwd: root, stdio: 'inherit', shell: process.platform === 'win32' }).status !== 0) process.exit(1);

children.push(run('lab', 'node', ['scripts/lab/target.mjs'], { ...process.env, LAB_PORT }));
children.push(run('api', 'node', ['packages/api/dist/http/main.js'], apiEnv));
children.push(run('web', 'npm', ['run', 'dev', '-w', '@secscan/web', '--', '--port', WEB_PORT], process.env));

console.log('[demo] waiting for lab, API, and web…');
await waitFor(labUrl); await waitFor(`${api}/health`); await waitFor(web);

const flows = JSON.parse(readFileSync(resolve(root, 'scripts/lab/flows.json'), 'utf-8'));
console.log('[demo] running the full suite against the lab (labelled flows)…');
try {
  const res = await fetch(`${api}/scans/quick`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: labUrl, flows, actor: 'demo' }) });
  const scan = await res.json();
  console.log(`\n[demo] scan ${scan.id}: ${scan.confirmed} confirmed, ${scan.review} to review, ${scan.notTested} not tested`);
  console.log('[demo] expect: confirmed BOLA + cross-tenant + BFLA + SSTI + open-redirect + CORS + headers; product 42 and reflected-XSS in review.');
} catch (e) { console.error('[demo] seed scan failed:', String(e)); }

console.log(`\n[demo] ▸ opening ${web} — see Results & reports (login as any user via /login?as=alice on the lab)\n`);
openBrowser(web);
