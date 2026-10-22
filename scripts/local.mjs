#!/usr/bin/env node
/**
 * One command to run the whole app locally.
 *
 *   npm run local           fast: in-memory (no Docker), scans run inline
 *   npm run local -- --full persistent: Docker (Postgres + Redis + Mailpit) + worker
 *
 * Either way it builds, boots the API in dev-trust mode (no auth, lab lock off
 * for hosts you paste, loopback only) plus the web console with live reload,
 * waits for it to come up, and opens your browser. Use the "Quick scan" box:
 * paste a URL you own and it runs the full non-destructive suite. Drop an
 * identities.json next to this repo to also test logged-in pages and turn on
 * the IDOR/BOLA engine.
 */
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const full = process.argv.includes('--full');
const WEB_PORT = process.env.SECSCAN_WEB_PORT ?? '5173';
const API_PORT = process.env.PORT ?? '3001';
const url = `http://localhost:${WEB_PORT}`;

const children = [];
const shutdown = () => { for (const c of children) { try { c.kill(); } catch { /* gone */ } } process.exit(0); };
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

function run(label, cmd, args, env) {
  const p = spawn(cmd, args, { cwd: root, env, shell: process.platform === 'win32' });
  const tag = (l) => `[${label}] ${l}`;
  const pipe = (s, out) => s.on('data', (d) => d.toString().split('\n').filter(Boolean).forEach((l) => out(tag(l))));
  pipe(p.stdout, console.log); pipe(p.stderr, console.error);
  p.on('exit', (code) => { console.error(tag(`exited (${code}); shutting down`)); shutdown(); });
  return p;
}
function step(label, cmd, args) {
  console.log(`[local] ${label}…`);
  const r = spawnSync(cmd, args, { cwd: root, stdio: 'inherit', shell: process.platform === 'win32' });
  if (r.status !== 0) { console.error(`[local] "${label}" failed`); process.exit(r.status ?? 1); }
}
async function waitForWeb(timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { const r = await fetch(url); if (r.ok || r.status < 500) return true; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
}
function openBrowser() {
  const [cmd, args] = process.platform === 'darwin' ? ['open', [url]]
    : process.platform === 'win32' ? ['cmd', ['/c', 'start', '', url]]
      : ['xdg-open', [url]];
  try { spawn(cmd, args, { stdio: 'ignore', detached: true }).unref(); } catch { /* open manually */ }
}

const idFile = resolve(root, 'identities.json');
const apiEnv = {
  ...process.env,
  SECSCAN_DEV_TRUST: 'true', SECSCAN_BIND: '127.0.0.1', PORT: API_PORT,
  SECSCAN_ALLOW_PRIVATE_TARGETS: 'true', SECSCAN_MAILER: 'console',
  SECSCAN_FINGERPRINT_SECRET: process.env.SECSCAN_FINGERPRINT_SECRET ?? randomBytes(24).toString('hex'),
  ...(existsSync(idFile) ? { SECSCAN_IDENTITIES_FILE: idFile } : {}),
};

step('building packages', 'npm', ['run', 'build']);

if (full) {
  step('starting Docker services (Postgres, Redis, Mailpit)', 'docker', ['compose', 'up', '-d', 'postgres', 'redis', 'mailpit']);
  apiEnv.DATABASE_URL = process.env.DATABASE_URL ?? 'postgresql://secscan:secscan_dev_only@localhost:5432/secscan';
  apiEnv.SECSCAN_REDIS_URL = process.env.SECSCAN_REDIS_URL ?? 'redis://localhost:6379';
  step('waiting for Postgres', 'node', ['-e', 'setTimeout(()=>{},4000)']);
  step('running migrations', 'npm', ['run', 'db:migrate']);
}

console.log(existsSync(idFile)
  ? '[local] identities.json found — logged-in + IDOR engine enabled'
  : '[local] no identities.json — public-surface scan only (add one to enable the IDOR engine)');
console.log(`[local] DEV-TRUST mode${full ? ' + Docker (Postgres/Redis/Mailpit)' : ' (in-memory, no Docker)'}: paste any URL you own; no auth, loopback only.`);

children.push(run('api', 'node', ['packages/api/dist/http/main.js'], apiEnv));
if (full) children.push(run('worker', 'node', ['packages/api/dist/worker/main.js'], apiEnv));
children.push(run('web', 'npm', ['run', 'dev', '-w', '@secscan/web', '--', '--port', WEB_PORT], process.env));

console.log('[local] waiting for the web console to come up…');
if (await waitForWeb()) { console.log(`\n[local] ▸ opening ${url}  — Quick scan box is on the Overview\n`); openBrowser(); }
else console.log(`\n[local] web console did not respond yet; open ${url} manually.\n`);
if (full) console.log('[local] owner sign-off codes (if used): http://localhost:8025 (Mailpit)');
