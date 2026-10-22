#!/usr/bin/env node
/**
 * One command to run the whole app locally: `npm run local`.
 *
 * Boots the API in dev-trust mode (no auth, lab lock off for hosts you paste,
 * loopback only) plus the web console with live reload. No Postgres, no Redis —
 * state is in memory and scans run inline. Open the printed URL and use the
 * "Quick scan" box: paste a URL you own and it runs the full non-destructive
 * suite. Drop an identities.json next to this repo to also test logged-in pages
 * and turn on the IDOR/BOLA engine.
 */
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const WEB_PORT = process.env.SECSCAN_WEB_PORT ?? '5173';
const API_PORT = process.env.PORT ?? '3001';

const idFile = resolve(root, 'identities.json');
const apiEnv = {
  ...process.env,
  SECSCAN_DEV_TRUST: 'true',
  SECSCAN_BIND: '127.0.0.1',
  PORT: API_PORT,
  SECSCAN_ALLOW_PRIVATE_TARGETS: 'true', // localhost / LAN targets you own
  SECSCAN_MAILER: 'console',
  SECSCAN_FINGERPRINT_SECRET: process.env.SECSCAN_FINGERPRINT_SECRET ?? randomBytes(24).toString('hex'),
  ...(existsSync(idFile) ? { SECSCAN_IDENTITIES_FILE: idFile } : {}),
};

function run(label, cmd, args, env) {
  const p = spawn(cmd, args, { cwd: root, env, shell: process.platform === 'win32' });
  const tag = (line) => `[${label}] ${line}`;
  const pipe = (stream, out) => stream.on('data', (d) => d.toString().split('\n').filter(Boolean).forEach((l) => out(tag(l))));
  pipe(p.stdout, (l) => console.log(l));
  pipe(p.stderr, (l) => console.error(l));
  p.on('exit', (code) => { console.error(tag(`exited (${code}); shutting down`)); shutdown(); });
  return p;
}

let children = [];
function shutdown() { for (const c of children) { try { c.kill(); } catch { /* already gone */ } } process.exit(0); }
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

console.log('[local] building packages…');
const build = spawn('npm', ['run', 'build'], { cwd: root, stdio: 'inherit', shell: process.platform === 'win32' });
build.on('exit', (code) => {
  if (code !== 0) { console.error('[local] build failed'); process.exit(code ?? 1); }
  if (existsSync(idFile)) console.log('[local] identities.json found — logged-in + IDOR engine enabled');
  else console.log('[local] no identities.json — public-surface scan only (add one to enable the IDOR engine)');
  console.log('[local] DEV-TRUST mode: paste any URL you own; no auth, loopback only.');
  children.push(run('api', 'node', ['packages/api/dist/http/main.js'], apiEnv));
  children.push(run('web', 'npm', ['run', 'dev', '-w', '@secscan/web', '--', '--port', WEB_PORT], process.env));
  setTimeout(() => console.log(`\n[local] ▸ open  http://localhost:${WEB_PORT}  — Quick scan box is on the Overview\n`), 2500);
});
