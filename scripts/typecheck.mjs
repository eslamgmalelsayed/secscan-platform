#!/usr/bin/env node
/**
 * Typecheck every workspace package with `tsc --noEmit` (review gap 6: the root
 * lint script had nothing to lint). This is the project's lint: it catches type
 * errors across all packages without emitting. The web app is typechecked by
 * its own `vite build`, so it is skipped here.
 */
import { readdirSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkgDir = join(root, 'packages');
const pkgs = readdirSync(pkgDir).filter((n) => existsSync(join(pkgDir, n, 'tsconfig.json')));

let failed = 0;
for (const name of pkgs) {
  const cfg = join(pkgDir, name, 'tsconfig.json');
  process.stdout.write(`typecheck @secscan/${name} ... `);
  const r = spawnSync('npx', ['tsc', '--noEmit', '-p', cfg], { cwd: root, encoding: 'utf-8' });
  if (r.status === 0) {
    console.log('ok');
  } else {
    failed++;
    console.log('FAIL');
    process.stdout.write((r.stdout || '') + (r.stderr || ''));
  }
}
console.log(`\n${pkgs.length - failed}/${pkgs.length} packages typecheck clean`);
process.exit(failed ? 1 : 0);
