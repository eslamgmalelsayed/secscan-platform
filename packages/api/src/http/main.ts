import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { SecretStore, createHttpSender, loadIdentities } from '@secscan/engine';
import { LabPolicy } from '../core';
import { buildApp } from './app';

/**
 * Production bootstrap. The §3.2 lock is ON unless SECSCAN_LEGAL_RESOLVED=true
 * is set explicitly; the lab allow-list comes from SECSCAN_LAB_HOSTS (CSV).
 *
 * Test-account material (§7) is loaded once from SECSCAN_IDENTITIES_FILE
 * (see engine/identities.ts for the shape) into an in-memory SecretStore; it
 * is never exposed over HTTP. Scan requests reference identities by key.
 *
 * The API has no authentication of its own yet (review 2.3), so it binds to
 * loopback unless SECSCAN_BIND is set explicitly.
 */
async function main() {
  const legalResolved = process.env.SECSCAN_LEGAL_RESOLVED === 'true';
  const labHosts = (process.env.SECSCAN_LAB_HOSTS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const store = new SecretStore();
  const idFile = process.env.SECSCAN_IDENTITIES_FILE;
  const loaded = idFile ? loadIdentities(JSON.parse(readFileSync(idFile, 'utf-8')), store) : null;
  // No silent 'change-me': a per-boot random secret is used and announced instead.
  let fingerprintSecret = process.env.SECSCAN_FINGERPRINT_SECRET;
  if (!fingerprintSecret) {
    fingerprintSecret = randomBytes(32).toString('hex');
    // eslint-disable-next-line no-console
    console.warn('[secscan] SECSCAN_FINGERPRINT_SECRET not set; using a random per-boot secret (report fingerprints will not match across restarts)');
  }
  const adminToken = process.env.SECSCAN_ADMIN_TOKEN;
  // eslint-disable-next-line no-console
  if (!adminToken) console.warn('[secscan] SECSCAN_ADMIN_TOKEN not set; approve/revoke/manual-ownership are OPEN (local dev only)');
  const app = await buildApp({
    lab: new LabPolicy(legalResolved, labHosts, { allowPrivateTargets: process.env.SECSCAN_ALLOW_PRIVATE_TARGETS === 'true' }),
    sender: createHttpSender({ store }),
    fingerprintSecret,
    liveness: loaded?.liveness,
    adminToken,
  });
  const port = Number(process.env.PORT ?? 3001);
  const bind = process.env.SECSCAN_BIND ?? '127.0.0.1';
  await app.listen(port, bind);
  // eslint-disable-next-line no-console
  console.log(`secscan api on ${bind}:${port} (legalResolved=${legalResolved}, labHosts=${labHosts.length}, identities=${loaded?.identities.length ?? 0}, adminToken=${adminToken ? 'set' : 'OPEN'})`);
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e);
  process.exit(1);
});
