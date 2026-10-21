import { createHttpSender } from '@secscan/engine';
import { LabPolicy } from '../core';
import { buildApp } from './app';

/**
 * Production bootstrap. The §3.2 lock is ON unless SECSCAN_LEGAL_RESOLVED=true
 * is set explicitly; the lab allow-list comes from SECSCAN_LAB_HOSTS (CSV).
 */
async function main() {
  const legalResolved = process.env.SECSCAN_LEGAL_RESOLVED === 'true';
  const labHosts = (process.env.SECSCAN_LAB_HOSTS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const app = await buildApp({
    lab: new LabPolicy(legalResolved, labHosts),
    sender: createHttpSender(),
    fingerprintSecret: process.env.SECSCAN_FINGERPRINT_SECRET ?? 'change-me',
  });
  const port = Number(process.env.PORT ?? 3001);
  await app.listen(port, '0.0.0.0');
  // eslint-disable-next-line no-console
  console.log(`secscan api on :${port} (legalResolved=${legalResolved}, labHosts=${labHosts.length})`);
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e);
  process.exit(1);
});
