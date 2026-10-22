import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { SecretStore, createHttpSender, loadIdentities } from '@secscan/engine';
import { RedisStopSignal, scanQueueProducer } from '@secscan/workers';
import { ConsoleMailer, LabPolicy, SmtpMailer, type Mailer } from '../core';
import { createPrismaStores } from '../persistence/prismaStores';
import { buildApp } from './app';
import { parseApiTokens } from './auth';

/**
 * Bootstrap. Everything is configured by environment (see .env.example):
 *
 *   SECSCAN_LAB_HOSTS            CSV allow-list while SECSCAN_LEGAL_RESOLVED != true (§3.2)
 *   SECSCAN_ALLOW_PRIVATE_TARGETS  true to permit targets on private addresses (local lab)
 *   SECSCAN_IDENTITIES_FILE      test-account material, kept in memory only (§7)
 *   SECSCAN_API_TOKENS           name:token,... bearer tokens; the name is the audit actor
 *   SECSCAN_ADMIN_TOKEN          x-admin-token for approve / revoke / manual overrides
 *   SECSCAN_FINGERPRINT_SECRET   HMAC key for report fingerprints and owner codes
 *   DATABASE_URL                 Postgres; unset = in-memory (lost on restart)
 *   SECSCAN_SMTP_URL / _MAIL_FROM  owner sign-off mail; SECSCAN_MAILER=console prints codes to this log
 *   SECSCAN_BIND / PORT          default 127.0.0.1:3001
 */
async function main() {
  const warn = (m: string) => console.warn(`[secscan] ${m}`); // eslint-disable-line no-console
  const legalResolved = process.env.SECSCAN_LEGAL_RESOLVED === 'true';
  const labHosts = (process.env.SECSCAN_LAB_HOSTS ?? '').split(',').map((s) => s.trim()).filter(Boolean);

  const store = new SecretStore();
  const idFile = process.env.SECSCAN_IDENTITIES_FILE;
  const loaded = idFile ? loadIdentities(JSON.parse(readFileSync(idFile, 'utf-8')), store) : null;

  let fingerprintSecret = process.env.SECSCAN_FINGERPRINT_SECRET;
  if (!fingerprintSecret) {
    fingerprintSecret = randomBytes(32).toString('hex');
    warn('SECSCAN_FINGERPRINT_SECRET not set; using a random per-boot secret (fingerprints and pending owner codes will not survive a restart)');
  }

  const adminToken = process.env.SECSCAN_ADMIN_TOKEN;
  if (!adminToken) warn('SECSCAN_ADMIN_TOKEN not set; approve/revoke/manual overrides are OPEN (local dev only)');
  const auth = parseApiTokens(process.env.SECSCAN_API_TOKENS);
  if (!auth) warn('SECSCAN_API_TOKENS not set; every route is OPEN and the audit actor is whatever the client sends (local dev only)');

  let mailer: Mailer | undefined;
  if (process.env.SECSCAN_SMTP_URL) mailer = new SmtpMailer(process.env.SECSCAN_SMTP_URL, process.env.SECSCAN_MAIL_FROM ?? 'secscan@localhost');
  else if (process.env.SECSCAN_MAILER === 'console') { mailer = new ConsoleMailer(); warn('owner codes are printed to this log (SECSCAN_MAILER=console)'); }
  else warn('no mailer configured; owner sign-off by email is disabled (manual admin path only)');

  const db = process.env.DATABASE_URL ? createPrismaStores(process.env.DATABASE_URL) : null;
  if (db) await db.db.$queryRawUnsafe('SELECT 1'); // fail fast on a bad URL
  else warn('DATABASE_URL not set; state is in memory and is lost on restart');

  // With Redis, scans are queued for a separate worker process and the stop
  // flag is shared across processes; without it, scans run inline in the API.
  const redisUrl = process.env.SECSCAN_REDIS_URL;
  const scanQueue = redisUrl ? scanQueueProducer(redisUrl) : undefined;
  const stopSignal = redisUrl ? new RedisStopSignal(redisUrl) : undefined;
  if (redisUrl && !db) warn('SECSCAN_REDIS_URL set without DATABASE_URL; the worker cannot share in-memory state — set DATABASE_URL too');
  else if (!redisUrl) warn('SECSCAN_REDIS_URL not set; scans run inline in the API process (no worker)');

  const app = await buildApp({
    lab: new LabPolicy(legalResolved, labHosts, { allowPrivateTargets: process.env.SECSCAN_ALLOW_PRIVATE_TARGETS === 'true' }),
    sender: createHttpSender({ store }),
    fingerprintSecret,
    liveness: loaded?.liveness,
    identities: loaded?.identities,
    adminToken,
    auth,
    mailer,
    stores: db?.stores,
    scanQueue,
    stopSignal,
  });
  const port = Number(process.env.PORT ?? 3001);
  const bind = process.env.SECSCAN_BIND ?? '127.0.0.1';
  await app.listen(port, bind);

  const shutdown = async () => { await app.close(); await db?.close(); process.exit(0); };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);

  // eslint-disable-next-line no-console
  console.log(`secscan api on ${bind}:${port} (store=${db ? 'postgres' : 'memory'}, auth=${auth ? Object.keys(auth.tokens).length + ' token(s)' : 'OPEN'}, adminToken=${adminToken ? 'set' : 'OPEN'}, mailer=${mailer ? mailer.constructor.name : 'none'}, labHosts=${labHosts.length}, identities=${loaded?.identities.length ?? 0})`);
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e);
  process.exit(1);
});
