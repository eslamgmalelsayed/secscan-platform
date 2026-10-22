/**
 * Scan worker process (Design §4, review gap 1).
 *
 * Consumes queued scans from Redis and runs them, sharing state with the API
 * only through Postgres (the scan record moves queued -> running -> done) and
 * Redis (the stop flag). It loads the identities file ITSELF, so secrets never
 * travel through the queue — the job carries identity keys only.
 *
 * Requires DATABASE_URL (shared store) and SECSCAN_REDIS_URL (queue + stop).
 */
import { readFileSync } from 'node:fs';
import { SecretStore, createHttpSender, loadIdentities } from '@secscan/engine';
import { RedisStopSignal, startScanWorker } from '@secscan/workers';
import { LabPolicy, type QueuedScan } from '../core';
import { buildCore } from '../http/core-factory';
import { createPrismaStores } from '../persistence/prismaStores';

async function main() {
  const redisUrl = process.env.SECSCAN_REDIS_URL;
  const databaseUrl = process.env.DATABASE_URL;
  if (!redisUrl) throw new Error('SECSCAN_REDIS_URL is required for the worker');
  if (!databaseUrl) throw new Error('DATABASE_URL is required for the worker (it shares state with the API)');

  const legalResolved = process.env.SECSCAN_LEGAL_RESOLVED === 'true';
  const labHosts = (process.env.SECSCAN_LAB_HOSTS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const fingerprintSecret = process.env.SECSCAN_FINGERPRINT_SECRET;
  if (!fingerprintSecret) throw new Error('SECSCAN_FINGERPRINT_SECRET is required (must match the API)');

  // Load identities locally: material stays here, never in the queue.
  const store = new SecretStore();
  const idFile = process.env.SECSCAN_IDENTITIES_FILE;
  const parsed = idFile ? JSON.parse(readFileSync(idFile, 'utf-8')) : {};
  const loaded = idFile ? loadIdentities(parsed, store) : null;
  // JWTs for analysis are derived from local bearer material, not shipped in jobs.
  const tokens = Object.values(parsed as Record<string, { bearer?: string }>)
    .map((m) => m?.bearer).filter((b): b is string => !!b);

  const db = createPrismaStores(databaseUrl);
  await db.db.$queryRawUnsafe('SELECT 1');

  const stopSignal = new RedisStopSignal(redisUrl);
  const core = buildCore({
    lab: new LabPolicy(legalResolved, labHosts, { allowPrivateTargets: process.env.SECSCAN_ALLOW_PRIVATE_TARGETS === 'true' }),
    sender: createHttpSender({ store }),
    fingerprintSecret,
    liveness: loaded?.liveness,
    identities: loaded?.identities,
    stores: db.stores,
    stopSignal,
    pacing: {
      requestsPerSecond: process.env.SECSCAN_RPS ? Number(process.env.SECSCAN_RPS) : undefined,
      maxDurationMs: process.env.SECSCAN_MAX_MS ? Number(process.env.SECSCAN_MAX_MS) : undefined,
    },
  });

  const queue = startScanWorker(redisUrl, async (jobData) => {
    const job = jobData as QueuedScan;
    await core.scan.execute(job.scanId, {
      engagementId: job.engagementId, grantId: job.grantId, flows: job.flows,
      identities: job.identities, rootUrl: job.rootUrl, skipChecks: job.skipChecks,
      actor: job.actor, tokens,
    });
  });

  const shutdown = async () => { await queue.close(); await stopSignal.close(); await db.close(); process.exit(0); };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);

  // eslint-disable-next-line no-console
  console.log(`secscan worker up (redis=${new URL(redisUrl).host}, store=postgres, identities=${loaded?.identities.length ?? 0})`);
}

main().catch((e) => { console.error(e); process.exit(1); });
