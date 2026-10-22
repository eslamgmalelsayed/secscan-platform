/**
 * The BullMQ queue must satisfy the same contract as InMemoryQueue. Runs only
 * when SECSCAN_TEST_REDIS_URL is set (docker compose up redis).
 */
import { describe, it, expect, afterEach } from 'vitest';
import { randomUUID } from 'node:crypto';
import {
  BullMqQueue, InMemoryQueue, attach, discoveryHandler, scanHandler, validatorHandler,
  type DiscoveryJob, type Worklist, type Queue, type ScanJob, type ScanOutcome, type ValidateJob, type ValidationResult,
} from '../src';

const REDIS = process.env.SECSCAN_TEST_REDIS_URL;
const open: BullMqQueue<any, any>[] = [];

function makers(): [string, <T, R>() => Queue<T, R>][] {
  const out: [string, <T, R>() => Queue<T, R>][] = [['in-memory', <T, R>() => new InMemoryQueue<T, R>()]];
  if (REDIS) {
    out.push(['bullmq', <T, R>() => {
      const q = new BullMqQueue<T, R>(`secscan-test-${randomUUID()}`, { redisUrl: REDIS });
      open.push(q);
      return q;
    }]);
  }
  return out;
}

afterEach(async () => {
  for (const q of open.splice(0)) { await q.obliterate(); await q.close(); }
});

for (const [name, make] of makers()) {
  describe(`queue contract: ${name}`, () => {
    it('drain returns results in add order', async () => {
      const q = make<ValidateJob, ValidationResult>();
      attach(q, validatorHandler(async (id) => id.endsWith('fixed')));
      await q.add({ findingId: 'a-fixed' });
      await q.add({ findingId: 'b-open' });
      await q.add({ findingId: 'c-fixed' });
      expect(await q.drain()).toEqual([
        { findingId: 'a-fixed', result: 'fixed' },
        { findingId: 'b-open', result: 'still_open' },
        { findingId: 'c-fixed', result: 'fixed' },
      ]);
    }, 20_000);

    it('job data survives the round-trip intact', async () => {
      const q = make<DiscoveryJob, Worklist>();
      attach(q, discoveryHandler());
      await q.add({ grantId: 'g1', hosts: ['App.Example.com', 'app.example.com', 'api.example.com'] });
      const [w] = await q.drain();
      expect(w.grantId).toBe('g1');
      expect(w.targets.sort()).toEqual(['api.example.com', 'app.example.com']);
    }, 20_000);

    it('a second drain only covers jobs added since the first', async () => {
      const q = make<ScanJob, ScanOutcome>();
      let n = 0;
      attach(q, scanHandler(async () => ({ id: `scan-${++n}`, status: 'done', findings: [] })));
      await q.add({ engagementId: 'E', grantId: 'g', flows: [], identities: [] });
      expect((await q.drain()).map((r) => r.scanId)).toEqual(['scan-1']);
      await q.add({ engagementId: 'E', grantId: 'g', flows: [], identities: [] });
      expect((await q.drain()).map((r) => r.scanId)).toEqual(['scan-2']);
    }, 20_000);

    it('a failing handler rejects drain', async () => {
      const q = make<ValidateJob, ValidationResult>();
      attach(q, validatorHandler(async () => { throw new Error('retest exploded'); }));
      await q.add({ findingId: 'x' });
      await expect(q.drain()).rejects.toThrow(/retest exploded/);
    }, 20_000);
  });
}

if (!REDIS) describe.skip('queue contract: bullmq (set SECSCAN_TEST_REDIS_URL to run)', () => { it('skipped', () => {}); });
