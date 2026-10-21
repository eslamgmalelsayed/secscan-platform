import { describe, it, expect } from 'vitest';
import {
  InMemoryQueue, discoveryHandler, scanHandler, validatorHandler, attach,
  type DiscoveryJob, type Worklist, type ScanJob, type ScanOutcome, type ValidateJob, type ValidationResult,
} from '../src';

describe('discovery worker', () => {
  it('dedups and lowercases hosts into a worklist', async () => {
    const q = new InMemoryQueue<DiscoveryJob, Worklist>();
    attach(q, discoveryHandler());
    await q.add({ grantId: 'g1', hosts: ['App.Example.com', 'app.example.com', 'api.example.com'] });
    const [w] = await q.drain();
    expect(w.targets.sort()).toEqual(['api.example.com', 'app.example.com']);
  });
});

describe('scan worker', () => {
  it('runs a job via the injected (scope-gated) runner', async () => {
    const q = new InMemoryQueue<ScanJob, ScanOutcome>();
    attach(q, scanHandler(async () => ({ id: 'scan-1', status: 'done', findings: [{} as any, {} as any] })));
    await q.add({ engagementId: 'E1', grantId: 'g1', flows: [], identities: [] });
    const [out] = await q.drain();
    expect(out).toEqual({ scanId: 'scan-1', status: 'done', confirmed: 2 });
  });
});

describe('validator worker', () => {
  it('reports fixed vs still_open from the retest', async () => {
    const q = new InMemoryQueue<ValidateJob, ValidationResult>();
    attach(q, validatorHandler(async (id) => id === 'F-fixed'));
    await q.add({ findingId: 'F-fixed' });
    await q.add({ findingId: 'F-open' });
    const results = await q.drain();
    expect(results).toEqual([
      { findingId: 'F-fixed', result: 'fixed' },
      { findingId: 'F-open', result: 'still_open' },
    ]);
  });
});
