import { describe, it, expect } from 'vitest';
import type { Identity, RecordedRequest, RecordedResponse, Sender } from '@secscan/engine';
import { runScan } from '../src/run';

const HOST = 'lab.internal';
const json = (status: number, body: string): RecordedResponse => ({ status, headers: { 'content-type': 'application/json' }, body });

// A vulnerable lab app: /orders requires login; any session sees order 42 (IDOR).
const vulnApp: Sender = async (req: RecordedRequest, ident: Identity) => {
  const p = new URL(req.url).pathname;
  if (p.startsWith('/orders/')) {
    if (!ident.sessionRef) return json(403, '{"e":"login"}');
    return json(200, '{"order":42,"buyer":"alice"}');
  }
  if (p === '/') return json(200, '<html>home</html>');
  return json(404, '{}');
};

const flows: RecordedRequest[] = [
  { method: 'GET', url: `https://${HOST}/orders/42`, ownsObject: true, capturedAsRole: 'customer', capturedAsTenant: 't1' },
];
const identitiesFile = {
  'customer/t1': { cookies: { sid: 'alice' } },
  'customer/t2': { cookies: { sid: 'bob' } },
};

describe('runScan (one-command, injected sender)', () => {
  it('walks the lifecycle, finds the IDOR, and writes both reports', async () => {
    const res = await runScan(
      { host: HOST, root: `https://${HOST}/`, flows, identitiesFile, allowPrivate: true },
      { sender: vulnApp, fingerprintSecret: 'test-secret' },
    );
    expect(res.status).toBe('done');
    expect(res.confirmed).toBeGreaterThanOrEqual(1);
    expect(res.reportEn).toContain('Cross-tenant data access'); // t2 reads t1's order
    expect(res.reportAr).toContain('تقرير تقييم أمني');
    expect(res.reportEn).toContain('Security Assessment Report');
    expect(res.grantId).toContain(HOST);
  });

  it('runs anonymously with no identities: no false IDOR (scorecard findings still allowed)', async () => {
    const res = await runScan(
      { host: HOST, root: `https://${HOST}/`, flows, allowPrivate: true },
      { sender: vulnApp, fingerprintSecret: 'test-secret' },
    );
    expect(res.status).toBe('done');
    // the owner baseline is 403 when anonymous, so the access-control finding
    // must NOT appear (passive scorecard findings on the root are fine).
    expect(res.reportEn).not.toContain('object-level authorization');
  });
});
