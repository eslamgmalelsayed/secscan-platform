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
      { host: HOST, root: `https://${HOST}/`, flows, identitiesFile, allowPrivate: true, rps: 0 },
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
      { host: HOST, root: `https://${HOST}/`, flows, allowPrivate: true, rps: 0 },
      { sender: vulnApp, fingerprintSecret: 'test-secret' },
    );
    expect(res.status).toBe('done');
    // the owner baseline is 403 when anonymous, so the access-control finding
    // must NOT appear (passive scorecard findings on the root are fine).
    expect(res.reportEn).not.toContain('object-level authorization');
  });

  it('quick mode: discovers endpoints from a URL alone (no flows supplied)', async () => {
    // a small site whose home page links to two more pages; the open redirect
    // on /go is a confirmable, non-destructive finding reachable by crawling.
    const html = (body: string): RecordedResponse => ({ status: 200, headers: { 'content-type': 'text/html' }, body });
    const site: Sender = async (req: RecordedRequest) => {
      const u = new URL(req.url); const p = u.pathname;
      if (p === '/') return html('<a href="/about">a</a> <a href="/go?next=x">g</a>');
      if (p === '/about') return html('about');
      if (p === '/go') return { status: 302, headers: { location: u.searchParams.get('next') ?? '/' }, body: '' };
      return json(404, '{}');
    };
    const res = await runScan(
      { host: HOST, root: `https://${HOST}/`, flows: [], discover: { maxPages: 10 }, allowPrivate: true, rps: 0 },
      { sender: site, fingerprintSecret: 'test-secret' },
    );
    expect(res.status).toBe('done');
    // crawling reached /go and the non-destructive open-redirect check fired
    expect(res.reportEn).toContain('Open redirect');
    // and it records that it discovered endpoints
    expect(res.notTested.some((n) => n.includes('discovered'))).toBe(true);
  }, 25000);

  it('quick mode WITH identities runs the full suite: crawls logged-in and finds an authz issue', async () => {
    const html = (body: string): RecordedResponse => ({ status: 200, headers: { 'content-type': 'text/html' }, body });
    // logged-in home links to a per-user order; the order endpoint is vulnerable
    // (any session reads any order). Anonymous sees nothing.
    const app: Sender = async (req: RecordedRequest, ident: Identity) => {
      const p = new URL(req.url).pathname;
      if (!ident.sessionRef) return { status: 401, headers: { 'content-type': 'application/json' }, body: '{"e":"login"}' };
      if (p === '/') return html('<a href="/orders/101">my order</a>');
      if (p === '/orders/101') return json(200, '{"order":101,"buyer":"alice"}'); // IDOR/cross-tenant
      return json(404, '{}');
    };
    const res = await runScan(
      { host: HOST, root: `https://${HOST}/`, flows: [], discover: { maxPages: 10 }, identitiesFile, allowPrivate: true, rps: 0 },
      { sender: app, fingerprintSecret: 'test-secret' },
    );
    expect(res.status).toBe('done');
    // crawled as a logged-in identity, so the authorization engine ran and flagged
    // the shared order. No owner label on a crawled flow => it's a review candidate.
    expect(res.review).toBeGreaterThanOrEqual(1);
    expect(res.notTested.some((n) => n.includes("as 'customer/t1'"))).toBe(true);
  }, 25000);
});
