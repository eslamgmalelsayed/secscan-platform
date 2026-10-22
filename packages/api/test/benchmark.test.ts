/**
 * Fixed benchmark (Design §12 "quality" kill criterion).
 *
 * An in-process fixture app with a KNOWN set of weaknesses and a known-clean
 * surface. The full pipeline (grant lifecycle -> ScanService -> real HTTP
 * sender -> authz-diff + checks) must report exactly the expected findings:
 * every expected one present (recall) and nothing else confirmed (precision).
 * Anything added to the fixture must be added to EXPECTED, and vice versa.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHttpSender, loadIdentities, type RecordedRequest } from '@secscan/engine';
import {
  AppendOnlyAuditLog, AuthorizationService, LabPolicy, ScanService,
  InMemoryGrantRepo, InMemoryScanRepo, InMemoryEngagementRepo,
} from '../src/core';
import type { Engagement } from '@secscan/shared';

const NOW = new Date();
let srv: Server; let base: string; let host: string;

const users: Record<string, { id: number; name: string; tenant: string }> = {
  'sid=alice': { id: 1, name: 'Alice', tenant: 't1' },
  'sid=bob': { id: 2, name: 'Bob', tenant: 't1' },
  'sid=carol': { id: 3, name: 'Carol', tenant: 't2' },
};
const orders = [
  { id: 101, ownerId: 1, tenant: 't1', total: 50 },
  { id: 102, ownerId: 2, tenant: 't1', total: 70 },
  { id: 201, ownerId: 3, tenant: 't2', total: 90 },
];
const invoices = [{ id: 7, ownerId: 1, tenant: 't1', amount: 10 }];

beforeAll(async () => {
  srv = createServer((req, res) => {
    const u = new URL(req.url ?? '/', 'http://x');
    const me = users[(req.headers.cookie ?? '').split(';').map((s) => s.trim()).find((c) => c.startsWith('sid=')) ?? ''];
    const json = (status: number, body: unknown) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };

    if (u.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html', 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'content-security-policy': "default-src 'self'" });
      return res.end('<html>home</html>');
    }
    // CLEAN: per-session profile (ids differ) -> must NOT be an IDOR
    if (u.pathname === '/api/me') return me ? json(200, { id: me.id, name: me.name, tenant: me.tenant, created_at: '2026-01-01T00:00:00Z' }) : json(401, { e: 'login' });
    // CLEAN: list scoped to the session
    if (u.pathname === '/api/orders') return me ? json(200, orders.filter((o) => o.ownerId === me.id)) : json(401, { e: 'login' });
    // CLEAN: object-level check enforced (same tenant, different user -> 403)
    if (u.pathname.startsWith('/api/invoices/')) {
      if (!me) return json(401, { e: 'login' });
      const inv = invoices.find((i) => i.id === Number(u.pathname.split('/')[3]));
      return inv && inv.ownerId === me.id ? json(200, inv) : json(403, { e: 'forbidden' });
    }
    // WEAK #1: object-level check missing (any session can read any order) -> bola_idor
    // WEAK #2: ... including across tenants -> cross_tenant
    if (u.pathname.startsWith('/api/orders/')) {
      if (!me) return json(401, { e: 'login' });
      const o = orders.find((x) => x.id === Number(u.pathname.split('/')[3]));
      return o ? json(200, o) : json(404, {});
    }
    // WEAK #3: labeled requiresAuth by the owner, but served to anyone -> missing_auth
    if (u.pathname === '/api/admin/export') return json(200, { rows: 3 });
    // WEAK #4: reflects Origin with credentials -> cors
    if (u.pathname === '/api/profile') {
      const origin = req.headers['origin'];
      if (origin) { res.setHeader('access-control-allow-origin', origin); res.setHeader('access-control-allow-credentials', 'true'); }
      return me ? json(200, { id: me.id }) : json(401, {});
    }
    // WEAK #5: open redirect
    if (u.pathname === '/login') { res.writeHead(302, { location: u.searchParams.get('next') ?? '/' }); return res.end(); }
    res.writeHead(404); res.end();
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
  const port = (srv.address() as AddressInfo).port;
  host = '127.0.0.1'; base = `http://${host}:${port}`;
});
afterAll(() => srv.close());

const EXPECTED = [
  'AC-bola_idor',     // /api/orders/101 read by bob
  'AC-cross_tenant',  // /api/orders/101 read by carol (t2)
  'AC-missing_auth',  // /api/admin/export
  'CHK-cors',         // /api/profile
  'CHK-open_redirect',// /login?next=
];

describe('benchmark fixture: exact precision and recall', () => {
  it('reports every known weakness and nothing on the clean surface', async () => {
    const grants = new InMemoryGrantRepo(); const scans = new InMemoryScanRepo(); const audit = new AppendOnlyAuditLog();
    const engs = new InMemoryEngagementRepo();
    const auth = new AuthorizationService(grants, audit);
    await auth.createGrant({
      grantId: 'bench', targets: [{ host, scheme: 'http', port: Number(base.split(':')[2]) }], ownershipProof: 'http_token', ownershipToken: 't',
      chain: [{ party: 'A', email: 'a@a.sa', role: 'requester', signedAt: NOW.toISOString(), statement: 'r' }],
      notBefore: new Date(NOW.getTime() - 3.6e6).toISOString(), notAfter: new Date(NOW.getTime() + 3.6e6).toISOString(),
    }, 'a@a.sa');
    await auth.recordOwnershipVerified('bench', 'admin');
    await auth.ownerSign('bench', { party: 'Owner', email: 'o@o.sa', role: 'system_owner', signedAt: NOW.toISOString(), statement: 'ok' }, 'o@o.sa');
    await auth.adminApprove('bench', 'admin');

    const { store, identities, liveness } = loadIdentities({
      'customer/t1': { cookies: { sid: 'alice' }, liveness: `${base}/api/me` },
      'customer2/t1': { cookies: { sid: 'bob' }, liveness: `${base}/api/me` },
      'customer/t2': { cookies: { sid: 'carol' }, liveness: `${base}/api/me` },
    });
    await engs.save({
      id: 'E', client: host, preparedBy: 'bench', assets: [host], environment: 'lab', authorizationRef: 'bench',
      window: { start: new Date(NOW.getTime() - 3.6e6).toISOString(), end: new Date(NOW.getTime() + 3.6e6).toISOString() },
      methodology: { ar: 'x', en: 'x' }, limitations: { ar: 'y', en: 'y' },
    } as Engagement);
    const svc = new ScanService({
      auth, lab: new LabPolicy(false, [host], { allowPrivateTargets: true }), scans, engagements: engs, audit,
      sender: createHttpSender({ store }), fingerprintSecret: 's', liveness, pacing: { requestsPerSecond: 500 },
    });
    const flows: RecordedRequest[] = [
      { method: 'GET', url: `${base}/api/me`, capturedAsRole: 'customer', capturedAsTenant: 't1' },
      { method: 'GET', url: `${base}/api/orders`, capturedAsRole: 'customer', capturedAsTenant: 't1' },
      { method: 'GET', url: `${base}/api/invoices/7`, capturedAsRole: 'customer', capturedAsTenant: 't1' },
      { method: 'GET', url: `${base}/api/orders/101`, capturedAsRole: 'customer', capturedAsTenant: 't1' },
      { method: 'GET', url: `${base}/api/admin/export`, capturedAsRole: 'customer', capturedAsTenant: 't1', requiresAuth: true },
      { method: 'GET', url: `${base}/api/profile`, capturedAsRole: 'customer', capturedAsTenant: 't1' },
      { method: 'GET', url: `${base}/login?next=/dash` },
    ];
    const scan = await svc.run({ engagementId: 'E', grantId: 'bench', flows, identities, actor: 'bench', rootUrl: `${base}/` });

    const confirmed = scan.findings.map((f) => f.id.replace(/-[0-9a-f]{8}$/, '')).sort();
    expect(scan.status).toBe('done');
    expect(confirmed).toEqual([...EXPECTED].sort());       // recall AND precision, exactly
    expect(scan.notTested.filter((n) => n.startsWith('skipped') || n.startsWith('stopped'))).toEqual([]);
    expect(scan.findings.every((f) => f.confidence === 'confirmed')).toBe(true);
    // nothing confirmed on the clean endpoints
    for (const clean of ['/api/me', '/api/orders', '/api/invoices/7']) {
      expect(scan.findings.some((f) => f.location?.endsWith(clean)), clean).toBe(false);
    }
  }, 30_000);
});
