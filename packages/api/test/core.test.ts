import { describe, it, expect, beforeEach } from 'vitest';
import type { Identity, RecordedRequest, RecordedResponse, Sender } from '@secscan/engine';
import type { Engagement } from '@secscan/shared';
import {
  AppendOnlyAuditLog, AuthorizationService, AuthorizationError, LabPolicy, LabPolicyError,
  ReportService, ScanService,
  InMemoryGrantRepo, InMemoryEngagementRepo, InMemoryScanRepo,
} from '../src/core';

const NOW = new Date();
const LAB_HOST = 'lab.internal';

function grantInput(host = LAB_HOST) {
  return {
    grantId: 'g1', targets: [{ host }], ownershipProof: 'dns_txt', ownershipToken: 'tok',
    chain: [{ party: 'Agency', email: 'a@agency.sa', role: 'requester', signedAt: NOW.toISOString(), statement: 'we request testing' }],
    notBefore: new Date(NOW.getTime() - 3.6e6).toISOString(),
    notAfter: new Date(NOW.getTime() + 3.6e6).toISOString(),
    status: 'pending_owner',
  };
}
const ownerLink = {
  party: 'Lab Owner', email: 'owner@lab.sa', role: 'system_owner' as const,
  signedAt: NOW.toISOString(), statement: 'I own lab.internal and authorize testing',
};

const json = (status: number, body: string): RecordedResponse => ({ status, headers: { 'content-type': 'application/json' }, body });
const vulnOrders: Sender = async (req: RecordedRequest, ident: Identity) => {
  if (new URL(req.url).pathname.startsWith('/orders/')) {
    if (!ident.sessionRef) return json(403, '{"e":"login"}');
    return json(200, '{"order":42,"buyer":"alice"}'); // vulnerable: any session
  }
  return json(404, '{}');
};
const alice: Identity = { role: 'customer', tenant: 't1', sessionRef: 'sess-alice' };
const bob: Identity = { role: 'customer', tenant: 't1', sessionRef: 'sess-bob' };
const flow: RecordedRequest = { method: 'GET', url: `https://${LAB_HOST}/orders/42`, capturedAsRole: 'customer', capturedAsTenant: 't1' };

let grants: InMemoryGrantRepo, engs: InMemoryEngagementRepo, scans: InMemoryScanRepo, audit: AppendOnlyAuditLog, auth: AuthorizationService;
beforeEach(() => {
  grants = new InMemoryGrantRepo(); engs = new InMemoryEngagementRepo(); scans = new InMemoryScanRepo();
  audit = new AppendOnlyAuditLog(); auth = new AuthorizationService(grants, audit);
});

describe('authorization lifecycle', () => {
  it('blocks a scan until ownership + owner-sign + admin-approve, then activates', () => {
    auth.createGrant(grantInput(), 'a@agency.sa');
    expect(() => auth.assertScanAllowed('g1')).toThrow(AuthorizationError); // ownership not verified
    auth.recordOwnershipVerified('g1', 'system');
    expect(() => auth.assertScanAllowed('g1')).toThrow(/owner has not signed/);
    auth.ownerSign('g1', ownerLink, 'owner@lab.sa');
    expect(() => auth.assertScanAllowed('g1')).toThrow(/admin has not approved/);
    const rec = auth.adminApprove('g1', 'admin');
    expect(rec.grant.status).toBe('active');
    expect(() => auth.assertScanAllowed('g1')).not.toThrow();
  });

  it('writes an append-only audit trail in order', () => {
    auth.createGrant(grantInput(), 'a@agency.sa');
    auth.recordOwnershipVerified('g1', 'system');
    auth.ownerSign('g1', ownerLink, 'owner@lab.sa');
    auth.adminApprove('g1', 'admin');
    const actions = audit.list('g1').map((e) => e.action);
    expect(actions).toEqual(['grant_created', 'ownership_verified', 'owner_signed', 'admin_approved', 'grant_activated']);
    // the returned list is a copy: mutating it does not change the log
    audit.list('g1').pop();
    expect(audit.list('g1').length).toBe(5);
  });

  it('revoke stops a previously-active grant', () => {
    auth.createGrant(grantInput(), 'a@agency.sa');
    auth.recordOwnershipVerified('g1', 'system');
    auth.ownerSign('g1', ownerLink, 'owner@lab.sa');
    auth.adminApprove('g1', 'admin');
    auth.revoke('g1', 'admin');
    expect(() => auth.assertScanAllowed('g1')).toThrow(/not active/);
  });
});

function activateGrant(host = LAB_HOST) {
  auth.createGrant(grantInput(host), 'a@agency.sa');
  auth.recordOwnershipVerified('g1', 'system');
  auth.ownerSign('g1', ownerLink, 'owner@lab.sa');
  auth.adminApprove('g1', 'admin');
}

describe('LabPolicy gate (§3.2)', () => {
  it('rejects a target outside the lab allow-list', async () => {
    activateGrant('evil.example.com');
    const svc = new ScanService({
      auth, lab: new LabPolicy(false, [LAB_HOST]), scans, audit,
      sender: vulnOrders, fingerprintSecret: 's', resolveHost: () => ['10.0.0.5'],
    });
    await expect(svc.run({ engagementId: 'E1', grantId: 'g1', flows: [flow], identities: [alice, bob], actor: 'admin' }))
      .rejects.toThrow(LabPolicyError);
  });
});

describe('session liveness (§7)', () => {
  it('drops an identity whose liveness probe fails and says so in notTested', async () => {
    activateGrant(LAB_HOST);
    const sender: Sender = async (req, ident) => {
      if (new URL(req.url).pathname === '/me') return ident.sessionRef === 'sess-alice' ? json(200, '{"me":1}') : json(401, '{}');
      return vulnOrders(req, ident);
    };
    const svc = new ScanService({
      auth, lab: new LabPolicy(false, [LAB_HOST]), scans, audit, sender, fingerprintSecret: 's',
      liveness: { 'sess-alice': `https://${LAB_HOST}/me`, 'sess-bob': `https://${LAB_HOST}/me` },
      pacing: { requestsPerSecond: 1000 },
    });
    const scan = await svc.run({ engagementId: 'E1', grantId: 'g1', flows: [flow], identities: [alice, bob], actor: 'admin', skipChecks: true });
    expect(scan.notTested.some((n) => n.includes("session 'sess-bob' failed its liveness probe"))).toBe(true);
    // bob is gone, so only the anonymous challenger remains and orders/42 needs login -> no IDOR claimed
    expect(scan.findings).toHaveLength(0);
    expect(scan.telemetry?.requests).toBeGreaterThan(0);
  });
});

describe('scope-gated scan + report', () => {
  it('runs on a lab target and confirms a BOLA finding', async () => {
    activateGrant(LAB_HOST);
    const svc = new ScanService({
      auth, lab: new LabPolicy(false, [LAB_HOST]), scans, audit,
      sender: vulnOrders, fingerprintSecret: 's', resolveHost: () => ['10.0.0.5'],
    });
    const scan = await svc.run({ engagementId: 'E1', grantId: 'g1', flows: [flow], identities: [alice, bob], actor: 'admin' });
    expect(scan.status).toBe('done');
    expect(scan.findings.length).toBeGreaterThanOrEqual(1);
    expect(scan.findings[0].id).toContain('bola_idor');
    expect(audit.list('g1').some((e) => e.action === 'scan_run')).toBe(true);

    const engagement: Engagement = {
      id: 'E1', client: 'Lab', preparedBy: 'SecScan', assets: [LAB_HOST], environment: 'lab',
      authorizationRef: 'g1', window: { start: grantInput().notBefore, end: grantInput().notAfter },
      methodology: { ar: 'اختبار صلاحيات', en: 'Authorization testing' },
      limitations: { ar: 'المعمل فقط', en: 'Lab only' },
    } as Engagement;
    engs.save(engagement);
    const report = new ReportService(engs, scans).render('E1', scan.id, 'ar');
    expect(report).toContain('تقرير تقييم أمني');
    expect(report).toContain('ما الذي لم يُفحص'); // coverage-limits section always present
  });
});
