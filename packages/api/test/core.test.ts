import { describe, it, expect, beforeEach } from 'vitest';
import type { Identity, RecordedRequest, RecordedResponse, Sender } from '@secscan/engine';
import type { Engagement } from '@secscan/shared';
import {
  AppendOnlyAuditLog, AuthorizationService, AuthorizationError, LabPolicy, LabPolicyError,
  ReportService, RetestService, ScanService, ScanPreconditionError,
  InMemoryGrantRepo, InMemoryEngagementRepo, InMemoryScanRepo, MemoryMailer,
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
const flow: RecordedRequest = { method: 'GET', url: `https://${LAB_HOST}/orders/42`, ownsObject: true, capturedAsRole: 'customer', capturedAsTenant: 't1' };
const engagementE1 = (): Engagement => ({
  id: 'E1', client: 'Lab', preparedBy: 'SecScan', assets: [LAB_HOST], environment: 'lab',
  authorizationRef: 'g1', window: { start: grantInput().notBefore, end: grantInput().notAfter },
  methodology: { ar: 'اختبار صلاحيات', en: 'Authorization testing' },
  limitations: { ar: 'المعمل فقط', en: 'Lab only' },
} as Engagement);

let grants: InMemoryGrantRepo, engs: InMemoryEngagementRepo, scans: InMemoryScanRepo, audit: AppendOnlyAuditLog, auth: AuthorizationService;
beforeEach(() => {
  grants = new InMemoryGrantRepo(); engs = new InMemoryEngagementRepo(); scans = new InMemoryScanRepo();
  audit = new AppendOnlyAuditLog(); auth = new AuthorizationService(grants, audit);
});

describe('authorization lifecycle', () => {
  it('blocks a scan until ownership + owner-sign + admin-approve, then activates', async () => {
    await auth.createGrant(grantInput(), 'a@agency.sa');
    await expect(auth.assertScanAllowed('g1')).rejects.toThrow(AuthorizationError); // ownership not verified
    await auth.recordOwnershipVerified('g1', 'system');
    await expect(auth.assertScanAllowed('g1')).rejects.toThrow(/owner has not signed/);
    await auth.ownerSign('g1', ownerLink, 'owner@lab.sa');
    await expect(auth.assertScanAllowed('g1')).rejects.toThrow(/admin has not approved/);
    const rec = await auth.adminApprove('g1', 'admin');
    expect(rec.grant.status).toBe('active');
    await expect(auth.assertScanAllowed('g1')).resolves.toBeDefined();
  });

  it('writes an append-only audit trail in order', async () => {
    await auth.createGrant(grantInput(), 'a@agency.sa');
    await auth.recordOwnershipVerified('g1', 'system');
    await auth.ownerSign('g1', ownerLink, 'owner@lab.sa');
    await auth.adminApprove('g1', 'admin');
    const actions = (await audit.list('g1')).map((e) => e.action);
    expect(actions).toEqual(['grant_created', 'ownership_recorded_manually', 'owner_signed_manually', 'admin_approved', 'grant_activated']);
    // the returned list is a copy: mutating it does not change the log
    (await audit.list('g1')).pop();
    expect((await audit.list('g1')).length).toBe(5);
  });

  it('automatic ownership proof only flips the flag when every target passes, and audits failures', async () => {
    await auth.createGrant(grantInput(), 'a@agency.sa');
    const fail = await auth.verifyOwnership('g1', 'system', { resolveTxt: async () => [['secscan-verify=wrong']] });
    expect(fail.verification.ok).toBe(false);
    expect((await grants.get('g1'))!.ownershipVerified).toBe(false);
    const ok = await auth.verifyOwnership('g1', 'system', { resolveTxt: async () => [['secscan-verify=tok']] });
    expect(ok.verification.ok).toBe(true);
    expect((await grants.get('g1'))!.ownershipVerified).toBe(true);
    expect((await audit.list('g1')).map((e) => e.action)).toEqual(['grant_created', 'ownership_verification_failed', 'ownership_verified']);
  });

  it('revoke stops a previously-active grant', async () => {
    await auth.createGrant(grantInput(), 'a@agency.sa');
    await auth.recordOwnershipVerified('g1', 'system');
    await auth.ownerSign('g1', ownerLink, 'owner@lab.sa');
    await auth.adminApprove('g1', 'admin');
    await auth.revoke('g1', 'admin');
    await expect(auth.assertScanAllowed('g1')).rejects.toThrow(/not active/);
  });
});

async function activateGrant(host = LAB_HOST) {
  await auth.createGrant(grantInput(host), 'a@agency.sa');
  await auth.recordOwnershipVerified('g1', 'system');
  await auth.ownerSign('g1', ownerLink, 'owner@lab.sa');
  await auth.adminApprove('g1', 'admin');
}

describe('LabPolicy gate (§3.2)', () => {
  it('rejects a target outside the lab allow-list', async () => {
    await activateGrant('evil.example.com');
    const svc = new ScanService({
      auth, lab: new LabPolicy(false, [LAB_HOST], { allowPrivateTargets: true }), scans, engagements: engs, audit,
      sender: vulnOrders, fingerprintSecret: 's', resolveHost: () => ['10.0.0.5'],
    });
    await expect(svc.run({ engagementId: 'E1', grantId: 'g1', flows: [flow], identities: [alice, bob], actor: 'admin' }))
      .rejects.toThrow(LabPolicyError);
  });
});

describe('owner sign-off by email code (§6)', () => {
  function svc(now = () => new Date()) {
    const mailer = new MemoryMailer();
    return { mailer, auth: new AuthorizationService(grants, audit, { mailer, secret: 'k', now }) };
  }
  const owner = { party: 'Owner', email: 'boss@example.com', statement: 'I authorize testing' };
  const codeFrom = (m: MemoryMailer) => /code to the requester: (\d{6})/.exec(m.sent.at(-1)!.text)![1];

  it('a correct code appends a server-written system_owner link', async () => {
    const { mailer, auth: a } = svc();
    await a.createGrant(grantInput('app.example.com'), 'agency');
    const { challengeId } = await a.requestOwnerSignature('g1', owner, 'agency');
    const rec = await a.confirmOwnerSignature('g1', challengeId, codeFrom(mailer), 'agency');
    const link = rec.grant.chain.find((l) => l.role === 'system_owner')!;
    expect(link.email).toBe('boss@example.com');
    expect(rec.grant.status).toBe('pending_owner'); // still needs ownership proof + admin approval
  });

  it('refuses an owner mailbox that is not on every target domain', async () => {
    const { auth: a } = svc();
    await a.createGrant(grantInput('app.example.com'), 'agency');
    await expect(a.requestOwnerSignature('g1', { ...owner, email: 'boss@gmail.com' }, 'agency')).rejects.toThrow(/domain/);
    await expect(a.requestOwnerSignature('g1', { ...owner, email: 'boss@notexample.com' }, 'agency')).rejects.toThrow(/domain/);
  });

  it('locks the challenge after five wrong codes', async () => {
    const { mailer, auth: a } = svc();
    await a.createGrant(grantInput('app.example.com'), 'agency');
    const { challengeId } = await a.requestOwnerSignature('g1', owner, 'agency');
    const wrong = codeFrom(mailer) === '000000' ? '111111' : '000000';
    for (let i = 0; i < 4; i++) await expect(a.confirmOwnerSignature('g1', challengeId, wrong, 'agency')).rejects.toThrow(/incorrect/);
    await expect(a.confirmOwnerSignature('g1', challengeId, wrong, 'agency')).rejects.toThrow(/too many/);
    await expect(a.confirmOwnerSignature('g1', challengeId, codeFrom(mailer), 'agency')).rejects.toThrow(/unknown/);
  });

  it('rejects an expired code', async () => {
    let t = Date.now();
    const { mailer, auth: a } = svc(() => new Date(t));
    await a.createGrant(grantInput('app.example.com'), 'agency');
    const { challengeId } = await a.requestOwnerSignature('g1', owner, 'agency');
    t += 11 * 60_000;
    await expect(a.confirmOwnerSignature('g1', challengeId, codeFrom(mailer), 'agency')).rejects.toThrow(/expired/);
  });
});

describe('session liveness (§7)', () => {
  it('drops an identity whose liveness probe fails and says so in notTested', async () => {
    await activateGrant(LAB_HOST);
    const sender: Sender = async (req, ident) => {
      if (new URL(req.url).pathname === '/me') return ident.sessionRef === 'sess-alice' ? json(200, '{"me":1}') : json(401, '{}');
      return vulnOrders(req, ident);
    };
    await engs.save(engagementE1());
    const svc = new ScanService({
      auth, lab: new LabPolicy(false, [LAB_HOST], { allowPrivateTargets: true }), scans, engagements: engs, audit, sender, fingerprintSecret: 's',
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
    await activateGrant(LAB_HOST);
    await engs.save(engagementE1());
    const svc = new ScanService({
      auth, lab: new LabPolicy(false, [LAB_HOST], { allowPrivateTargets: true }), scans, engagements: engs, audit,
      sender: vulnOrders, fingerprintSecret: 's', resolveHost: () => ['10.0.0.5'],
    });
    const scan = await svc.run({ engagementId: 'E1', grantId: 'g1', flows: [flow], identities: [alice, bob], actor: 'admin' });
    expect(scan.status).toBe('done');
    expect(scan.findings.length).toBeGreaterThanOrEqual(1);
    expect(scan.findings[0].id).toContain('bola_idor');
    expect((await audit.list('g1')).some((e) => e.action === 'scan_run')).toBe(true);

    const report = await new ReportService(engs, scans).render('E1', scan.id, 'ar');
    expect(report).toContain('تقرير تقييم أمني');
    expect(report).toContain('ما الذي لم يُفحص'); // coverage-limits section always present
  }, 20000);
});

function labSvc(sender: Sender) {
  return new ScanService({
    auth, lab: new LabPolicy(false, [LAB_HOST], { allowPrivateTargets: true }), scans, engagements: engs, audit,
    sender, fingerprintSecret: 's', resolveHost: () => ['10.0.0.5'], pacing: { requestsPerSecond: 1000 },
  });
}

describe('scan preconditions (gap 5)', () => {
  it('refuses a scan whose engagement does not exist, up front', async () => {
    await activateGrant(LAB_HOST); // note: no engagement saved
    await expect(labSvc(vulnOrders).run({ engagementId: 'E1', grantId: 'g1', flows: [flow], identities: [alice, bob], actor: 'admin' }))
      .rejects.toThrow(ScanPreconditionError);
  });
});

describe('operator stop (gap 3)', () => {
  it('halts on an aborted signal and records a partial, stopped result', async () => {
    await activateGrant(LAB_HOST); await engs.save(engagementE1());
    const ac = new AbortController(); ac.abort();
    const scan = await labSvc(vulnOrders).run({
      engagementId: 'E1', grantId: 'g1', flows: [flow], identities: [alice, bob], actor: 'admin',
      signal: ac.signal, skipChecks: true,
    });
    expect(scan.status).toBe('done');
    expect(scan.telemetry?.stopped).toBe(1);
    expect(scan.notTested.some((n) => n.includes('stopped'))).toBe(true);
  });
});

describe('retests (gap 4) + evidence bundle (gap 7)', () => {
  it('re-tests a finding after a fix and writes its retest history; bundle carries evidence', async () => {
    await activateGrant(LAB_HOST); await engs.save(engagementE1());
    let fixed = false;
    const sender: Sender = async (req, ident) => {
      if (new URL(req.url).pathname.startsWith('/orders/')) {
        if (!ident.sessionRef) return json(403, '{"e":"login"}');
        if (fixed && ident.sessionRef !== 'sess-alice') return json(403, '{"e":"forbidden"}'); // now enforced
        return json(200, '{"order":42,"buyer":"alice"}');
      }
      return json(404, '{}');
    };
    const svc = labSvc(sender);
    const req = { engagementId: 'E1', grantId: 'g1', flows: [flow], identities: [alice, bob], actor: 'admin' };
    const scan = await svc.run(req);
    const finding = scan.findings.find((f) => f.id.includes('bola_idor'))!;
    expect(finding).toBeDefined();

    // evidence bundle carries the finding and its evidence
    const bundle = await new ReportService(engs, scans).bundle('E1', scan.id);
    expect(bundle.engagement.id).toBe('E1');
    expect(bundle.findings.some((f) => f.id === finding.id)).toBe(true);
    expect(bundle.findings[0].evidence.length).toBeGreaterThan(0);

    fixed = true;
    const res = await new RetestService(scans, svc).retest(scan.id, finding.id, req);
    expect(res.result).toBe('fixed');
    const updated = await scans.get(scan.id);
    const back = updated!.findings.find((f) => f.id === finding.id)!;
    expect(back.retests?.length).toBe(1);
    expect(back.retests?.[0].result).toBe('fixed');
    expect(back.status).toBe('fixed');
  });
});
