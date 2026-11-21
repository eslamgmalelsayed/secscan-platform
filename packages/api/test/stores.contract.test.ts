/**
 * Store contract: the in-memory stores and the Postgres stores must behave
 * identically. The Postgres half runs only when SECSCAN_TEST_DATABASE_URL is
 * set (see `npm run db:test:setup`); it truncates its own test database.
 */
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { Finding, type Engagement } from '@secscan/shared';
import type { AuthorizationGrant } from '@secscan/engine';
import {
  AppendOnlyAuditLog, InMemoryEngagementRepo, InMemoryGrantRepo, InMemoryOwnerChallengeStore, InMemoryScanRepo,
  AuthorizationService, MemoryMailer,
  type GrantRecord, type ScanRecord,
} from '../src/core';
import type { CoreStores } from '../src/http/core-factory';
import { createPrismaStores, type PrismaStoresHandle } from '../src/persistence/prismaStores';

const T = '2026-10-22T10:00:00.000Z';

function grantRecord(id = 'g1'): GrantRecord {
  const grant: AuthorizationGrant = {
    grantId: id,
    targets: [{ host: 'app.example.com', scheme: 'https', port: null }, { host: 'api.example.com', scheme: 'https', port: 8443 }],
    ownershipProof: 'dns_txt', ownershipToken: 'tok',
    chain: [
      { party: 'Agency', email: 'a@agency.sa', role: 'requester', signedAt: T, statement: 'request' },
      { party: 'Owner', email: 'o@example.com', role: 'system_owner', signedAt: T, statement: 'ok' },
    ],
    notBefore: T, notAfter: '2026-10-23T10:00:00.000Z', allowStateChanging: false, status: 'active',
  };
  return { grant, ownershipVerified: true, ownershipMethod: 'automatic', adminApproved: true };
}

const finding = (id: string, sev: Finding['severity'], withCvss = true): Finding => Finding.parse({
  id, title: { ar: 'عنوان', en: 'Title' }, severity: sev, confidence: 'confirmed',
  ...(withCvss ? { cvss: { score: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' } } : {}),
  asset: 'app.example.com', location: 'GET /orders/1',
  description: { ar: 'و', en: 'd' }, impact: { ar: 'أ', en: 'i' }, remediation: { ar: 'ح', en: 'r' },
  evidence: [{ kind: 'note', label: 'l', content: 'c' }], controls: [{ framework: 'CWE', control: 'CWE-639' }],
  source: 'test', firstSeen: T,
});

function scanRecord(): ScanRecord {
  return {
    id: 'scan-1', engagementId: 'E1', grantId: 'g1', status: 'done',
    findings: [finding('AC-1', 'high'), finding('CHK-2', 'medium', false)],
    review: [finding('AC-3', 'high')],
    notTested: ['skipped: x', 'deny_no_grant: y'],
    telemetry: { requests: 12, durationMs: 340, costPerConfirmedFinding: null },
    createdAt: T,
  };
}

const engagement: Engagement = {
  id: 'E1', client: 'Lab', preparedBy: 'SecScan', assets: ['app.example.com'], environment: 'staging',
  authorizationRef: 'g1', window: { start: T, end: '2026-10-23T10:00:00.000Z' },
  methodology: { ar: 'م', en: 'm' }, limitations: { ar: 'ح', en: 'l' },
};

function contract(name: string, make: () => Promise<CoreStores>, extra?: (s: () => CoreStores) => void) {
  describe(`store contract: ${name}`, () => {
    let s: CoreStores;
    beforeEach(async () => { s = await make(); });

    it('grant round-trips exactly, including target and chain order', async () => {
      const rec = grantRecord();
      await s.grants.save(rec);
      expect(await s.grants.get('g1')).toEqual(rec);
      expect(await s.grants.get('missing')).toBeUndefined();
    });

    it('re-saving a grant replaces targets and chain instead of duplicating them', async () => {
      const rec = grantRecord();
      await s.grants.save(rec);
      rec.grant.chain = rec.grant.chain.slice(0, 1);
      rec.grant.status = 'revoked';
      await s.grants.save(rec);
      const back = (await s.grants.get('g1'))!;
      expect(back.grant.chain).toHaveLength(1);
      expect(back.grant.status).toBe('revoked');
      expect(await s.grants.list()).toHaveLength(1);
    });

    it('engagement round-trips', async () => {
      await s.engagements.save(engagement);
      expect(await s.engagements.get('E1')).toEqual(engagement);
    });

    it('scan round-trips with confirmed and review findings kept apart and in order', async () => {
      await s.grants.save(grantRecord());
      const scan = scanRecord();
      await s.scans.save(scan);
      expect(await s.scans.get('scan-1')).toEqual(scan);
      expect((await s.scans.list('E1')).map((x) => x.id)).toEqual(['scan-1']);
      expect(await s.scans.list('other')).toEqual([]);
    });

    it('appends concurrent retest events to the finding without replacing the scan', async () => {
      await s.grants.save(grantRecord());
      const scan = scanRecord();
      await s.scans.save(scan);
      await Promise.all(['r1','r2'].map(note => s.scans.appendRetest(scan.id,scan.findings[0].id,{at:T,result:'inconclusive',note})));
      const back=await s.scans.get(scan.id);
      expect(back!.findings[0].retests.map(e=>e.note)).toEqual(expect.arrayContaining(['r1','r2']));
      expect(back!.review).toEqual(scan.review);
    });

    it('audit is ordered and returns copies', async () => {
      await s.grants.save(grantRecord());
      await s.audit.append({ actor: 'a', action: 'one', grantId: 'g1' });
      await s.audit.append({ actor: 'b', action: 'two', grantId: 'g1', detail: 'd' });
      await s.audit.append({ actor: 'c', action: 'unrelated' });
      const g1 = await s.audit.list('g1');
      expect(g1.map((e) => e.action)).toEqual(['one', 'two']);
      expect(g1[1].detail).toBe('d');
      expect((await s.audit.list()).map((e) => e.action)).toEqual(['one', 'two', 'unrelated']);
    });

    it('owner challenge put/get/delete', async () => {
      await s.grants.save(grantRecord());
      const c = { id: 'c1', grantId: 'g1', party: 'P', email: 'o@example.com', statement: 's', codeHash: 'ab', expiresAt: T, attempts: 0 };
      await s.challenges.put(c);
      expect(await s.challenges.get('c1')).toEqual(c);
      await s.challenges.put({ ...c, attempts: 2 });
      expect((await s.challenges.get('c1'))!.attempts).toBe(2);
      await s.challenges.delete('c1');
      expect(await s.challenges.get('c1')).toBeUndefined();
    });

    it('the full owner sign-off flow works on this store', async () => {
      const mailer = new MemoryMailer();
      const auth = new AuthorizationService(s.grants, s.audit, { mailer, challenges: s.challenges, secret: 'k' });
      const rec = grantRecord('g2');
      rec.grant.chain = rec.grant.chain.slice(0, 1);
      await auth.createGrant({ ...rec.grant, status: 'pending_owner' }, 'agency');
      const { challengeId } = await auth.requestOwnerSignature('g2', { party: 'Owner', email: 'boss@example.com', statement: 'ok' }, 'agency');
      const code = /code to the requester: (\d{6})/.exec(mailer.sent[0].text)![1];
      await auth.confirmOwnerSignature('g2', challengeId, code, 'agency');
      const back = (await s.grants.get('g2'))!;
      expect(back.grant.chain.at(-1)!.role).toBe('system_owner');
      expect((await s.audit.list('g2')).map((e) => e.action)).toEqual(['grant_created', 'owner_signature_requested', 'owner_signed']);
    });

    extra?.(() => s);
  });
}

contract('in-memory', async () => ({
  grants: new InMemoryGrantRepo(), engagements: new InMemoryEngagementRepo(), scans: new InMemoryScanRepo(),
  audit: new AppendOnlyAuditLog(), challenges: new InMemoryOwnerChallengeStore(),
}));

const PG_URL = process.env.SECSCAN_TEST_DATABASE_URL;
let handle: PrismaStoresHandle | undefined;

if (PG_URL) {
  contract('postgres', async () => {
    handle ??= createPrismaStores(PG_URL);
    // TRUNCATE does not fire the row-level append-only triggers, so the test DB can be reset.
    await handle.db.$executeRawUnsafe(
      'TRUNCATE "AuditEntry","Finding","Scan","OwnerChallenge","ChainLink","Target","Engagement","Grant" RESTART IDENTITY CASCADE',
    );
    return handle.stores;
  }, () => {
    it('persists assessment snapshots and rejects a stale project revision', async () => {
      const { Assessments } = await import('../src/core/assessment');
      const service = new Assessments(handle!.stores.projects!);
      const p = await service.create('owner',{name:'PG assessment',assets:['example'],authorization:'permit',expires:'2099-01-01T00:00:00Z'});
      await service.change('owner',p.id,p.revision,{type:'publish'});
      await expect(service.change('owner',p.id,p.revision,{type:'publish'})).rejects.toThrow('Reload');
      expect((await service.get('owner',p.id)).reports).toHaveLength(1);
    });
    it('the database itself refuses UPDATE and DELETE on the audit log', async () => {
      await handle!.stores.audit.append({ actor: 'a', action: 'x' });
      await expect(handle!.db.auditEntry.updateMany({ data: { actor: 'evil' } })).rejects.toThrow(/append-only/);
      await expect(handle!.db.auditEntry.deleteMany({})).rejects.toThrow(/append-only/);
    });
  });
} else {
  describe.skip('store contract: postgres (set SECSCAN_TEST_DATABASE_URL to run)', () => { it('skipped', () => {}); });
}

afterAll(async () => { await handle?.close(); });
