import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { coverage, type Operation, type Outcome, type Project } from '@secscan/shared';
import { Assessments, MemoryProjectStore, type ProjectStore } from '../src/core/assessment';
import { FileProjects } from '../src/persistence/fileProjects';
import { importCases } from '../src/core/assessmentImports';
import { RetestService } from '../src/core/retestService';
import { InMemoryScanRepo } from '../src/core/repositories';

const input = {
  name: 'Demo',
  assets: ['demo'],
  authorization: 'Permit 1',
  expires: '2099-01-01T00:00:00.000Z',
};
const row = {
  domain: 'Business logic' as const,
  asset: 'demo',
  title: 'Order approval',
  expected: 'Second reviewer required',
};
const temp: string[] = [];
afterEach(async () => {
  for (const dir of temp.splice(0)) await rm(dir, { recursive: true, force: true });
});
async function fixture(store: ProjectStore = new MemoryProjectStore()) {
  const svc = new Assessments(store);
  let p = await svc.create('owner', input);
  const change = async (action: Operation, actor = 'owner') =>
    (p = await svc.change(actor, p.id, p.revision, action));
  await change({ type: 'plan', cases: [row] });
  const observe = (outcome: Outcome, baseline?: string) =>
    change({
      type: 'observe',
      caseId: p.cases[0].id,
      outcome,
      context: 'v1',
      evidence: 'Observed behavior',
      baseline,
    });
  const review = (approve = true) =>
    change({
      type: 'review',
      caseId: p.cases[0].id,
      observationId: p.cases[0].observations.at(-1)!.id,
      approve,
      reason: 'Reviewed',
    });
  return {
    svc,
    change,
    observe,
    review,
    get p() {
      return p;
    },
  };
}
describe('assessment decisions', () => {
  it('requires a positive control on closure, retains history and reopens regressions', async () => {
    const f = await fixture();
    await f.observe('fail');
    await f.review();
    await f.observe('inconclusive');
    await f.review();
    expect(f.p.cases[0].state).toBe('open');
    expect(coverage(f.p.cases).inconclusive).toBe(1);
    await f.observe('pass');
    await expect(f.review()).rejects.toThrow('positive control');
    await f.observe('pass', 'The owner could access the same resource');
    await f.review();
    expect(f.p.cases[0].state).toBe('fixed');
    await f.change({ type: 'publish' });
    const published = f.p.reports[0];
    await f.observe('fail');
    await f.review();
    expect(f.p.cases[0].state).toBe('open');
    expect(f.p.reports[0]).toEqual(published);
    expect(published.ar).toContain('تم التحقق');
    expect(published.en).toContain('fixed');
  });
  it('enforces roles, isolation and stale revisions', async () => {
    const f = await fixture();
    await expect(f.svc.get('stranger', f.p.id)).rejects.toThrow('not found');
    await f.change({ type: 'member', name: 'reader', role: 'reader' });
    await expect(f.change({ type: 'publish' }, 'reader')).rejects.toThrow();
    await f.change({ type: 'member', name: 'tester', role: 'tester' });
    await f.change(
      {
        type: 'observe',
        caseId: f.p.cases[0].id,
        outcome: 'fail',
        context: 'build',
        evidence: 'Cookie: sid=example',
      },
      'tester',
    );
    expect(f.p.cases[0].observations[0].evidence).toBe('Cookie: [redacted]');
    await expect(f.change({ type: 'publish' }, 'tester')).rejects.toThrow();
    await expect(f.svc.change('owner', f.p.id, 1, { type: 'publish' })).rejects.toThrow('Reload');
  });
  it('rolls back a partially invalid batch and rejects an expired grant', async () => {
    const f = await fixture();
    await expect(
      f.change({
        type: 'plan',
        cases: [
          { ...row, title: 'First' },
          { ...row, asset: 'other' },
        ],
      }),
    ).rejects.toThrow('outside');
    expect((await f.svc.get('owner', f.p.id)).cases.length).toBe(1);
    await expect(f.svc.create('owner', { ...input, expires: '2000-01-01T00:00:00.000Z' })).rejects.toThrow(
      'expired',
    );
  });
  it('rejects concurrent writes and restores complete revisions in local mode', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'secscan-assessment-'));
    temp.push(dir);
    const file = new FileProjects(dir);
    const f = await fixture(file);
    const other = new Assessments(new FileProjects(dir));
    const writes = await Promise.allSettled(
      [f.svc, other].map((s) => s.change('owner', f.p.id, f.p.revision, { type: 'publish' })),
    );
    expect(writes.filter((w) => w.status === 'fulfilled')).toHaveLength(1);
    expect((await other.get('owner', f.p.id)).reports).toHaveLength(1);
  });
  it('deduplicates repeated imports for the same revision', async () => {
    const f = await fixture();
    const action: Operation = {
      type: 'import',
      format: 's3',
      asset: 'demo',
      context: 'build1',
      data: { PublicAccessBlockConfiguration: { BlockPublicAcls: false } },
    };
    await f.change(action);
    await f.change(action);
    expect(f.p.cases).toHaveLength(5);
    expect(f.p.cases.slice(1).every((c) => c.observations.length === 1)).toBe(true);
  });
});
describe('read-only domain evidence', () => {
  const collect = (format: Extract<Operation, { type: 'import' }>['format'], data: unknown) =>
    importCases({ type: 'import', format, data, asset: 'demo', context: 'b' });
  it.each([
    ['s3', { PublicAccessBlockConfiguration: {} }, 'inconclusive'],
    ['s3', { PublicAccessBlockConfiguration: { BlockPublicAcls: false } }, 'fail'],
    ['s3', { PublicAccessBlockConfiguration: { BlockPublicAcls: true } }, 'pass'],
    ['ios', { bundle: 'org.demo', build: '1', allowsArbitraryLoads: true, exceptionDomains: [] }, 'fail'],
    ['android', { packageName: 'org.demo' }, 'inconclusive'],
    ['android', { packageName: 'org.demo', debuggable: true }, 'fail'],
    ['android', { packageName: 'org.demo', debuggable: false }, 'pass'],
    [
      'isolation',
      { service: 'test', baseline: 'reachable', guest: 'unknown', evidence: 'timeout' },
      'inconclusive',
    ],
    [
      'isolation',
      { service: 'test', baseline: 'unavailable', guest: 'verified-policy-deny', evidence: 'no control' },
      'inconclusive',
    ],
    [
      'isolation',
      { service: 'test', baseline: 'reachable', guest: 'same-service-reachable', evidence: 'marker' },
      'fail',
    ],
    [
      'isolation',
      {
        service: 'test',
        baseline: 'reachable',
        guest: 'verified-policy-deny',
        evidence: 'matched firewall event',
      },
      'pass',
    ],
    ['iam', { Statement: { Effect: 'Allow', Action: '*', Resource: '*' } }, 'fail'],
    ['iam', { Statement: { Effect: 'Allow', Action: '*', Resource: '*', Condition: {} } }, 'inconclusive'],
    ['wifi', { platform: 'linux', at: '2026-01-01T00:00:00Z', wifi: {} }, 'inconclusive'],
    [
      'sarif',
      {
        version: '2.1.0',
        runs: [
          { tool: { driver: { name: 'sample' } }, results: [{ ruleId: 'R', message: { text: 'review' } }] },
        ],
      },
      'inconclusive',
    ],
    [
      'cyclonedx',
      { bomFormat: 'CycloneDX', components: [], vulnerabilities: [{ id: 'sample' }] },
      'inconclusive',
    ],
  ] as const)('classifies %s %j', (format, data, expected) =>
    expect(collect(format, data)[0].outcome).toBe(expected),
  );
  it('plans OpenAPI without executing operations', () =>
    expect(
      collect('openapi', { openapi: '3.1.0', paths: { '/a': { post: {}, parameters: [] } } }).map(
        (c) => c.title,
      ),
    ).toEqual(['POST /a']));
});
describe('legacy retest', () => {
  it('never closes on a failed scan', async () => {
    const scans = new InMemoryScanRepo();
    await scans.save({
      id: 'one',
      grantId: 'G',
      engagementId: 'E',
      status: 'done',
      createdAt: '',
      notTested: [],
      findings: [{ id: 'F', status: 'open', retests: [] } as any],
    });
    const service = new RetestService(scans, {
      run: async () => ({ id: 'two', status: 'failed', findings: [] }),
    } as any);
    expect((await service.retest('one', 'F', { grantId: 'G', engagementId: 'E' } as any)).result).toBe(
      'inconclusive',
    );
    expect((await scans.get('one'))!.findings[0].status).toBe('open');
  });
});

describe('project evidence access', () => {
  it('requires membership and a referenced attachment before issuing a link', async () => {
    const blobs = new Map<string, string>();
    const store = new MemoryProjectStore();
    const svc = new Assessments(store, {
      async put(id, text) {
        blobs.set(id, text);
        return 'samplehash';
      },
      async read() {
        return { url: 'https://example.invalid/signed' };
      },
    });
    let p = await svc.create('owner', input);
    p = await svc.change('owner', p.id, p.revision, { type: 'plan', cases: [row] });
    p = await svc.change('owner', p.id, p.revision, {
      type: 'observe',
      caseId: p.cases[0].id,
      context: 'v1',
      evidence: 'fixture',
      attachment: 'Authorization: Bearer sample',
      outcome: 'inconclusive',
    });
    expect(blobs.get(p.id)).toBe('Authorization: [redacted]');
    await expect(svc.attachment('other', p.id, 'samplehash')).rejects.toThrow('not found');
    await expect(svc.attachment('owner', p.id, 'unreferenced')).rejects.toThrow('not found');
    await expect(svc.attachment('owner', p.id, 'samplehash')).resolves.toHaveProperty('url');
    expect((await svc.get('owner', p.id)).history.at(-1)?.action).toContain('attachment access');
  });
});

describe('import titles longer than the label limit', () => {
  it('records the row with a shortened title that keeps the rule and line', async () => {
    const f = await fixture();
    const uri = 'src/' + 'deep/'.repeat(60) + 'file.ts';
    const result = (startLine: number) => ({
      ruleId: 'js/sql-injection',
      message: { text: 'Tainted query' },
      locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine } } }],
    });
    await f.change({
      type: 'import',
      format: 'sarif',
      asset: 'demo',
      context: 'commit abc',
      data: { version: '2.1.0', runs: [{ tool: { driver: { name: 'scanner' } }, results: [result(7), result(912)] }] },
    });
    const titles = f.p.cases.slice(1).map((c) => c.title);
    expect(titles).toHaveLength(2);
    for (const title of titles) expect(title.length).toBeLessThanOrEqual(240);
    expect(titles[0].startsWith('js/sql-injection')).toBe(true);
    expect(titles[0].endsWith('file.ts#7')).toBe(true);
    expect(titles[1].endsWith('file.ts#912')).toBe(true);
  });
});
