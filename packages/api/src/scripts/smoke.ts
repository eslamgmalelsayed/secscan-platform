/**
 * End-to-end HTTP smoke test (no network, no DB): builds the Nest/Fastify app
 * with a fake vulnerable lab target and drives the full lifecycle via
 * fastify.inject. Run from compiled dist: `npm run smoke`.
 */
import type { Identity, RecordedRequest, RecordedResponse, Sender } from '@secscan/engine';
import { LabPolicy } from '../core';
import { buildApp } from '../http/app';

const LAB = 'lab.internal';
const NOW = new Date();

const json = (status: number, body: string): RecordedResponse => ({ status, headers: { 'content-type': 'application/json' }, body });
const vulnOrders: Sender = async (req: RecordedRequest, ident: Identity) => {
  if (new URL(req.url).pathname.startsWith('/orders/')) {
    if (!ident.sessionRef) return json(403, '{"e":"login"}');
    return json(200, '{"order":42,"buyer":"alice"}');
  }
  return json(404, '{}');
};

const grant = {
  grantId: 'g1', targets: [{ host: LAB }], ownershipProof: 'dns_txt', ownershipToken: 'tok',
  chain: [{ party: 'Agency', email: 'a@agency.sa', role: 'requester', signedAt: NOW.toISOString(), statement: 'request' }],
  notBefore: new Date(NOW.getTime() - 3.6e6).toISOString(),
  notAfter: new Date(NOW.getTime() + 3.6e6).toISOString(), status: 'pending_owner',
};
const ownerLink = { party: 'Lab Owner', email: 'owner@lab.sa', role: 'system_owner', signedAt: NOW.toISOString(), statement: 'I authorize' };
const flows = [{ method: 'GET', url: `https://${LAB}/orders/42`, capturedAsRole: 'customer', capturedAsTenant: 't1' }];
const identities = [
  { role: 'customer', tenant: 't1', sessionRef: 'sess-alice' },
  { role: 'customer', tenant: 't1', sessionRef: 'sess-bob' },
];
const engagement = {
  id: 'E1', client: 'Lab', preparedBy: 'SecScan', assets: [LAB], environment: 'lab', authorizationRef: 'g1',
  window: { start: grant.notBefore, end: grant.notAfter },
  methodology: { ar: 'اختبار صلاحيات', en: 'Authorization testing' },
  limitations: { ar: 'المعمل فقط', en: 'Lab only' },
};

let passed = 0, failed = 0;
function check(name: string, cond: boolean, extra = '') {
  if (cond) { passed++; console.log(`PASS ${name}`); }
  else { failed++; console.log(`FAIL ${name} ${extra}`); }
}

async function main() {
  const app = await buildApp({
    lab: new LabPolicy(false, [LAB]), sender: vulnOrders,
    fingerprintSecret: 'secret', resolveHost: () => ['10.0.0.5'],
  });
  const f = app.getHttpAdapter().getInstance();
  const post = (url: string, payload: unknown) => f.inject({ method: 'POST', url, payload: payload as any });
  const get = (url: string) => f.inject({ method: 'GET', url });

  check('health', JSON.parse((await get('/health')).payload).legalResolved === false);
  check('create grant', (await post('/grants', { grant, actor: 'a@agency.sa' })).statusCode === 201);

  const early = await post('/scans', { engagementId: 'E1', grantId: 'g1', flows, identities, actor: 'admin' });
  check('scan blocked before activation (403)', early.statusCode === 403, `got ${early.statusCode}`);

  await post('/grants/g1/ownership', { actor: 'system' });
  await post('/grants/g1/owner-sign', { link: ownerLink, actor: 'owner@lab.sa' });
  const approved = JSON.parse((await post('/grants/g1/approve', { actor: 'admin' })).payload);
  check('grant active after lifecycle', approved.status === 'active', JSON.stringify(approved));

  await post('/engagements', { engagement });
  const scanResp = await post('/scans', { engagementId: 'E1', grantId: 'g1', flows, identities, actor: 'admin' });
  const scan = JSON.parse(scanResp.payload);
  check('scan runs and confirms a finding', scanResp.statusCode === 201 && scan.confirmed >= 1, JSON.stringify(scan));

  const report = JSON.parse((await get(`/scans/${scan.id}/report?lang=ar`)).payload);
  check('bilingual report renders', typeof report.markdown === 'string' && report.markdown.includes('تقرير تقييم أمني'));

  const auditEntries = JSON.parse((await get('/grants/g1/audit')).payload);
  check('audit trail recorded scan_run', auditEntries.some((e: any) => e.action === 'scan_run'));

  await app.close();
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
