/**
 * End-to-end HTTP smoke test (no network, no DB): builds the Nest/Fastify app
 * with a fake vulnerable lab target and drives the full lifecycle via
 * fastify.inject. Run from compiled dist: `npm run smoke`.
 */
import type { Identity, RecordedRequest, RecordedResponse, Sender } from '@secscan/engine';
import { LabPolicy, MemoryMailer } from '../core';
import { buildApp } from '../http/app';

const OPERATOR_TOKEN = 'op-token-0123456789abcdef';

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
const flows = [{ method: 'GET', url: `https://${LAB}/orders/42`, ownsObject: true, capturedAsRole: 'customer', capturedAsTenant: 't1' }];
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
  const mailer = new MemoryMailer();
  const app = await buildApp({
    lab: new LabPolicy(false, [LAB], { allowPrivateTargets: true }), sender: vulnOrders,
    fingerprintSecret: 'secret', resolveHost: () => ['10.0.0.5'], adminToken: 'adm',
    ownership: { resolveTxt: async () => [] }, // no TXT record in the lab => automatic proof fails
    auth: { tokens: { 'operator@lab': OPERATOR_TOKEN } },
    mailer,
  });
  const f = app.getHttpAdapter().getInstance();
  const bearer = { authorization: `Bearer ${OPERATOR_TOKEN}` };
  const post = (url: string, payload: unknown) => f.inject({ method: 'POST', url, payload: payload as any, headers: bearer });
  const get = (url: string) => f.inject({ method: 'GET', url, headers: bearer });

  // --- authentication ---
  const health = await f.inject({ method: 'GET', url: '/health' }); // public, no token
  check('health is public', health.statusCode === 200 && JSON.parse(health.payload).apiTokenRequired === true);
  const noTok = await f.inject({ method: 'GET', url: '/grants' });
  check('no bearer token is 401', noTok.statusCode === 401, `got ${noTok.statusCode}`);
  const badTok = await f.inject({ method: 'GET', url: '/grants', headers: { authorization: 'Bearer wrong-token-000000000' } });
  check('wrong bearer token is 401', badTok.statusCode === 401, `got ${badTok.statusCode}`);

  check('create grant', (await post('/grants', { grant, actor: 'someone-else@spoof' })).statusCode === 201);

  const early = await post('/scans', { engagementId: 'E1', grantId: 'g1', flows, identities, actor: 'admin' });
  check('scan blocked before activation (403)', early.statusCode === 403, `got ${early.statusCode}`);

  const postAdmin = (url: string, payload: unknown) => f.inject({ method: 'POST', url, payload: payload as any, headers: { ...bearer, 'x-admin-token': 'adm' } });

  const autoProof = JSON.parse((await post('/grants/g1/ownership', { actor: 'system' })).payload);
  check('automatic ownership proof fails without a TXT record', autoProof.ownershipVerified === false && autoProof.verification?.ok === false, JSON.stringify(autoProof));
  const noToken = await post('/grants/g1/ownership/manual', { actor: 'admin' });
  check('manual ownership without admin token is 403', noToken.statusCode === 403, `got ${noToken.statusCode}`);
  const badApprove = await post('/grants/g1/approve', { actor: 'admin' });
  check('approve without admin token is 403', badApprove.statusCode === 403, `got ${badApprove.statusCode}`);
  await postAdmin('/grants/g1/ownership/manual', { actor: 'admin' });
  // --- owner sign-off by email code ---
  const wrongDomain = await post('/grants/g1/owner-sign/request', { owner: { party: 'X', email: 'x@other.com', statement: 'ok' } });
  check('owner email off the target domain is refused (403)', wrongDomain.statusCode === 403, `got ${wrongDomain.statusCode}`);
  const reqSig = await post('/grants/g1/owner-sign/request', { owner: { party: 'Lab Owner', email: 'owner@lab.internal', statement: 'I authorize testing of lab.internal' } });
  const { challengeId } = JSON.parse(reqSig.payload);
  const sentCode = /code to the requester: (\d{6})/.exec(mailer.sent[0]?.text ?? '')?.[1];
  check('owner code emailed to the owner mailbox', reqSig.statusCode === 201 && !!challengeId && !!sentCode && mailer.sent[0].to === 'owner@lab.internal');
  const wrongCode = sentCode === '000000' ? '111111' : '000000';
  const bad = await post('/grants/g1/owner-sign/confirm', { challengeId, code: wrongCode });
  check('wrong owner code is refused (403)', bad.statusCode === 403, `got ${bad.statusCode}`);
  const signed = await post('/grants/g1/owner-sign/confirm', { challengeId, code: sentCode });
  check('correct owner code signs the grant', signed.statusCode === 201, `got ${signed.statusCode} ${signed.payload}`);
  const replay = await post('/grants/g1/owner-sign/confirm', { challengeId, code: sentCode });
  check('owner code cannot be reused', replay.statusCode === 403, `got ${replay.statusCode}`);
  const manualNoAdmin = await post('/grants/g1/owner-sign', { link: ownerLink });
  check('manual owner-sign without admin token is 403', manualNoAdmin.statusCode === 403, `got ${manualNoAdmin.statusCode}`);
  const approved = JSON.parse((await postAdmin('/grants/g1/approve', { actor: 'admin' })).payload);
  check('grant active after lifecycle', approved.status === 'active', JSON.stringify(approved));

  await post('/engagements', { engagement });
  const scanResp = await post('/scans', { engagementId: 'E1', grantId: 'g1', flows, identities, actor: 'admin' });
  const scan = JSON.parse(scanResp.payload);
  check('scan runs and confirms a finding', scanResp.statusCode === 201 && scan.confirmed >= 1, JSON.stringify(scan));

  const report = JSON.parse((await get(`/scans/${scan.id}/report?lang=ar`)).payload);
  check('bilingual report renders', typeof report.markdown === 'string' && report.markdown.includes('تقرير تقييم أمني'));

  const badEng = await post('/engagements', { engagement: { id: 'E2' } });
  check('malformed engagement rejected (400)', badEng.statusCode === 400, `got ${badEng.statusCode}`);
  const badScan = await post('/scans', { engagementId: 'E1', grantId: 'g1', flows: [{ method: 'GET', url: 'not a url' }], identities, actor: 'admin' });
  check('malformed flow rejected (400)', badScan.statusCode === 400, `got ${badScan.statusCode}`);
  const missing = await get('/scans/nope');
  check('unknown scan is 404', missing.statusCode === 404, `got ${missing.statusCode}`);

  const auditEntries = JSON.parse((await get('/grants/g1/audit')).payload);
  check('audit trail recorded scan_run', auditEntries.some((e: any) => e.action === 'scan_run'));
  const created = auditEntries.find((e: any) => e.action === 'grant_created');
  check('audit actor comes from the token, not the request body', created?.actor === 'operator@lab', JSON.stringify(created));
  check('audit never stores the owner address in full', !JSON.stringify(auditEntries).includes('owner@lab.internal'));

  // quick scan is refused unless dev-trust mode is on (the gate holds by default)
  const quickOff = await post('/scans/quick', { url: `https://${LAB}/`, actor: 'admin' });
  check('quick scan refused when dev-trust is off (403)', quickOff.statusCode === 403, `got ${quickOff.statusCode}`);

  await app.close();

  // Second app in dev-trust mode: a one-URL quick scan auto-grants, crawls, and
  // reports — no grant lifecycle, no flows, no auth.
  const html = (body: string): RecordedResponse => ({ status: 200, headers: { 'content-type': 'text/html' }, body });
  const site: Sender = async (req) => {
    const u = new URL(req.url);
    if (u.pathname === '/') return html('<a href="/go?next=x">g</a>');
    if (u.pathname === '/go') return { status: 302, headers: { location: u.searchParams.get('next') ?? '/' }, body: '' };
    return json(404, '{}');
  };
  const devApp = await buildApp({
    lab: new LabPolicy(false, [], { allowPrivateTargets: true }), sender: site,
    fingerprintSecret: 'smoke', devTrust: true,
  });
  const df = devApp.getHttpAdapter().getInstance();
  const devHealth = JSON.parse((await df.inject({ method: 'GET', url: '/health' })).payload);
  check('health reports dev-trust on', devHealth.devTrust === true);
  const quick = await df.inject({ method: 'POST', url: '/scans/quick', payload: { url: `https://${LAB}/`, actor: 'tester' } as any });
  const q = JSON.parse(quick.payload);
  check('quick scan from a URL runs and reports', quick.statusCode === 201 && (q.status === 'done') && q.confirmed >= 1, JSON.stringify(q));
  await devApp.close();
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
