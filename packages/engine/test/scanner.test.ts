import { describe, it, expect } from 'vitest';
import {
  AuthorizationGrant, GuardedClient, ScopeGuard, runAccessControlScan,
  type Identity, type RecordedRequest, type RecordedResponse, type Sender,
} from '../src';

const NOW = new Date();
const PUBLIC = () => ['93.184.216.34'];
const HOST = 'app.example.com';

function grant() {
  return AuthorizationGrant.parse({
    grantId: 'g', targets: [{ host: HOST }], ownershipProof: 'dns_txt', ownershipToken: 't',
    chain: [{ party: 'Owner', email: 'o@o.sa', role: 'system_owner', signedAt: NOW.toISOString(), statement: 'ok' }],
    notBefore: new Date(NOW.getTime() - 3.6e6).toISOString(),
    notAfter: new Date(NOW.getTime() + 3.6e6).toISOString(),
    status: 'active',
  });
}
const json = (status: number, body: string): RecordedResponse => ({ status, headers: { 'content-type': 'application/json' }, body });

const app: Sender = async (req: RecordedRequest, ident: Identity) => {
  const path = new URL(req.url).pathname;
  if (path.startsWith('/orders/')) {
    if (!ident.sessionRef) return json(403, '{"e":"login"}');
    return json(200, '{"order":42,"buyer":"alice"}'); // vulnerable: any session
  }
  if (path === '/public') return json(200, '{"public":true}');
  if (path === '/account/ssn') return json(200, '{"ssn":"private"}'); // leaks to anyone
  return json(404, '{}');
};

const alice: Identity = { role: 'customer', tenant: 't1', sessionRef: 'sess-alice' };
const bob: Identity = { role: 'customer', tenant: 't1', sessionRef: 'sess-bob' };

// capturedAsRole must match an identity's role to pick the owner
const flows: RecordedRequest[] = [
  { method: 'GET', url: `https://${HOST}/orders/42`, capturedAsRole: 'customer', capturedAsTenant: 't1' },
  { method: 'GET', url: `https://${HOST}/public`, capturedAsRole: 'customer', capturedAsTenant: 't1' },
  { method: 'GET', url: `https://${HOST}/account/ssn`, requiresAuth: true, capturedAsRole: 'customer', capturedAsTenant: 't1' },
];

describe('runAccessControlScan', () => {
  it('reports BOLA + missing-auth, suppresses the public resource', async () => {
    const client = new GuardedClient(new ScopeGuard([grant()], { resolveHost: PUBLIC }), app);
    // two identities with the same role -> scanner picks the first as owner;
    // make roles distinct so bob is a genuine challenger.
    const result = await runAccessControlScan({
      client, grantFingerprint: 'fp',
      flows, identities: [alice, { ...bob, role: 'customer', tenant: 't1' }],
    });
    const types = result.reportReady.map((f) => f.id);
    expect(types.some((id) => id.includes('bola_idor'))).toBe(true);
    expect(types.some((id) => id.includes('missing_auth'))).toBe(true);
    expect(result.reportReady.every((f) => f.confidence === 'confirmed')).toBe(true);
    // public resource never becomes a finding
    expect(result.reportReady.concat(result.needsReview).some((f) => f.location?.includes('/public'))).toBe(false);
    const s = result.summary();
    expect(s.reportReady).toBeGreaterThanOrEqual(2);
    expect(s.bySeverity.critical).toBeGreaterThanOrEqual(1);
  });
});

describe('runAccessControlScan — coverage gaps are reported, not silent (review 2.6)', () => {
  const client = () => new GuardedClient(new ScopeGuard([grant()], { resolveHost: PUBLIC }), app);

  it('a HAR-style flow with no tenant falls back to the first identity of that role and still finds the IDOR', async () => {
    const r = await runAccessControlScan({
      client: client(), grantFingerprint: 'fp',
      flows: [{ method: 'GET', url: `https://${HOST}/orders/42`, capturedAsRole: 'customer', capturedAsTenant: null }],
      identities: [alice, bob],
    });
    expect(r.reportReady.some((f) => f.id.includes('bola_idor'))).toBe(true);
  });

  it('a flow whose role has no identity is listed in notTested', async () => {
    const r = await runAccessControlScan({
      client: client(), grantFingerprint: 'fp',
      flows: [{ method: 'GET', url: `https://${HOST}/orders/42`, capturedAsRole: 'manager', capturedAsTenant: 't1' }],
      identities: [alice, bob],
    });
    expect(r.reportReady).toHaveLength(0);
    expect(r.notTested.some((n) => n.includes("no identity supplied for role 'manager/t1'"))).toBe(true);
  });

  it('scope refusals go to notTested only, not errors', async () => {
    const r = await runAccessControlScan({
      client: client(), grantFingerprint: 'fp',
      flows: [{ method: 'GET', url: 'https://other.example.org/x', capturedAsRole: 'customer', capturedAsTenant: 't1' }],
      identities: [alice, bob],
    });
    expect(r.errors).toHaveLength(0);
    expect(r.notTested.some((n) => n.startsWith('deny_no_grant'))).toBe(true);
  });
});
