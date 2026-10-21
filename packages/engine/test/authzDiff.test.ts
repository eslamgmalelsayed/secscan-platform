import { describe, it, expect } from 'vitest';
import {
  AuthorizationDiffer, AuthorizationGrant, GuardedClient, ScopeGuard,
  type Identity, type RecordedRequest, type RecordedResponse, type Sender,
} from '../src';

const NOW = new Date();
const PUBLIC = () => ['93.184.216.34'];
const HOST = 'app.example.com';

function grant() {
  return AuthorizationGrant.parse({
    grantId: 'g', targets: [{ host: HOST }], ownershipProof: 'dns_txt', ownershipToken: 't',
    chain: [{ party: 'Owner', email: 'o@o.sa', role: 'system_owner', signedAt: NOW.toISOString(), statement: 'authorized' }],
    notBefore: new Date(NOW.getTime() - 3.6e6).toISOString(),
    notAfter: new Date(NOW.getTime() + 3.6e6).toISOString(),
    status: 'active',
  });
}

const json = (status: number, body: string): RecordedResponse =>
  ({ status, headers: { 'content-type': 'application/json' }, body });

/** Orders #42 requires login; `checkOwner` is the control that *should* stop
 *  one user reading another's order. */
function ordersApp(checkOwner: boolean): Sender {
  return async (req: RecordedRequest, ident: Identity) => {
    const path = new URL(req.url).pathname;
    if (path.startsWith('/orders/')) {
      if (!ident.sessionRef) return json(403, '{"error":"login"}');
      if (checkOwner && ident.sessionRef !== 'sess-alice') return json(403, '{"error":"forbidden"}');
      return json(200, '{"order":42,"buyer":"alice"}');
    }
    if (path === '/public') return json(200, '{"public":true}'); // same for everyone
    if (path === '/account/ssn') return json(200, '{"ssn":"private"}'); // leaks to anyone
    return json(404, '{}');
  };
}

function differ(sender: Sender) {
  const client = new GuardedClient(new ScopeGuard([grant()], { resolveHost: PUBLIC }), sender);
  return new AuthorizationDiffer(client, 'fp-test', { replaysForConfirmation: 2 });
}

const OWNER: Identity = { role: 'customer', tenant: 't1', sessionRef: 'sess-alice' };
const BOB: Identity = { role: 'customer', tenant: 't1', sessionRef: 'sess-bob' };
const ANON: Identity = { role: 'anonymous', sessionRef: null };
const ORDER: RecordedRequest = { method: 'GET', url: `https://${HOST}/orders/42`, capturedAsRole: 'customer', capturedAsTenant: 't1' };

describe('AuthorizationDiffer', () => {
  it('finds a confirmed IDOR in a vulnerable app', async () => {
    const f = await differ(ordersApp(false)).testObjectAccess(ORDER, OWNER, BOB);
    expect(f).not.toBeNull();
    expect(f!.severity).toBe('high');
    expect(f!.confidence).toBe('confirmed');
    expect(f!.title.ar.length).toBeGreaterThan(0);
    expect(f!.controls.some((c) => c.framework.startsWith('NCA'))).toBe(true);
  });

  it('reports nothing when access control is enforced', async () => {
    const f = await differ(ordersApp(true)).testObjectAccess(ORDER, OWNER, BOB);
    expect(f).toBeNull();
  });

  it('does not flag a public resource', async () => {
    const pub: RecordedRequest = { method: 'GET', url: `https://${HOST}/public`, capturedAsRole: 'customer', capturedAsTenant: 't1' };
    const f = await differ(ordersApp(false)).testObjectAccess(pub, OWNER, BOB);
    expect(f).toBeNull();
  });

  it('flags missing authentication (critical) when the owner labeled the flow', async () => {
    const priv: RecordedRequest = {
      method: 'GET', url: `https://${HOST}/account/ssn`, requiresAuth: true,
      capturedAsRole: 'customer', capturedAsTenant: 't1',
    };
    const f = await differ(ordersApp(false)).testObjectAccess(priv, OWNER, ANON);
    expect(f).not.toBeNull();
    expect(f!.severity).toBe('critical');
    expect(f!.id).toContain('missing_auth');
  });

  it('refuses to send out of scope', async () => {
    const out: RecordedRequest = { method: 'GET', url: 'https://evil.example.org/x' };
    await expect(differ(ordersApp(false)).testObjectAccess(out, OWNER, BOB)).rejects.toThrow(/deny_no_grant/);
  });
});
