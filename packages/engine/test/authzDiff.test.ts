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
// The owner captured their OWN order #42 and labelled it owner-of-object.
const ORDER: RecordedRequest = { method: 'GET', url: `https://${HOST}/orders/42`, ownsObject: true, capturedAsRole: 'customer', capturedAsTenant: 't1' };

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

/** A SECURE app: every session gets only its own profile. `distinctIds`
 *  controls whether the two test accounts differ in id/created_at at all. */
function profileApp(distinctIds: boolean): Sender {
  return async (req: RecordedRequest, ident: Identity) => {
    const path = new URL(req.url).pathname;
    if (!ident.sessionRef) return json(401, '{"error":"login"}');
    if (path === '/api/me') {
      const alice = { id: '6f1c2a3e-1111-4c5d-8e9f-aaaaaaaaaaaa', name: 'Customer', plan: 'free', created_at: '2026-01-01T00:00:00Z' };
      const bob = distinctIds
        ? { id: '7a2d3b4f-2222-4c5d-8e9f-bbbbbbbbbbbb', name: 'Customer', plan: 'free', created_at: '2026-03-05T10:00:00Z' }
        : alice; // two test accounts seeded identically
      return json(200, JSON.stringify(ident.sessionRef === 'sess-alice' ? alice : bob));
    }
    if (path === '/orders') {
      // vulnerable: ?id= is trusted without an ownership check
      const id = new URL(req.url).searchParams.get('id');
      return json(200, `{"order":${id},"buyer":"alice","request_id":"${ident.sessionRef}-${Math.random()}"}`);
    }
    return json(404, '{}');
  };
}

describe('AuthorizationDiffer — false-positive guards (review 2.1)', () => {
  const ME: RecordedRequest = { method: 'GET', url: `https://${HOST}/api/me`, capturedAsRole: 'customer', capturedAsTenant: 't1' };

  it('does not report a secure per-session endpoint whose bodies differ only in id/timestamps', async () => {
    const f = await differ(profileApp(true)).testObjectAccess(ME, OWNER, BOB);
    expect(f).toBeNull();
  });

  it('does not report a per-session endpoint with no object identifier in the request, even if bodies are identical', async () => {
    const f = await differ(profileApp(false)).testObjectAccess(ME, OWNER, BOB);
    expect(f).toBeNull();
  });

  it('still reports IDOR when the identifier is a query parameter and volatile fields differ', async () => {
    const byId: RecordedRequest = { method: 'GET', url: `https://${HOST}/orders?id=42`, ownsObject: true, capturedAsRole: 'customer', capturedAsTenant: 't1' };
    const f = await differ(profileApp(true)).testObjectAccess(byId, OWNER, BOB);
    expect(f).not.toBeNull();
    expect(f!.id).toContain('bola_idor');
  });
});

describe('AuthorizationDiffer — a shared resource named by an object id (product-page FP)', () => {
  // /api/products/42 NAMES an object but is a catalog item every logged-in user
  // may see. Response comparison cannot tell it from a private object, so
  // without an owner-of-object label it must NOT be auto-confirmed.
  const catalog: Sender = async (req, ident) => {
    if (!ident.sessionRef) return json(401, '{"e":"login"}');
    if (new URL(req.url).pathname === '/api/products/42') return json(200, '{"product":42,"name":"Widget","price":9}');
    return json(404, '{}');
  };
  const PRODUCT = (ownsObject?: boolean): RecordedRequest =>
    ({ method: 'GET', url: `https://${HOST}/api/products/42`, ownsObject, capturedAsRole: 'customer', capturedAsTenant: 't1' });

  it('does not confirm it; routes it to review as `likely` with a reason', async () => {
    const f = await differ(catalog).testObjectAccess(PRODUCT(), OWNER, BOB);
    expect(f).not.toBeNull();
    expect(f!.id).toContain('bola_idor');
    expect(f!.confidence).toBe('likely'); // review queue, NOT the report
    const note = f!.evidence.find((e) => e.label === 'review');
    expect(note).toBeDefined();
    expect(note!.content).toContain('owner-of-object');
  });

  it('confirms the same request once the owner labels it owner-of-object', async () => {
    const f = await differ(catalog).testObjectAccess(PRODUCT(true), OWNER, BOB);
    expect(f!.confidence).toBe('confirmed');
  });
});

describe('AuthorizationDiffer — function-level authorization (BFLA)', () => {
  // /admin/settings has no object identifier; a customer receiving the admin
  // body is broken function-level authorization OR identically seeded accounts.
  const app: Sender = async (req, ident) => {
    if (!ident.sessionRef) return json(401, '{}');
    if (new URL(req.url).pathname === '/admin/settings') return json(200, '{"maintenance":false}');
    return json(404, '{}');
  };
  const ADMIN: Identity = { role: 'admin', tenant: 't1', sessionRef: 'sess-admin' };
  const SETTINGS = (privilegedFunction?: boolean): RecordedRequest =>
    ({ method: 'GET', url: `https://${HOST}/admin/settings`, privilegedFunction, capturedAsRole: 'admin', capturedAsTenant: 't1' });

  it('yields a `likely` function-level candidate for review when the flow is not labelled', async () => {
    const f = await differ(app).testObjectAccess(SETTINGS(), ADMIN, BOB);
    expect(f).not.toBeNull();
    expect(f!.id).toContain('function_level');
    expect(f!.confidence).toBe('likely');
    expect(f!.evidence.some((e) => e.label === 'review')).toBe(true);
  });

  it('confirms a BFLA once the owner labels the endpoint a privileged function', async () => {
    const f = await differ(app).testObjectAccess(SETTINGS(true), ADMIN, BOB);
    expect(f!.id).toContain('function_level');
    expect(f!.confidence).toBe('confirmed');
    expect(f!.severity).toBe('high');
    expect(f!.controls.some((c) => c.framework === 'OWASP' && c.control === 'API5:2023')).toBe(true);
  });
});
