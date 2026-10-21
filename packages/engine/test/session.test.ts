import { describe, it, expect } from 'vitest';
import {
  AuthorizationGrant, GuardedClient, ScopeGuard, SessionRegistry,
  type Identity, type RecordedRequest, type Sender,
} from '../src';

const NOW = new Date();
const HOST = 'app.example.com';
function grant() {
  return AuthorizationGrant.parse({
    grantId: 'g', targets: [{ host: HOST }], ownershipProof: 'dns_txt', ownershipToken: 't',
    chain: [{ party: 'O', email: 'o@o.sa', role: 'system_owner', signedAt: NOW.toISOString(), statement: 'ok' }],
    notBefore: new Date(NOW.getTime() - 3.6e6).toISOString(),
    notAfter: new Date(NOW.getTime() + 3.6e6).toISOString(), status: 'active',
  });
}

// alice's session is live, bob's is expired.
const sender: Sender = async (_req, ident: Identity) =>
  ident.sessionRef === 'sess-alice'
    ? { status: 200, headers: {}, body: '{"me":"alice"}' }
    : { status: 401, headers: {}, body: '' };

const liveness: RecordedRequest = { method: 'GET', url: `https://${HOST}/me` };

describe('SessionRegistry', () => {
  it('marks dead sessions invalid and excludes them', async () => {
    const reg = new SessionRegistry();
    reg.register({ role: 'customer', tenant: 't1', sessionRef: 'sess-alice' }, liveness);
    reg.register({ role: 'admin', tenant: 't1', sessionRef: 'sess-bob' }, liveness);
    const client = new GuardedClient(new ScopeGuard([grant()], { resolveHost: () => ['93.184.216.34'] }), sender);

    const failed = await reg.verifyAll(client);
    expect(failed.map((i) => i.role)).toEqual(['admin']);
    expect(reg.identities().map((i) => i.role)).toEqual(['customer']);
    expect(reg.byRole('customer', 't1')?.sessionRef).toBe('sess-alice');
  });
});
