import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { AuthorizationGrant, GuardedClient, ScopeGuard, createHttpSender, SecretStore, type RecordedRequest } from '@secscan/engine';
import { graphqlIntrospection, csrfToken, rateLimitAbsence, massAssignment, type CheckContext } from '../src';

const NOW = new Date();
let srv: Server; let base: string;

beforeAll(async () => {
  srv = createServer((req, res) => {
    const u = new URL(req.url ?? '/', 'http://x');
    const p = u.pathname;
    const html = (b: string) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(b); };
    const json = (b: string) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(b); };

    if (p === '/graphql') {
      if ((u.searchParams.get('query') ?? '').includes('__schema')) return json('{"data":{"__schema":{"queryType":{"name":"Query"}}}}');
      return json('{"data":null}');
    }
    if (p === '/form' || p === '/safe-form') {
      const token = p === '/safe-form' ? '<input type="hidden" name="_csrf" value="abc">' : '';
      return html(`<form method="post" action="/do">${token}<input name="x"></form>`);
    }
    if (p === '/open') return json('{"ok":true}'); // never throttled
    if (p === '/create') { // echoes the posted body (mass assignment sink)
      let body = ''; req.on('data', (c) => (body += c)); req.on('end', () => json(body || '{}')); return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
  base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
});
afterAll(() => srv.close());

function grant(allowStateChanging = false) {
  return AuthorizationGrant.parse({
    grantId: 'g', targets: [{ host: '127.0.0.1', scheme: 'http' }], ownershipProof: 'http_token', ownershipToken: 't',
    chain: [{ party: 'Owner', email: 'o@o.sa', role: 'system_owner', signedAt: NOW.toISOString(), statement: 'ok' }],
    notBefore: new Date(NOW.getTime() - 3.6e6).toISOString(),
    notAfter: new Date(NOW.getTime() + 3.6e6).toISOString(), allowStateChanging, status: 'active',
  });
}
function ctxFor(flows: RecordedRequest[], allowStateChanging = false): CheckContext {
  const client = new GuardedClient(new ScopeGuard([grant(allowStateChanging)], { blockPrivateAddresses: false }), createHttpSender({ store: new SecretStore() }));
  return { client, grantFingerprint: 'fp', rootUrl: `${base}/`, flows };
}
const get = (path: string): RecordedRequest => ({ method: 'GET', url: `${base}${path}` });
const post = (path: string, body: object): RecordedRequest => ({ method: 'POST', url: `${base}${path}`, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

describe('logic + hardening family', () => {
  it('GraphQL introspection: flags an endpoint that answers __schema', async () => {
    const out = await graphqlIntrospection(ctxFor([get('/graphql')]));
    expect(out).toHaveLength(1);
    expect(out[0].confidence).toBe('confirmed');
  });

  it('CSRF: flags a POST form with no token, not one with a token', async () => {
    expect(await csrfToken(ctxFor([get('/form')]))).toHaveLength(1);
    expect(await csrfToken(ctxFor([get('/safe-form')]))).toHaveLength(0);
  });

  it('rate limit: flags an endpoint that never throttles a burst', async () => {
    const out = await rateLimitAbsence(ctxFor([get('/open')]));
    expect(out).toHaveLength(1);
    expect(out[0].confidence).toBe('needs_review');
  });

  it('mass assignment is CONFIRMED on a staging grant that allows writes', async () => {
    const out = await massAssignment(ctxFor([post('/create', { name: 'x' })], true));
    expect(out).toHaveLength(1);
    expect(out[0].confidence).toBe('confirmed');
  });

  it('mass assignment is GATED off when the grant forbids state-changing writes', async () => {
    // the scope guard refuses the write, so the check cannot run — no finding, no write sent
    const out = await massAssignment(ctxFor([post('/create', { name: 'x' })], false));
    expect(out).toHaveLength(0);
  });
});
