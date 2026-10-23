import { describe, it, expect } from 'vitest';
import {
  AuthorizationGrant, GuardedClient, ScopeGuard, discoverFlows,
  type Identity, type RecordedRequest, type RecordedResponse, type Sender,
} from '../src';

const NOW = new Date();
const HOST = 'app.example.com';
const PUBLIC = () => ['93.184.216.34'];

function grant() {
  return AuthorizationGrant.parse({
    grantId: 'g', targets: [{ host: HOST }], ownershipProof: 'dns_txt', ownershipToken: 't',
    chain: [{ party: 'Owner', email: 'o@o.sa', role: 'system_owner', signedAt: NOW.toISOString(), statement: 'ok' }],
    notBefore: new Date(NOW.getTime() - 3.6e6).toISOString(),
    notAfter: new Date(NOW.getTime() + 3.6e6).toISOString(),
    status: 'active',
  });
}
const html = (body: string): RecordedResponse => ({ status: 200, headers: { 'content-type': 'text/html' }, body });
const json = (body: string): RecordedResponse => ({ status: 200, headers: { 'content-type': 'application/json' }, body });

/** A tiny site: home links to /about, /products (which links to an off-site
 *  page and back home), and an API endpoint. */
const site: Sender = async (req: RecordedRequest) => {
  const p = new URL(req.url).pathname;
  if (p === '/') return html('<a href="/about">about</a> <a href="/products">products</a> <a href="https://evil.example.org/x">ad</a>');
  if (p === '/about') return html('<a href="/">home</a> <a href="mailto:x@y.z">mail</a>');
  if (p === '/products') return html('<a href="/api/products/42">item</a> <a href="/">home</a>');
  if (p === '/api/products/42') return json('{"id":42}');
  return html('<p>404</p>');
};

function client(sender: Sender = site) {
  return new GuardedClient(new ScopeGuard([grant()], { resolveHost: PUBLIC }), sender);
}

describe('discoverFlows', () => {
  it('crawls same-origin pages from a root URL and returns GET flows', async () => {
    const flows = await discoverFlows(client(), `https://${HOST}/`);
    const paths = flows.map((f) => new URL(f.url).pathname).sort();
    expect(paths).toEqual(['/', '/about', '/api/products/42', '/products']);
    expect(flows.every((f) => f.method === 'GET')).toBe(true);
  });

  it('never leaves the origin (ignores off-site, mailto, tel)', async () => {
    const flows = await discoverFlows(client(), `https://${HOST}/`);
    expect(flows.some((f) => f.url.includes('evil.example.org'))).toBe(false);
    expect(flows.some((f) => f.url.startsWith('mailto'))).toBe(false);
  });

  it('respects the page budget', async () => {
    const flows = await discoverFlows(client(), `https://${HOST}/`, { maxPages: 2 });
    expect(flows.length).toBeLessThanOrEqual(2);
  });

  it('stays within scope — an out-of-scope root yields nothing, no throw', async () => {
    const flows = await discoverFlows(client(), 'https://evil.example.org/');
    expect(flows).toEqual([]);
  });

  it('stamps attribution when crawling as a role, but never sets ownsObject', async () => {
    const asCustomer: Identity = { role: 'customer', tenant: 't1', sessionRef: 'sess' };
    const flows = await discoverFlows(client(), `https://${HOST}/`, { identity: asCustomer, capturedAsRole: 'customer', capturedAsTenant: 't1' });
    expect(flows[0].capturedAsRole).toBe('customer');
    expect(flows.every((f) => f.ownsObject === undefined)).toBe(true);
  });

  it('mines endpoints from a JS bundle (SPA) that no anchor links to', async () => {
    // a SPA: the home page only loads /app.js, which references the API by string.
    const spa: Sender = async (req: RecordedRequest) => {
      const p = new URL(req.url).pathname;
      if (p === '/') return html('<div id="app"></div><script src="/app.js"></script>');
      if (p === '/app.js') return { status: 200, headers: { 'content-type': 'text/javascript' }, body: 'const u="/api/users/5"; fetch("/api/orders"); axios.get(`/api/profile`);' };
      if (p.startsWith('/api/')) return json('{"ok":true}');
      return { status: 404, headers: { 'content-type': 'text/html' }, body: 'nope' };
    };
    const flows = await discoverFlows(client(spa), `https://${HOST}/`);
    const paths = flows.map((f) => new URL(f.url).pathname);
    expect(paths).toContain('/api/users/5');   // found only inside the JS bundle
    expect(paths).toContain('/api/orders');
    expect(paths).toContain('/api/profile');
    expect(paths).not.toContain('/app.js');     // static asset isn't a scan target
  });

  it('seeds endpoints from an OpenAPI document', async () => {
    const api: Sender = async (req: RecordedRequest) => {
      const p = new URL(req.url).pathname;
      if (p === '/openapi.json') return json(JSON.stringify({ paths: { '/api/widgets': {}, '/api/widgets/1': {} } }));
      if (p === '/') return html('<p>home</p>');
      if (p.startsWith('/api/')) return json('{"ok":true}');
      return { status: 404, headers: { 'content-type': 'text/html' }, body: 'nope' };
    };
    const flows = await discoverFlows(client(api), `https://${HOST}/`);
    const paths = flows.map((f) => new URL(f.url).pathname);
    expect(paths).toContain('/api/widgets');
    expect(paths).toContain('/api/widgets/1');
  });

  it('does not return error (4xx) pages as flows', async () => {
    const withErrors: Sender = async (req: RecordedRequest) => {
      const p = new URL(req.url).pathname;
      if (p === '/') return html('<a href="/missing">x</a> <a href="/ok">y</a>');
      if (p === '/ok') return html('ok');
      return { status: 404, headers: { 'content-type': 'text/html' }, body: 'nope' };
    };
    const flows = await discoverFlows(client(withErrors), `https://${HOST}/`);
    expect(flows.some((f) => new URL(f.url).pathname === '/missing')).toBe(false);
    expect(flows.some((f) => new URL(f.url).pathname === '/ok')).toBe(true);
  });
});
