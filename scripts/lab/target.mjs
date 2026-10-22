#!/usr/bin/env node
/**
 * SecScan demo lab — a DELIBERATELY VULNERABLE app to try the full suite against.
 * For local testing only. Every weakness here is intentional; never deploy this.
 *
 * Users (by cookie `sid`):  alice (customer/t1), bob (customer/t1),
 *                           carol (customer/t2), admin (admin/t1)
 */
import { createServer } from 'node:http';

const PORT = Number(process.env.LAB_PORT ?? 7799);
const users = {
  alice: { id: 1, tenant: 't1', role: 'customer' },
  bob: { id: 2, tenant: 't1', role: 'customer' },
  carol: { id: 3, tenant: 't2', role: 'customer' },
  admin: { id: 9, tenant: 't1', role: 'admin' },
};
const orders = { 101: { id: 101, ownerId: 1, tenant: 't1', total: 50 }, 102: { id: 102, ownerId: 2, tenant: 't1', total: 70 }, 201: { id: 201, ownerId: 3, tenant: 't2', total: 90 } };

const server = createServer((req, res) => {
  const u = new URL(req.url ?? '/', 'http://x');
  const p = u.pathname;
  const sid = (req.headers.cookie ?? '').split(';').map((s) => s.trim()).find((c) => c.startsWith('sid='))?.slice(4);
  const me = sid ? users[sid] : undefined;
  const html = (b) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(b); }; // NB: no security headers (intentional)
  const json = (s, b) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(b)); };

  // crawlable home so discovery finds the surface
  if (p === '/') return html(`<!doctype html><h1>Demo Shop</h1>
    <a href="/api/me">me</a> <a href="/api/orders/101">order 101</a> <a href="/api/products/42">product 42</a>
    <a href="/api/admin/export">admin export</a> <a href="/search?q=hi">search</a> <a href="/render?name=hi">render</a>
    <a href="/go?next=/dash">go</a> <a href="/graphql?query={__schema{queryType{name}}}">graphql</a>
    <form method="post" action="/profile"><input name="bio"><button>save</button></form>`); // CSRF: no token

  if (p === '/login') { const who = u.searchParams.get('as') ?? 'alice'; res.writeHead(200, { 'content-type': 'text/html', 'set-cookie': `sid=${who}` }); return res.end('ok'); } // weak session value

  if (p === '/api/me') return me ? json(200, { id: me.id, tenant: me.tenant, role: me.role, created_at: '2026-01-01' }) : json(401, { e: 'login' });

  // VULN: BOLA + cross-tenant — any logged-in user reads any order
  if (p.startsWith('/api/orders/')) { if (!me) return json(401, { e: 'login' }); const o = orders[u.pathname.split('/')[3]]; return o ? json(200, o) : json(404, {}); }

  // SHARED: a product every logged-in user may see (must land in REVIEW, not confirmed)
  if (p === '/api/products/42') return me ? json(200, { id: 42, name: 'Widget', price: 9 }) : json(401, { e: 'login' });

  // VULN: BFLA — admin-only export served to any role
  if (p === '/api/admin/export') return me ? json(200, { rows: 3, secret: 'quarterly' }) : json(401, { e: 'login' });

  // VULN: reflected input (XSS candidate)
  if (p === '/search') return html(`<p>results for ${u.searchParams.get('q') ?? ''}</p>`);
  // VULN: SSTI — evaluates {{a*b}}
  if (p === '/render') { const v = u.searchParams.get('name') ?? ''; const m = v.match(/\{\{(\d+)\*(\d+)\}\}/); return html(`<p>${m ? v.replace(m[0], String(+m[1] * +m[2])) : v}</p>`); }
  // VULN: open redirect
  if (p === '/go') { res.writeHead(302, { location: u.searchParams.get('next') ?? '/' }); return res.end(); }
  // VULN: GraphQL introspection enabled
  if (p === '/graphql') return (u.searchParams.get('query') ?? '').includes('__schema') ? json(200, { data: { __schema: { queryType: { name: 'Query' } } } }) : json(200, { data: null });
  // VULN: CORS reflects origin with credentials
  if (p === '/api/profile') { const o = req.headers.origin; if (o) { res.setHeader('access-control-allow-origin', o); res.setHeader('access-control-allow-credentials', 'true'); } return me ? json(200, { id: me.id }) : json(401, {}); }

  res.writeHead(404); res.end();
});
server.listen(PORT, '127.0.0.1', () => console.log(`[lab] vulnerable demo app on http://127.0.0.1:${PORT}`));
