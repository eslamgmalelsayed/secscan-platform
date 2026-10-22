import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { AuthorizationGrant, GuardedClient, ScopeGuard, createHttpSender, SecretStore, type RecordedRequest } from '@secscan/engine';
import { ssti, pathTraversal, nosqlDifferential, hostHeaderInjection, type CheckContext } from '../src';

const NOW = new Date();
let srv: Server; let base: string;

beforeAll(async () => {
  srv = createServer((req, res) => {
    const u = new URL(req.url ?? '/', 'http://x');
    const p = u.pathname;
    const html = (b: string) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(b); };
    const json = (b: string) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(b); };

    // SSTI: evaluates {{a*b}}. Safe variant echoes raw.
    if (p === '/render' || p === '/safe-render') {
      const v = u.searchParams.get('name') ?? '';
      if (p === '/render') { const m = v.match(/\{\{(\d+)\*(\d+)\}\}/); return html(`<p>${m ? v.replace(m[0], String(Number(m[1]) * Number(m[2]))) : v}</p>`); }
      return html(`<p>${v}</p>`); // reflects the literal expression, never evaluates
    }
    // Path traversal: returns passwd content when the path escapes. Safe = never.
    if (p === '/file' || p === '/safe-file') {
      const path = u.searchParams.get('path') ?? '';
      if (p === '/file' && path.includes('etc/passwd')) return res.end('root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:');
      res.writeHead(404); return res.end('not found');
    }
    // NoSQL: role[$ne] matches all; role[$eq]=admin and role=admin match the baseline.
    if (p === '/users' || p === '/safe-users') {
      const all = '{"users":[{"u":"admin"},{"u":"bob"},{"u":"carol"}]}';
      const adminOnly = '{"users":[{"u":"admin"}]}';
      if (p === '/users') {
        if (u.searchParams.has('role[$ne]')) return json(all);
        if (u.searchParams.has('role[$eq]')) return json(u.searchParams.get('role[$eq]') === 'admin' ? adminOnly : all);
      }
      return json(u.searchParams.get('role') === 'admin' ? adminOnly : all);
    }
    // Host-header: reflects X-Forwarded-Host into an absolute link. Safe = fixed host.
    if (p === '/profile' || p === '/safe-profile') {
      const host = p === '/profile' ? (req.headers['x-forwarded-host'] ?? req.headers.host) : 'app.example.com';
      return html(`<a href="https://${host}/reset">reset your password</a>`);
    }
    res.writeHead(404); res.end();
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
  base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
});
afterAll(() => srv.close());

function grant() {
  return AuthorizationGrant.parse({
    grantId: 'g', targets: [{ host: '127.0.0.1', scheme: 'http' }], ownershipProof: 'http_token', ownershipToken: 't',
    chain: [{ party: 'Owner', email: 'o@o.sa', role: 'system_owner', signedAt: NOW.toISOString(), statement: 'ok' }],
    notBefore: new Date(NOW.getTime() - 3.6e6).toISOString(),
    notAfter: new Date(NOW.getTime() + 3.6e6).toISOString(), status: 'active',
  });
}
function ctxFor(flows: RecordedRequest[]): CheckContext {
  const client = new GuardedClient(new ScopeGuard([grant()], { blockPrivateAddresses: false }), createHttpSender({ store: new SecretStore() }));
  return { client, grantFingerprint: 'fp', rootUrl: `${base}/`, flows };
}
const flow = (path: string): RecordedRequest => ({ method: 'GET', url: `${base}${path}` });

describe('injection family — detection, non-destructive', () => {
  it('SSTI: flags an evaluated template expression, not a mere reflection', async () => {
    const vuln = await ssti(ctxFor([flow('/render?name=x')]));
    expect(vuln).toHaveLength(1);
    expect(vuln[0].confidence).toBe('confirmed');
    expect(vuln[0].title.en).toContain('template injection');
    const safe = await ssti(ctxFor([flow('/safe-render?name=x')]));
    expect(safe).toHaveLength(0);
  });

  it('path traversal: flags a returned system-file signature, not a 404', async () => {
    const vuln = await pathTraversal(ctxFor([flow('/file?path=a.txt')]));
    expect(vuln).toHaveLength(1);
    expect(vuln[0].confidence).toBe('confirmed');
    const safe = await pathTraversal(ctxFor([flow('/safe-file?path=a.txt')]));
    expect(safe).toHaveLength(0);
  });

  it('NoSQL: flags a reproduced operator differential, not a plain filter', async () => {
    const vuln = await nosqlDifferential(ctxFor([flow('/users?role=admin')]));
    expect(vuln).toHaveLength(1);
    expect(vuln[0].confidence).toBe('confirmed');
    const safe = await nosqlDifferential(ctxFor([flow('/safe-users?role=admin')]));
    expect(safe).toHaveLength(0);
  });

  it('host-header: flags a reflected poisoned host, not a fixed one', async () => {
    const vuln = await hostHeaderInjection(ctxFor([flow('/profile')]));
    expect(vuln).toHaveLength(1);
    expect(vuln[0].confidence).toBe('likely');
    const safe = await hostHeaderInjection(ctxFor([flow('/safe-profile')]));
    expect(safe).toHaveLength(0);
  });
});
