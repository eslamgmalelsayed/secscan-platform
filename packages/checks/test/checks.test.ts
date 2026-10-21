import { describe, it, expect } from 'vitest';
import { createHmac } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { AddressInfo } from 'node:net';
import {
  AuthorizationGrant, GuardedClient, ScopeGuard, createHttpSender, type RecordedRequest,
} from '@secscan/engine';
import { runChecks, analyzeJwt, type CheckContext } from '../src';

const NOW = new Date();

function server(): Promise<{ srv: Server; base: string }> {
  const srv = createServer((req, res) => {
    const u = new URL(req.url ?? '/', 'http://x');
    const p = u.pathname;
    if (p === '/') {
      res.setHeader('Server', 'nginx/1.18.0');
      res.setHeader('Set-Cookie', 'sid=abc'); // no flags
      res.writeHead(200, { 'content-type': 'text/html' });
      return res.end('<html>key AKIAABCDEFGHIJKLMNOP home</html>'); // no sec headers; secret
    }
    if (p === '/search') {
      res.writeHead(200, { 'content-type': 'text/html' });
      return res.end(`<html>results for ${u.searchParams.get('q') ?? ''}</html>`);
    }
    if (p === '/item') {
      const id = u.searchParams.get('id') ?? '1';
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(id.endsWith("'1'='2") ? '{"items":[]}' : '{"items":[{"id":1}]}');
    }
    if (p === '/go') {
      res.writeHead(302, { location: u.searchParams.get('next') ?? '/' });
      return res.end();
    }
    if (p === '/api') {
      const origin = req.headers['origin'] as string | undefined;
      if (origin) { res.setHeader('access-control-allow-origin', origin); res.setHeader('access-control-allow-credentials', 'true'); }
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end('{"user":"alice"}');
    }
    res.writeHead(404); res.end();
  });
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => {
    const port = (srv.address() as AddressInfo).port;
    resolve({ srv, base: `http://127.0.0.1:${port}` });
  }));
}

function grant(host = '127.0.0.1') {
  return AuthorizationGrant.parse({
    grantId: 'g', targets: [{ host, scheme: 'http' }], ownershipProof: 'http_token', ownershipToken: 't',
    chain: [{ party: 'Owner', email: 'o@o.sa', role: 'system_owner', signedAt: NOW.toISOString(), statement: 'ok' }],
    notBefore: new Date(NOW.getTime() - 3.6e6).toISOString(),
    notAfter: new Date(NOW.getTime() + 3.6e6).toISOString(), status: 'active',
  });
}

function weakJwt(): string {
  const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const p = Buffer.from(JSON.stringify({ sub: '1', exp: 9999999999 })).toString('base64url');
  const sig = createHmac('sha256', 'secret').update(`${h}.${p}`).digest('base64url');
  return `${h}.${p}.${sig}`;
}
function noneJwt(): string {
  const h = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const p = Buffer.from(JSON.stringify({ sub: '1', exp: 9999999999 })).toString('base64url');
  return `${h}.${p}.`;
}

async function ctxFor(base: string): Promise<CheckContext> {
  const guard = new ScopeGuard([grant()], { blockPrivateAddresses: false });
  const client = new GuardedClient(guard, createHttpSender());
  const flows: RecordedRequest[] = [
    { method: 'GET', url: `${base}/search?q=hello` },
    { method: 'GET', url: `${base}/item?id=1` },
    { method: 'GET', url: `${base}/go?next=/dash` },
    { method: 'GET', url: `${base}/api` },
  ];
  return { client, grantFingerprint: 'fp', rootUrl: `${base}/`, flows, tokens: [noneJwt(), weakJwt()] };
}

describe('checks suite (live local server)', () => {
  it('detects passive + config + active + jwt classes', async () => {
    const { srv, base } = await server();
    try {
      const r = await runChecks(await ctxFor(base));
      const cats = new Set([...r.reportReady, ...r.needsReview].map((f) => categoryOf(f.id)));
      for (const c of ['security_header', 'insecure_cookie', 'tls', 'info_disclosure', 'secret_exposure', 'cors', 'open_redirect', 'injection', 'xss', 'jwt']) {
        expect(cats.has(c), `expected ${c} (got ${[...cats].join(',')})`).toBe(true);
      }
      // boolean SQLi is confirmed -> report-ready
      expect(r.reportReady.some((f) => f.title.en.includes('Boolean-based SQL injection'))).toBe(true);
      // reflected XSS is needs_review, never auto-reported
      expect(r.needsReview.some((f) => f.title.en.includes('reflected unescaped'))).toBe(true);
      expect(r.reportReady.some((f) => f.title.en.includes('reflected unescaped'))).toBe(false);
      // every finding carries a CVSS score and multi-framework controls
      for (const f of [...r.reportReady, ...r.needsReview]) {
        expect(f.cvss?.score).toBeTypeOf('number');
        expect(f.controls.some((c) => c.framework.includes('ASVS'))).toBe(true);
      }
    } finally {
      srv.close();
    }
  });
});

describe('analyzeJwt', () => {
  it('flags alg=none as critical and weak secret as high', () => {
    const none = analyzeJwt(noneJwt(), 'fp');
    expect(none.some((f) => f.severity === 'critical' && f.title.en.includes('alg=none'))).toBe(true);
    const weak = analyzeJwt(weakJwt(), 'fp');
    expect(weak.some((f) => f.severity === 'high' && f.title.en.includes('Weak JWT signing secret'))).toBe(true);
  });
});

function categoryOf(id: string): string {
  // id shape: CHK-<category>-<hash>  (category may contain underscores)
  return id.replace(/^CHK-/, '').replace(/-[0-9a-f]{8}$/, '');
}
