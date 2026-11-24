import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { AuthorizationGrant, GuardedClient, ScopeGuard, createHttpSender, type RecordedRequest } from '@secscan/engine';
import {
  analyzeWorkflows, danglingCname, isPublicName, emailSpoofing, judgeTls, orgDomain, reflectionServices, runChecks,
  websocketOrigin, type CheckContext, type DnsResolver,
} from '../src';

const NOW = new Date();
function grant(host: string) {
  return AuthorizationGrant.parse({
    grantId: 'g', targets: [{ host, scheme: 'http' }], ownershipProof: 'http_token', ownershipToken: 't',
    chain: [{ party: 'Owner', email: 'o@o.sa', role: 'system_owner', signedAt: NOW.toISOString(), statement: 'ok' }],
    notBefore: new Date(NOW.getTime() - 3.6e6).toISOString(),
    notAfter: new Date(NOW.getTime() + 3.6e6).toISOString(), status: 'active',
  });
}
function listen(handler: Parameters<typeof createServer>[0]): Promise<{ srv: Server; base: string }> {
  const srv = createServer(handler);
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => {
    resolve({ srv, base: `http://127.0.0.1:${(srv.address() as AddressInfo).port}` });
  }));
}
function ctxFor(base: string, flows: RecordedRequest[] = [], host = '127.0.0.1'): CheckContext {
  const guard = new ScopeGuard([grant(host)], { blockPrivateAddresses: false });
  return { client: new GuardedClient(guard, createHttpSender()), grantFingerprint: 'fp', rootUrl: `${base}/`, flows };
}
const titles = (r: Awaited<ReturnType<typeof runChecks>>) => [...r.reportReady, ...r.needsReview].map((f) => f.title.en);

/** A deliberately leaky app: every new check has one positive here. */
function leaky(): Parameters<typeof createServer>[0] {
  return (req, res) => {
    const u = new URL(req.url ?? '/', 'http://x');
    const json = (status: number, body: unknown) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
    switch (u.pathname) {
      case '/':
        res.writeHead(200, { 'content-type': 'text/html' });
        return res.end('<html><script src="/app.js"></script></html>');
      case '/app.js':
        res.writeHead(200, { 'content-type': 'application/javascript' });
        return res.end('console.log(1)\n//# sourceMappingURL=app.js.map');
      case '/app.js.map': return json(200, { version: 3, sources: ['src/main.ts'], sourcesContent: ['const secret = 1'], mappings: '' });
      case '/.git/HEAD': res.writeHead(200); return res.end('ref: refs/heads/main\n');
      case '/.env': res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('DB_PASSWORD=hunter2\nAPP_KEY=base64:abc\n');
      case '/actuator': return json(200, { _links: { self: {}, health: {}, env: {} } });
      case '/openapi.json': return json(200, { openapi: '3.0.0', paths: { '/a': {} } });
      case '/api/v2/items': return req.headers.cookie ? json(200, { items: [] }) : json(401, { error: 'login' });
      case '/api/v1/items': return json(200, { items: [{ id: 1 }] });
      case '/search':
        if ([...u.searchParams.keys()].some((k) => k.endsWith('[]'))) {
          res.writeHead(500, { 'content-type': 'text/plain' });
          return res.end('Traceback (most recent call last):\n  File "app.py"');
        }
        return json(200, { results: [] });
      default:
        res.writeHead(404, { 'content-type': 'text/html' });
        return res.end("<p>You're seeing this error because you have <code>DEBUG = True</code> in your settings</p>");
    }
  };
}

describe('exposure checks (live local server)', () => {
  it('reports files, source maps, consoles, debug pages, old API versions and malformed input', async () => {
    const { srv, base } = await listen(leaky());
    try {
      const flows: RecordedRequest[] = [
        { method: 'GET', url: `${base}/api/v2/items`, requiresAuth: true },
        { method: 'GET', url: `${base}/search?q=shoes` },
      ];
      const r = await runChecks(ctxFor(base, flows));
      const all = titles(r);
      for (const expected of [
        'Exposed git repository: /.git/HEAD', 'Exposed .env file: /.env', 'Published source map: /app.js.map',
        'Spring Boot Actuator reachable without authentication', 'Debug mode enabled: Django DEBUG = True',
        'Published API documentation: /openapi.json', 'Older API version skips authentication: /api/v1/items',
        'Malformed input exposes a stack trace: /search',
      ]) expect(all, expected).toContain(expected);
      // .env evidence carries key names only, never values
      const env = r.reportReady.find((f) => f.title.en.startsWith('Exposed .env'))!;
      expect(JSON.stringify(env.evidence)).toContain('DB_PASSWORD');
      expect(JSON.stringify(env.evidence)).not.toContain('hunter2');
      // actuator exposing env is high
      expect(r.reportReady.find((f) => f.title.en.startsWith('Spring Boot Actuator'))!.severity).toBe('high');
      // possibly-intended documentation never reaches the report on its own
      expect(r.reportReady.some((f) => f.title.en.startsWith('Published API documentation'))).toBe(false);
    } finally { srv.close(); }
  });

  it('stays quiet on a single-page app that answers every path with the same page', async () => {
    const { srv, base } = await listen((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/html', 'content-security-policy': "default-src 'self'", 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY' });
      res.end('<html><div id="app"></div></html>');
    });
    try {
      const r = await runChecks(ctxFor(base, [{ method: 'GET', url: `${base}/api/v2/items?x=1` }]));
      const added = /^CHK-(exposed_file|debug_mode|api_inventory|error_handling|websocket|service_exposure|email_auth|subdomain_takeover|tls)-/;
      expect([...r.reportReady, ...r.needsReview].filter((f) => added.test(f.id)).map((f) => f.title.en)).toEqual([]);
    } finally { srv.close(); }
  });
});

describe('websocketOrigin', () => {
  function wsServer(checkOrigin: boolean) {
    return listen((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<script>const s = new WebSocket("/live")</script>');
    }).then(({ srv, base }) => {
      srv.on('upgrade', (req, socket) => {
        const allowed = !checkOrigin || req.headers.origin === base;
        if (!allowed) { socket.end('HTTP/1.1 403 Forbidden\r\n\r\n'); return; }
        const accept = createHash('sha1').update(`${req.headers['sec-websocket-key']}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64');
        socket.end(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
      });
      return { srv, base };
    });
  }
  it('flags a socket that accepts any Origin and not one that checks it', async () => {
    const open = await wsServer(false);
    const strict = await wsServer(true);
    try {
      const a = await websocketOrigin(ctxFor(open.base));
      expect(a.map((f) => f.title.en)).toEqual(['WebSocket accepts a foreign Origin: /live']);
      expect(a[0].confidence).toBe('likely');
      expect(await websocketOrigin(ctxFor(strict.base))).toEqual([]);
    } finally { open.srv.close(); strict.srv.close(); }
  });
});

describe('judgeTls', () => {
  const base = { host: 'shop.example.com', protocol: 'TLSv1.3', chainError: null, hostnameError: null, legacyAccepted: false };
  it('reports expiry, untrusted chains, name mismatch and legacy protocols', () => {
    const now = new Date('2026-11-24T00:00:00Z');
    const f = judgeTls({ ...base, validTo: 'Nov 30 00:00:00 2026 GMT', chainError: 'DEPTH_ZERO_SELF_SIGNED_CERT', hostnameError: "Hostname/IP does not match certificate's altnames", legacyAccepted: true }, 'fp', now);
    expect(f.map((x) => x.title.en).sort()).toEqual([
      'Certificate chain is not trusted', 'Certificate does not match the host name', 'Certificate expires soon', 'Server accepts TLS 1.0 or 1.1',
    ]);
    expect(judgeTls({ ...base, validTo: 'Nov 1 00:00:00 2026 GMT', chainError: 'CERT_HAS_EXPIRED' }, 'fp', now).map((x) => x.title.en)).toEqual(['Certificate has expired']);
  });
  it('reports nothing for a healthy handshake, and does not treat an unmeasurable legacy probe as a finding', () => {
    expect(judgeTls({ ...base, validTo: 'Jun 1 00:00:00 2027 GMT', legacyAccepted: null }, 'fp', new Date('2026-11-24T00:00:00Z'))).toEqual([]);
  });
});

describe('reflectionServices', () => {
  it('reads service names from a framed list_services response', () => {
    const str = (field: number, s: string | Buffer) => {
      const b = Buffer.isBuffer(s) ? s : Buffer.from(s);
      return Buffer.concat([Buffer.from([(field << 3) | 2, b.length]), b]);
    };
    const list = Buffer.concat([str(1, str(1, 'shop.Orders')), str(1, str(1, 'grpc.health.v1.Health'))]);
    const msg = str(6, list);
    const frame = Buffer.concat([Buffer.from([0, 0, 0, 0, msg.length]), msg]);
    expect(reflectionServices(frame)).toEqual(['shop.Orders', 'grpc.health.v1.Health']);
    expect(reflectionServices(Buffer.from([0, 0, 0, 0, 3, 0xff, 0xff, 0xff]))).toEqual([]);
  });
});

function fakeDns(records: { txt?: Record<string, string[]>; cname?: Record<string, string>; a?: Record<string, string[]> }): DnsResolver {
  const nx = () => Object.assign(new Error('not found'), { code: 'ENOTFOUND' });
  return {
    resolveTxt: async (n) => { const v = records.txt?.[n]; if (!v) throw nx(); return v.map((r) => [r]); },
    resolveCname: async (n) => { const v = records.cname?.[n]; if (!v) throw Object.assign(new Error('no data'), { code: 'ENODATA' }); return [v]; },
    resolve4: async (n) => { const v = records.a?.[n]; if (!v) throw nx(); return v; },
    resolve6: async () => { throw nx(); },
  };
}
const dnsCtx = (dns: DnsResolver, host = 'shop.example.com'): CheckContext => ({
  ...ctxFor(`https://${host}`, [], host), dns,
});

describe('DNS checks', () => {
  it("treats special-use names as not public", () => { expect([isPublicName("lab.internal"), isPublicName("printer.local"), isPublicName("shop.example.com"), isPublicName("10.0.0.1")]).toEqual([false, false, true, false]); });
  it('finds the organizational domain', () => {
    expect(orgDomain('app.shop.example.com')).toBe('example.com');
    expect(orgDomain('store.example.com.sa')).toBe('example.com.sa');
    expect(orgDomain('127.0.0.1')).toBeNull();
    expect(orgDomain('lab.localhost')).toBeNull();
  });
  it('reports missing DMARC and a permissive SPF, and nothing for a strict setup', async () => {
    const weak = await emailSpoofing(dnsCtx(fakeDns({ txt: { 'example.com': ['v=spf1 include:mail.example.net +all'] } })));
    expect(weak.map((f) => f.title.en).sort()).toEqual(['No DMARC record', 'SPF allows any server (+all)']);
    const strict = await emailSpoofing(dnsCtx(fakeDns({ txt: { 'example.com': ['v=spf1 -all'], '_dmarc.example.com': ['v=DMARC1; p=reject'] } })));
    expect(strict).toEqual([]);
  });
  it('does not query DNS for a host no grant names', async () => {
    const ctx = { ...ctxFor('https://other.example.org', [], 'shop.example.com'), dns: fakeDns({}) };
    expect(await emailSpoofing(ctx)).toEqual([]);
    expect(await danglingCname(ctx)).toEqual([]);
  });
  it('flags a CNAME to a provider name that no longer resolves', async () => {
    const dangling = await danglingCname(dnsCtx(fakeDns({ cname: { 'shop.example.com': 'old-shop.azurewebsites.net' } })));
    expect(dangling.map((f) => f.title.en)).toEqual(['Subdomain open to takeover: shop.example.com']);
    const fine = await danglingCname(dnsCtx(fakeDns({ cname: { 'shop.example.com': 'cdn.example.net' } })));
    expect(fine).toEqual([]);
  });
});

describe('analyzeWorkflows', () => {
  it('flags script injection, pwn requests, broad tokens, self-hosted PR runners and unpinned actions', () => {
    const text = [
      'on:',
      '  pull_request_target:',
      'permissions: write-all',
      'jobs:',
      '  build:',
      '    runs-on: [self-hosted, linux]',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '        with:',
      '          ref: ${{ github.event.pull_request.head.sha }}',
      '      - uses: some-org/deploy-action@v2',
      '      - run: |',
      '          echo "Title: ${{ github.event.pull_request.title }}"',
      '      - run: echo "${{ github.event.issue.body }}"',
      '',
    ].join('\n');
    const f = analyzeWorkflows([{ path: '.github/workflows/ci.yml', text }]);
    const byTitle = (s: string) => f.filter((x) => x.title.en.startsWith(s));
    expect(byTitle('Command injection').map((x) => x.location)).toEqual(['.github/workflows/ci.yml:13', '.github/workflows/ci.yml:14']);
    expect(byTitle('pull_request_target checks out').length).toBe(1);
    expect(byTitle('GITHUB_TOKEN granted write-all').length).toBe(1);
    expect(byTitle('Self-hosted runner').length).toBe(1);
    expect(byTitle('Third-party action not pinned').map((x) => x.title.en)).toEqual(['Third-party action not pinned to a SHA: some-org/deploy-action']);
  });
  it('accepts a hardened workflow', () => {
    const text = [
      'on:',
      '  pull_request:',
      'permissions:',
      '  contents: read',
      'jobs:',
      '  test:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '      - uses: some-org/lint@0123456789abcdef0123456789abcdef01234567',
      '      - env:',
      '          TITLE: ${{ github.event.pull_request.title }}',
      '        run: echo "$TITLE"',
      '',
    ].join('\n');
    expect(analyzeWorkflows([{ path: 'ci.yml', text }])).toEqual([]);
  });
});
