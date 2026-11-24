/**
 * Checks that need their own connection: the TLS handshake, a WebSocket
 * upgrade, and gRPC server reflection over HTTP/2. Each one passes the same
 * scope gate as HTTP requests (`client.authorize`) and connects to the address
 * the gate resolved. No message is sent after a handshake succeeds.
 */
import { randomBytes } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { connect as h2connect } from 'node:http2';
import { checkServerIdentity, connect as tlsConnect, type PeerCertificate } from 'node:tls';
import type { LookupFunction } from 'node:net';
import type { Finding } from '@secscan/shared';
import { ScopeRefused } from '@secscan/engine';
import { build, header, type CheckContext } from './context';
import { fetchRoot, sameOriginScripts } from './passive';
import { isPublicName } from './dnsChecks';

const t = (ar: string, en: string) => ({ ar, en });
const TIMEOUT = 8000;

/** Connect to the address the scope gate pinned, keeping the original hostname for SNI. */
function pinned(address?: string): LookupFunction | undefined {
  if (!address) return undefined;
  const family = address.includes(':') ? 6 : 4;
  return ((_host: string, opts: { all?: boolean }, cb: (...a: unknown[]) => void) =>
    opts?.all ? cb(null, [{ address, family }]) : cb(null, address, family)) as unknown as LookupFunction;
}

async function gate(ctx: CheckContext, url: string, method = 'GET'): Promise<{ address?: string } | null> {
  try {
    return await ctx.client.authorize(url, method);
  } catch (e) {
    if (e instanceof ScopeRefused) return null;
    throw e;
  }
}

// ─── TLS ─────────────────────────────────────────────────────────────────────

export interface TlsObservation {
  host: string;
  protocol: string | null;
  chainError: string | null;
  hostnameError: string | null;
  validTo: string | null;
  /** true: server completed a TLS 1.0/1.1 handshake; false: refused; null: not measurable here. */
  legacyAccepted: boolean | null;
}

function handshake(host: string, port: number, address: string | undefined, legacy: boolean) {
  return new Promise<{ cert?: PeerCertificate; protocol?: string | null; error?: string; authError?: string | null }>((resolve) => {
    const socket = tlsConnect({
      host: address ?? host, port, servername: host, rejectUnauthorized: false,
      ...(legacy ? { minVersion: 'TLSv1' as const, maxVersion: 'TLSv1.1' as const, ciphers: 'DEFAULT:@SECLEVEL=0' } : {}),
    });
    const done = (v: Parameters<typeof resolve>[0]) => { socket.destroy(); resolve(v); };
    socket.setTimeout(TIMEOUT, () => done({ error: 'timeout' }));
    socket.once('secureConnect', () => done({
      cert: socket.getPeerCertificate(), protocol: socket.getProtocol(),
      authError: socket.authorizationError ? String(socket.authorizationError) : null,
    }));
    socket.once('error', (e: NodeJS.ErrnoException) => done({ error: `${e.code ?? ''} ${e.message}` }));
  });
}

export async function observeTls(ctx: CheckContext): Promise<TlsObservation | null> {
  const u = new URL(ctx.rootUrl);
  // Certificate posture is judged for public names; a lab name usually has its own CA.
  if (u.protocol !== 'https:' || !isPublicName(u.hostname)) return null;
  const g = await gate(ctx, ctx.rootUrl);
  if (!g) return null;
  const port = Number(u.port || 443);
  const main = await handshake(u.hostname, port, g.address, false);
  if (!main.cert) return null;
  const identity = main.cert.subject ? checkServerIdentity(u.hostname, main.cert) : new Error('no certificate');
  const legacy = await handshake(u.hostname, port, g.address, true);
  // A local OpenSSL without TLS 1.0/1.1 support cannot measure this; do not call it a pass.
  const localLimit = /no protocols available|unsupported protocol|NO_PROTOCOLS/i.test(legacy.error ?? '');
  return {
    host: u.host,
    protocol: main.protocol ?? null,
    chainError: main.authError ?? null,
    hostnameError: identity ? identity.message : null,
    validTo: main.cert.valid_to ?? null,
    legacyAccepted: legacy.protocol ? true : localLimit ? null : false,
  };
}

/** Pure decision from an observation, so it can be tested without a live server. */
export function judgeTls(o: TlsObservation, grantFingerprint: string, now = new Date()): Finding[] {
  const out: Finding[] = [];
  const add = (key: string, severity: 'high' | 'medium' | 'low', title: [string, string], detail: [string, string], evidence: string) =>
    out.push(build({
      category: 'tls', severity, confidence: 'confirmed',
      title: t(title[0], title[1]),
      description: t(detail[0], detail[1]),
      impact: t('يضعف حماية الاتصال أو يعلّم المستخدمين تجاهل تحذيرات المتصفح.', 'Weakens transport protection or trains users to ignore browser warnings.'),
      remediation: t('جدّد الشهادة من جهة موثوقة تطابق الاسم، وعطّل TLS 1.0 و1.1.', 'Renew the certificate from a trusted CA for the right name, and disable TLS 1.0 and 1.1.'),
      asset: o.host, location: 'TLS handshake',
      evidence: [{ kind: 'response', label: 'handshake', content: evidence }],
      cvss: { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N' },
      idSeed: `${o.host}|tls|${key}`,
    }, grantFingerprint));
  const expires = o.validTo ? new Date(o.validTo) : null;
  if (expires && !Number.isNaN(expires.getTime())) {
    const days = Math.floor((expires.getTime() - now.getTime()) / 86_400_000);
    if (days < 0) add('expired', 'high', ['الشهادة منتهية', 'Certificate has expired'], [`انتهت في ${o.validTo}.`, `It expired on ${o.validTo}.`], `valid_to ${o.validTo}`);
    else if (days <= 14) add('expiring', 'medium', ['الشهادة تنتهي قريبًا', 'Certificate expires soon'], [`تنتهي خلال ${days} يومًا.`, `It expires in ${days} days.`], `valid_to ${o.validTo}`);
  }
  if (o.chainError && !/CERT_HAS_EXPIRED/.test(o.chainError)) {
    add('chain', 'high', ['سلسلة الشهادة غير موثوقة', 'Certificate chain is not trusted'], [`فشل التحقق: ${o.chainError}.`, `Validation failed: ${o.chainError}.`], o.chainError);
  }
  if (o.hostnameError) {
    add('name', 'high', ['الشهادة لا تطابق اسم الموقع', 'Certificate does not match the host name'], [o.hostnameError, o.hostnameError], o.hostnameError);
  }
  if (o.legacyAccepted) {
    add('legacy', 'medium', ['الخادم يقبل TLS 1.0 أو 1.1', 'Server accepts TLS 1.0 or 1.1'], ['إصدارات TLS القديمة مكسورة ومهجورة.', 'Old TLS versions are broken and deprecated.'], 'handshake completed with maxVersion TLSv1.1');
  }
  return out;
}

export async function tlsPosture(ctx: CheckContext): Promise<Finding[]> {
  const o = await observeTls(ctx);
  return o ? judgeTls(o, ctx.grantFingerprint) : [];
}

// ─── WebSocket ───────────────────────────────────────────────────────────────

/** ws:// and wss:// endpoints named in flows, the root page or its same-origin scripts. */
export async function websocketEndpoints(ctx: CheckContext): Promise<string[]> {
  const root = new URL(ctx.rootUrl);
  const found = new Set<string>();
  const add = (raw: string) => {
    try {
      const u = new URL(raw, ctx.rootUrl.replace(/^http/, 'ws'));
      if ((u.protocol === 'ws:' || u.protocol === 'wss:') && u.hostname === root.hostname) found.add(u.toString());
    } catch { /* not a URL */ }
  };
  for (const f of ctx.flows) if (/^wss?:/i.test(f.url)) add(f.url);
  const page = await fetchRoot(ctx);
  const bodies = page ? [page.body] : [];
  if (page && (header(page, 'content-type') ?? '').includes('html')) {
    for (const src of sameOriginScripts(page.body, ctx.rootUrl, 5)) {
      const js = await ctx.client.send({ method: 'GET', url: src }, { role: 'anonymous', sessionRef: null }).catch(() => null);
      if (js?.body) bodies.push(js.body);
    }
  }
  for (const body of bodies) {
    for (const m of body.matchAll(/["'`](wss?:\/\/[^"'`\s]+)["'`]/g)) add(m[1]);
    for (const m of body.matchAll(/new\s+WebSocket\(\s*["'`](\/[^"'`\s]*)["'`]/g)) add(m[1]);
  }
  return [...found].slice(0, 5);
}

/** Status of an upgrade request sent with `origin`; the socket is closed straight away. */
function upgradeStatus(url: URL, origin: string, address?: string): Promise<number> {
  return new Promise((resolve) => {
    const secure = url.protocol === 'wss:';
    const req = (secure ? httpsRequest : httpRequest)({
      host: url.hostname, port: url.port || (secure ? 443 : 80), path: url.pathname + url.search,
      servername: url.hostname, rejectUnauthorized: false, lookup: pinned(address),
      headers: {
        connection: 'Upgrade', upgrade: 'websocket', 'sec-websocket-version': '13',
        'sec-websocket-key': randomBytes(16).toString('base64'), origin,
        'user-agent': 'secscan/0.1 (authorized security test)',
      },
      timeout: TIMEOUT,
    });
    req.once('upgrade', (res, socket) => { socket.destroy(); resolve(res.statusCode ?? 101); });
    req.once('response', (res) => { res.resume(); resolve(res.statusCode ?? 0); });
    req.once('timeout', () => { req.destroy(); resolve(0); });
    req.once('error', () => resolve(0));
    req.end();
  });
}

/**
 * Cross-site WebSocket hijacking precondition: the server completes the
 * upgrade for a foreign Origin. Whether that matters depends on how the socket
 * authenticates (browser cookies make it exploitable), so it goes to review.
 */
export async function websocketOrigin(ctx: CheckContext): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const endpoint of await websocketEndpoints(ctx)) {
    const url = new URL(endpoint);
    const g = await gate(ctx, endpoint);
    if (!g) continue;
    const own = `${url.protocol === 'wss:' ? 'https' : 'http'}://${url.host}`;
    if ((await upgradeStatus(url, own, g.address)) !== 101) continue; // not a live socket for us either
    const foreign = 'https://cross-origin.secscan.invalid';
    if ((await upgradeStatus(url, foreign, g.address)) !== 101) continue;
    out.push(build({
      category: 'websocket', severity: 'medium', confidence: 'likely',
      title: t(`WebSocket يقبل أصلًا خارجيًا: ${url.pathname}`, `WebSocket accepts a foreign Origin: ${url.pathname}`),
      description: t('الخادم أكمل المصافحة لطلب Origin من موقع آخر.', 'The server completed the handshake for an Origin from another site.'),
      impact: t('إن كان الاتصال يعتمد على كوكي الجلسة، يستطيع أي موقع فتحه باسم المستخدم (CSWSH).', 'If the socket relies on the session cookie, any site can open it as the user (CSWSH).'),
      remediation: t('تحقق من ترويسة Origin مقابل قائمة مسموحة، أو اطلب رمزًا في أول رسالة بدل الكوكي.', 'Check the Origin header against an allow-list, or require a token in the first message instead of the cookie.'),
      asset: url.host, location: `WS ${url.pathname}`,
      evidence: [{ kind: 'response', label: 'handshake', content: `Origin ${foreign} → 101 Switching Protocols` }],
      cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'H', I: 'L', A: 'N' },
      idSeed: `${endpoint}|ws-origin`,
    }, ctx.grantFingerprint));
  }
  return out;
}

// ─── gRPC reflection ─────────────────────────────────────────────────────────

/** Minimal protobuf reader: length-delimited fields only, which is all reflection needs. */
function fields(buf: Buffer): [number, Buffer][] {
  const out: [number, Buffer][] = [];
  let i = 0;
  const varint = () => {
    let v = 0, shift = 0;
    for (;;) {
      if (i >= buf.length) throw new Error('truncated');
      const b = buf[i++];
      v += (b & 0x7f) * 2 ** shift;
      if (!(b & 0x80)) return v;
      shift += 7;
    }
  };
  while (i < buf.length) {
    const key = varint();
    const wire = key & 7;
    if (wire === 2) { const len = varint(); out.push([key >>> 3, buf.subarray(i, i + len)]); i += len; }
    else if (wire === 0) varint();
    else if (wire === 1) i += 8;
    else if (wire === 5) i += 4;
    else throw new Error('unsupported wire type');
  }
  return out;
}

/** Service names from a framed ServerReflectionResponse stream (list_services_response = 6). */
export function reflectionServices(stream: Buffer): string[] {
  const names: string[] = [];
  let i = 0;
  while (i + 5 <= stream.length) {
    const len = stream.readUInt32BE(i + 1);
    const msg = stream.subarray(i + 5, i + 5 + len);
    i += 5 + len;
    try {
      for (const [n, list] of fields(msg)) if (n === 6)
        for (const [m, svc] of fields(list)) if (m === 1)
          for (const [k, name] of fields(svc)) if (k === 1) names.push(name.toString('utf8'));
    } catch { /* malformed frame */ }
  }
  return names;
}

const LIST_SERVICES = Buffer.from([0, 0, 0, 0, 2, 0x3a, 0x00]); // framed { list_services: "" }

function reflect(origin: string, path: string, address?: string): Promise<{ status: string | null; services: string[] }> {
  return new Promise((resolve) => {
    const u = new URL(origin);
    const session = h2connect(origin, { servername: u.hostname, rejectUnauthorized: false, lookup: pinned(address) } as object);
    const finish = (v: { status: string | null; services: string[] }) => { session.destroy(); resolve(v); };
    session.setTimeout(TIMEOUT, () => finish({ status: null, services: [] }));
    session.once('error', () => finish({ status: null, services: [] }));
    const stream = session.request({ ':method': 'POST', ':path': path, 'content-type': 'application/grpc', te: 'trailers' });
    const chunks: Buffer[] = [];
    let status: string | null = null;
    stream.on('response', (h) => { if (h['grpc-status'] != null) status = String(h['grpc-status']); });
    stream.on('trailers', (h) => { if (h['grpc-status'] != null) status = String(h['grpc-status']); });
    stream.on('data', (c: Buffer) => { if (chunks.reduce((n, b) => n + b.length, 0) < 1_000_000) chunks.push(c); });
    stream.on('end', () => finish({ status, services: reflectionServices(Buffer.concat(chunks)) }));
    stream.on('error', () => finish({ status: null, services: [] }));
    stream.end(LIST_SERVICES);
  });
}

/** Origins that look like gRPC: a flow with a gRPC content type or a Package.Service/Method path. */
export function grpcOrigins(ctx: CheckContext): string[] {
  const origins = new Set<string>();
  for (const f of ctx.flows) {
    const ct = Object.entries(f.headers ?? {}).find(([k]) => k.toLowerCase() === 'content-type')?.[1] ?? '';
    if (/application\/grpc/i.test(ct) || /^\/[a-z][\w]*(\.[\w]+)+\/[A-Z]\w*$/.test(new URL(f.url).pathname)) origins.add(new URL(f.url).origin);
  }
  return [...origins].slice(0, 3);
}

/**
 * Server reflection lists every service and method to anyone who asks. gRPC
 * calls are POST, so on a grant that does not allow POST the scope gate
 * refuses and the refusal shows in the not-tested list.
 */
export async function grpcReflection(ctx: CheckContext): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const origin of grpcOrigins(ctx)) {
    for (const version of ['v1', 'v1alpha']) {
      const path = `/grpc.reflection.${version}.ServerReflection/ServerReflectionInfo`;
      const g = await gate(ctx, origin + path, 'POST');
      if (!g) break;
      const r = await reflect(origin, path, g.address);
      if (!r.services.length) continue;
      out.push(build({
        category: 'service_exposure', severity: 'medium', confidence: 'confirmed',
        title: t('انعكاس خادم gRPC مفعّل', 'gRPC server reflection is enabled'),
        description: t(`الخادم سرد ${r.services.length} خدمة لطلب بلا مصادقة.`, `The server listed ${r.services.length} services to an unauthenticated request.`),
        impact: t('يكشف كل الخدمات والطرق، بما فيها الداخلية.', 'Reveals every service and method, including internal ones.'),
        remediation: t('عطّل الانعكاس في الإنتاج أو اشترط المصادقة عليه.', 'Disable reflection in production or require authentication for it.'),
        asset: new URL(origin).host, location: `gRPC ${path}`,
        evidence: [{ kind: 'response', label: 'services', content: r.services.slice(0, 15).join(', ') }],
        cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
        idSeed: `${origin}|grpc-reflection`,
      }, ctx.grantFingerprint));
      break;
    }
  }
  return out;
}
