/**
 * Exposure checks: files, docs, framework consoles and debug pages that a
 * deployment should not serve, plus older API versions and malformed-input
 * handling. Read-only GETs through the guarded client. Every probe needs a
 * content signature, never a bare 200, because single-page apps answer every
 * path with the same HTML. Evidence records what was found, never secret values.
 */
import { randomBytes } from 'node:crypto';
import type { Finding } from '@secscan/shared';
import type { RecordedResponse } from '@secscan/engine';
import { ANON, build, header, identityFor, safeSend, type CheckContext } from './context';
import { STACK, fetchRoot, sameOriginScripts } from './passive';

const t = (ar: string, en: string) => ({ ar, en });
const hostOf = (ctx: CheckContext) => new URL(ctx.rootUrl).host;
const at = (ctx: CheckContext, path: string) => new URL(path, ctx.rootUrl).toString();
const get = (ctx: CheckContext, url: string) => safeSend(ctx, { method: 'GET', url });
const isHtml = (r: RecordedResponse) => (header(r, 'content-type') ?? '').toLowerCase().includes('html');
const ok = (r: RecordedResponse | null): r is RecordedResponse => !!r && r.status >= 200 && r.status < 300;
const hasStack = (body: string) => STACK.some((s) => body.toLowerCase().includes(s));

/** One request to a path that cannot exist: the server's not-found answer. */
const missCache = new WeakMap<CheckContext, Promise<RecordedResponse | null>>();
export function fetchMissing(ctx: CheckContext): Promise<RecordedResponse | null> {
  let p = missCache.get(ctx);
  if (!p) {
    p = get(ctx, at(ctx, `/secscan-missing-${randomBytes(6).toString('hex')}`));
    missCache.set(ctx, p);
  }
  return p;
}
/** True when `r` is just the catch-all answer (SPA index or custom 404). */
async function isCatchAll(ctx: CheckContext, r: RecordedResponse) {
  const miss = await fetchMissing(ctx);
  return !!miss && miss.status === r.status && miss.body === r.body;
}

interface FileProbe {
  path: string;
  matches: (r: RecordedResponse) => boolean;
  severity: 'high' | 'medium' | 'low';
  what: [string, string];
  evidence: (r: RecordedResponse) => string;
}
const ENV_LINE = /^[A-Z][A-Z0-9_]{2,}=.*$/gm;
const FILES: FileProbe[] = [
  {
    path: '/.git/HEAD', severity: 'high', what: ['مستودع git مكشوف', 'Exposed git repository'],
    matches: (r) => /^(ref: refs\/\S+|[0-9a-f]{40})$/.test(r.body.trim()),
    evidence: () => '/.git/HEAD returned a git HEAD reference',
  },
  {
    path: '/.git/config', severity: 'high', what: ['إعدادات git مكشوفة', 'Exposed git config'],
    matches: (r) => /^\[core\]/m.test(r.body) && r.body.includes('repositoryformatversion'),
    evidence: () => '/.git/config returned a [core] section',
  },
  {
    path: '/.env', severity: 'high', what: ['ملف .env مكشوف', 'Exposed .env file'],
    matches: (r) => !isHtml(r) && (r.body.match(ENV_LINE)?.length ?? 0) >= 2,
    // Key names only; the values may be live secrets.
    evidence: (r) => 'keys: ' + [...new Set((r.body.match(ENV_LINE) ?? []).map((l) => l.split('=')[0]))].slice(0, 12).join(', '),
  },
  {
    path: '/.DS_Store', severity: 'low', what: ['ملف .DS_Store مكشوف', 'Exposed .DS_Store file'],
    matches: (r) => r.body.slice(4, 8) === 'Bud1',
    evidence: () => '/.DS_Store has the Bud1 signature (it lists directory contents)',
  },
];

export async function exposedFiles(ctx: CheckContext): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const probe of FILES) {
    const r = await get(ctx, at(ctx, probe.path));
    if (!ok(r) || (await isCatchAll(ctx, r)) || !probe.matches(r)) continue;
    out.push(build({
      category: 'exposed_file', severity: probe.severity, confidence: 'confirmed',
      title: t(`${probe.what[0]}: ${probe.path}`, `${probe.what[1]}: ${probe.path}`),
      description: t(`الخادم يقدّم ${probe.path} للعامة.`, `The server serves ${probe.path} publicly.`),
      impact: t('كشف الكود المصدري أو الأسرار أو بنية المجلدات.', 'Discloses source code, secrets or directory structure.'),
      remediation: t('امنع تقديم الملفات المخفية على الخادم أو الـ CDN، واحذفها من مجلد النشر، ودوّر أي سر ظهر فيها.', 'Block dotfiles at the server or CDN, remove them from the deploy directory, and rotate any secret they held.'),
      asset: hostOf(ctx), location: `GET ${probe.path}`,
      evidence: [{ kind: 'response', label: 'signature', content: probe.evidence(r) }],
      cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: probe.severity === 'low' ? 'L' : 'H', I: 'N', A: 'N' },
      idSeed: `${ctx.rootUrl}|file|${probe.path}`,
    }, ctx.grantFingerprint));
  }
  return out;
}

/** Published JavaScript source maps rebuild the original source tree. */
export async function sourceMaps(ctx: CheckContext): Promise<Finding[]> {
  const root = await fetchRoot(ctx);
  if (!root || !isHtml(root)) return [];
  const out: Finding[] = [];
  for (const src of sameOriginScripts(root.body, ctx.rootUrl, 5)) {
    const js = await get(ctx, src);
    if (!ok(js)) continue;
    const declared = js.body.match(/[#@]\s*sourceMappingURL=([^\s'"]+)/)?.[1];
    if (declared?.startsWith('data:')) continue;
    let mapUrl: string;
    try { mapUrl = new URL(declared ?? `${new URL(src).pathname}.map`, src).toString(); } catch { continue; }
    if (new URL(mapUrl).origin !== new URL(ctx.rootUrl).origin) continue;
    const map = await get(ctx, mapUrl);
    if (!ok(map)) continue;
    let parsed: { version?: unknown; sources?: unknown; sourcesContent?: unknown };
    try { parsed = JSON.parse(map.body); } catch { continue; }
    if (parsed.version !== 3 || !Array.isArray(parsed.sources)) continue;
    const withSource = Array.isArray(parsed.sourcesContent) && parsed.sourcesContent.some((c) => typeof c === 'string' && c.length > 0);
    const path = new URL(mapUrl).pathname;
    out.push(build({
      category: 'exposed_file', severity: withSource ? 'medium' : 'low', confidence: 'confirmed',
      title: t(`خريطة مصدر منشورة: ${path}`, `Published source map: ${path}`),
      description: t(`الخريطة تسرد ${parsed.sources.length} ملفًا مصدريًا${withSource ? ' مع محتواها' : ''}.`, `The map lists ${parsed.sources.length} source files${withSource ? ' with their contents' : ''}.`),
      impact: t('تعيد بناء الكود الأصلي للواجهة، بما فيه التعليقات والمسارات الداخلية.', 'Rebuilds the original front-end source, including comments and internal routes.'),
      remediation: t('لا تنشر ملفات .map في الإنتاج، أو ارفعها لأداة تتبع الأخطاء فقط.', 'Do not deploy .map files to production, or upload them only to your error tracker.'),
      asset: hostOf(ctx), location: `GET ${path}`,
      evidence: [{ kind: 'response', label: 'source map', content: `version 3 · ${parsed.sources.length} sources · sourcesContent ${withSource ? 'present' : 'absent'}` }],
      cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
      idSeed: `${mapUrl}|sourcemap`,
    }, ctx.grantFingerprint));
  }
  return out;
}

const DOC_PATHS = ['/openapi.json', '/swagger.json', '/v3/api-docs', '/v2/api-docs', '/swagger/v1/swagger.json', '/api-docs', '/swagger-ui.html', '/swagger-ui/index.html'];

/** Public API documentation can be intended, so it always goes to review. */
export async function apiDocs(ctx: CheckContext): Promise<Finding[]> {
  for (const path of DOC_PATHS) {
    const r = await get(ctx, at(ctx, path));
    if (!ok(r) || (await isCatchAll(ctx, r))) continue;
    let kind = '';
    try {
      const doc = JSON.parse(r.body);
      if ((doc.openapi || doc.swagger) && doc.paths) {
        kind = `${doc.openapi ? 'OpenAPI ' + doc.openapi : 'Swagger ' + doc.swagger} · ${Object.keys(doc.paths).length} paths`;
      }
    } catch {
      if (isHtml(r) && /swagger-ui/i.test(r.body)) kind = 'Swagger UI page';
    }
    if (!kind) continue;
    return [build({
      category: 'api_inventory', severity: 'info', confidence: 'needs_review',
      title: t(`توثيق API منشور: ${path}`, `Published API documentation: ${path}`),
      description: t('التوثيق متاح بلا تسجيل دخول. راجع إن كان هذا مقصودًا.', 'The documentation is available without login. Confirm this is intended.'),
      impact: t('يكشف كل نقاط الـ API، بما فيها الداخلية أو غير المكتملة.', 'Maps every API endpoint, including internal or unfinished ones.'),
      remediation: t('إن لم يكن عامًا بقصد، ضعه خلف المصادقة أو احذفه من بناء الإنتاج. ويمكن استيراده في SecScan كـ flows.', 'If it is not meant to be public, put it behind auth or drop it from the production build. You can also import it into SecScan as flows.'),
      asset: hostOf(ctx), location: `GET ${path}`,
      evidence: [{ kind: 'response', label: 'document', content: kind }],
      cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
      idSeed: `${ctx.rootUrl}|apidocs`,
    }, ctx.grantFingerprint)];
  }
  return [];
}

interface ConsoleProbe {
  path: string;
  name: string;
  severity: 'high' | 'medium';
  detect: (r: RecordedResponse) => string | null;
}
const SENSITIVE_ACTUATOR = ['env', 'heapdump', 'threaddump', 'configprops', 'shutdown', 'jolokia', 'logfile', 'gateway'];
const CONSOLES: ConsoleProbe[] = [
  {
    path: '/actuator', name: 'Spring Boot Actuator', severity: 'high',
    detect: (r) => {
      try {
        const links = Object.keys(JSON.parse(r.body)._links ?? {});
        return links.length ? `endpoints: ${links.join(', ')}` : null;
      } catch { return null; }
    },
  },
  {
    path: '/_ignition/health-check', name: 'Laravel Ignition', severity: 'high',
    detect: (r) => (/"can_execute_commands"\s*:/.test(r.body) ? 'Ignition health-check answered' : null),
  },
  { path: '/telescope', name: 'Laravel Telescope', severity: 'high', detect: (r) => (/Laravel Telescope|window\.Telescope\b/.test(r.body) ? 'Telescope dashboard served' : null) },
  { path: '/horizon', name: 'Laravel Horizon', severity: 'medium', detect: (r) => (/window\.Horizon\b/.test(r.body) ? 'Horizon dashboard served' : null) },
  { path: '/server-status', name: 'Apache server-status', severity: 'medium', detect: (r) => (/Apache Server Status for/i.test(r.body) ? 'server-status page served' : null) },
  { path: '/phpinfo.php', name: 'phpinfo()', severity: 'medium', detect: (r) => (/phpinfo\(\)/.test(r.body) && /PHP Version/.test(r.body) ? 'phpinfo() output served' : null) },
  { path: '/elmah.axd', name: 'ELMAH error log', severity: 'high', detect: (r) => (/Error Log for/i.test(r.body) && /ELMAH/i.test(r.body) ? 'ELMAH log served' : null) },
  { path: '/trace.axd', name: 'ASP.NET trace', severity: 'medium', detect: (r) => (/Application Trace/i.test(r.body) ? 'trace.axd served' : null) },
];

/** Framework consoles and diagnostics reachable without login. */
export async function frameworkConsoles(ctx: CheckContext): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const probe of CONSOLES) {
    const r = await get(ctx, at(ctx, probe.path));
    if (!ok(r) || (await isCatchAll(ctx, r))) continue;
    const found = probe.detect(r);
    if (!found) continue;
    let severity: 'high' | 'medium' | 'low' = probe.severity;
    if (probe.path === '/actuator') {
      severity = SENSITIVE_ACTUATOR.some((e) => found.split(/[ ,]+/).includes(e)) ? 'high' : 'low';
    }
    out.push(build({
      category: 'debug_mode', severity, confidence: 'confirmed',
      title: t(`${probe.name} متاح بلا مصادقة`, `${probe.name} reachable without authentication`),
      description: t(`${probe.path} يجيب بلا تسجيل دخول.`, `${probe.path} answers without login.`),
      impact: t('لوحات التشخيص تكشف الإعدادات والطلبات والأسرار، وبعضها يسمح بتنفيذ أوامر.', 'Diagnostic consoles leak configuration, requests and secrets; some allow running commands.'),
      remediation: t('عطّلها في الإنتاج أو ضعها خلف المصادقة على شبكة داخلية.', 'Disable it in production or put it behind authentication on an internal network.'),
      asset: hostOf(ctx), location: `GET ${probe.path}`,
      evidence: [{ kind: 'response', label: probe.name, content: found }],
      cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: severity === 'low' ? 'L' : 'H', I: 'N', A: 'N' },
      idSeed: `${ctx.rootUrl}|console|${probe.path}`,
    }, ctx.grantFingerprint));
  }
  return out;
}

const DEBUG_PAGES: [RegExp, string, 'high' | 'medium'][] = [
  [/Werkzeug Debugger|__debugger__/, 'Werkzeug interactive debugger', 'high'],
  [/You're seeing this error because you have <code>DEBUG = True<\/code>/, 'Django DEBUG = True', 'medium'],
  [/Whoops! There was an error|ignition-app|Illuminate\\/, 'Laravel debug page', 'medium'],
  [/Action Controller: Exception caught|Rails\.root:/, 'Rails development error page', 'medium'],
  [/sf-toolbar|Symfony Exception/, 'Symfony debug toolbar or exception page', 'medium'],
  [/Server Error in '\/' Application[\s\S]*Version Information:/, 'ASP.NET detailed error page', 'medium'],
];

/** The not-found page of a framework left in debug mode. */
export async function debugPages(ctx: CheckContext): Promise<Finding[]> {
  const miss = await fetchMissing(ctx);
  if (!miss) return [];
  const hit = DEBUG_PAGES.find(([re]) => re.test(miss.body));
  if (!hit) return [];
  const [, name, severity] = hit;
  return [build({
    category: 'debug_mode', severity, confidence: 'confirmed',
    title: t(`وضع التطوير مفعّل: ${name}`, `Debug mode enabled: ${name}`),
    description: t('طلب لمسار غير موجود أعاد صفحة خطأ التطوير.', 'A request for a missing path returned the framework development error page.'),
    impact: t('يكشف المسارات والإعدادات والكود، وبعض المصححات تسمح بتنفيذ أوامر.', 'Reveals routes, settings and code; some debuggers allow running commands.'),
    remediation: t('عطّل وضع التطوير في الإنتاج وأرجع صفحات خطأ عامة.', 'Turn debug mode off in production and serve generic error pages.'),
    asset: hostOf(ctx), location: 'GET /<missing path>',
    evidence: [{ kind: 'response', label: 'signature', content: `${name} · HTTP ${miss.status}` }],
    cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: severity === 'high' ? 'H' : 'N', A: 'N' },
    idSeed: `${ctx.rootUrl}|debugpage|${name}`,
  }, ctx.grantFingerprint)];
}

/** Older API versions that are still served next to the documented one. */
export async function shadowApiVersions(ctx: CheckContext): Promise<Finding[]> {
  const out: Finding[] = [];
  const tried = new Set<string>();
  for (const flow of ctx.flows.filter((f) => f.method.toUpperCase() === 'GET').slice(0, 30)) {
    const u = new URL(flow.url);
    const m = u.pathname.match(/\/v(\d+)(?=\/|$)/);
    if (!m || Number(m[1]) < 2) continue;
    const current = Number(m[1]);
    for (let v = current - 1; v >= Math.max(1, current - 3); v--) {
      const older = new URL(u);
      older.pathname = u.pathname.replace(/\/v\d+(?=\/|$)/, `/v${v}`);
      if (tried.has(older.toString())) continue;
      if (tried.size >= 12) return out;
      tried.add(older.toString());
      const anonOld = await safeSend(ctx, { method: 'GET', url: older.toString() }, ANON);
      if (!ok(anonOld) || isHtml(anonOld) || (await isCatchAll(ctx, anonOld))) continue;
      // An older version that skips the login the current one demands is the real problem.
      let opensAuth = false;
      if (flow.requiresAuth) {
        const anonNew = await safeSend(ctx, { method: 'GET', url: flow.url }, ANON);
        opensAuth = !!anonNew && (anonNew.status === 401 || anonNew.status === 403);
      }
      out.push(build({
        category: 'api_inventory', severity: opensAuth ? 'high' : 'low', confidence: opensAuth ? 'likely' : 'needs_review',
        title: opensAuth
          ? t(`إصدار API أقدم يتجاوز المصادقة: ${older.pathname}`, `Older API version skips authentication: ${older.pathname}`)
          : t(`إصدار API أقدم ما زال يعمل: ${older.pathname}`, `Older API version still served: ${older.pathname}`),
        description: opensAuth
          ? t(`${u.pathname} يطلب تسجيل الدخول، بينما ${older.pathname} يجيب بلا مصادقة.`, `${u.pathname} requires login while ${older.pathname} answers without it.`)
          : t(`${older.pathname} يجيب بجانب ${u.pathname}. تأكد أنه ما زال مُدارًا.`, `${older.pathname} answers next to ${u.pathname}. Confirm it is still maintained.`),
        impact: t('الإصدارات القديمة تفوتها إصلاحات الأمان وضوابط الوصول الأحدث.', 'Old versions miss newer security fixes and access controls.'),
        remediation: t('أوقف الإصدارات القديمة أو طبّق عليها نفس المصادقة والضوابط، واحتفظ بجرد للإصدارات العاملة.', 'Retire old versions or apply the same auth and controls, and keep an inventory of live versions.'),
        asset: u.host, location: `GET ${older.pathname}`,
        evidence: [{ kind: 'response', label: 'anonymous status', content: `${older.pathname} → HTTP ${anonOld.status}${opensAuth ? ` · ${u.pathname} → 401/403 anonymously` : ''}` }],
        cvss: opensAuth
          ? { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' }
          : { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
        idSeed: `${older.toString()}|shadow`,
      }, ctx.grantFingerprint));
    }
  }
  return out;
}

const MALFORMED: [string, (name: string, value: string) => [string, string]][] = [
  ['array instead of a string', (n, v) => [`${n}[]`, v]],
  ['null byte', (n) => [n, '\u0000']],
  ['oversized value', (n) => [n, 'A'.repeat(4096)]],
  ['quote and brace characters', (n) => [n, '"\'{}\\']],
];

function withParam(url: URL, name: string, [key, value]: [string, string]) {
  const next = new URL(url);
  next.searchParams.delete(name);
  next.searchParams.append(key, value);
  return next.toString();
}

/**
 * Malformed input on GET parameters: a stack trace the normal response does
 * not show, or a login-protected endpoint that starts answering (fails open).
 */
export async function malformedInput(ctx: CheckContext): Promise<Finding[]> {
  const out: Finding[] = [];
  const flows = ctx.flows
    .filter((f) => f.method.toUpperCase() === 'GET' && [...new URL(f.url).searchParams.keys()].length > 0)
    .slice(0, 5);
  for (const flow of flows) {
    const u = new URL(flow.url);
    const name = [...u.searchParams.keys()][0];
    const value = u.searchParams.get(name) ?? '';
    const identity = identityFor(ctx, flow);
    const base = await safeSend(ctx, { method: 'GET', url: flow.url, headers: flow.headers }, identity);
    if (!base) continue;
    const anonBase = flow.requiresAuth ? await safeSend(ctx, { method: 'GET', url: flow.url }, ANON) : null;
    const guarded = !!anonBase && (anonBase.status === 401 || anonBase.status === 403);
    const baseStack = hasStack(base.body);
    for (const [label, variant] of MALFORMED) {
      const url = withParam(u, name, variant(name, value));
      const r = await safeSend(ctx, { method: 'GET', url, headers: flow.headers }, identity);
      if (r && !baseStack && hasStack(r.body)) {
        out.push(build({
          category: 'error_handling', severity: 'medium', confidence: 'likely',
          title: t(`مدخل مشوّه يكشف تتبع مكدّس: ${u.pathname}`, `Malformed input exposes a stack trace: ${u.pathname}`),
          description: t(`قيمة (${label}) في '${name}' أعادت تتبع مكدّس لا يظهر في الرد العادي.`, `A ${label} in '${name}' returned a stack trace the normal response does not show.`),
          impact: t('يكشف تفاصيل داخلية ويدل على مسار خطأ غير معالج.', 'Leaks internal detail and points to an unhandled error path.'),
          remediation: t('تحقق من نوع المدخلات وطولها، والتقط الأخطاء وأرجع رسالة عامة.', 'Validate input type and length, catch errors and return a generic message.'),
          asset: u.host, location: `GET ${u.pathname}`,
          evidence: [
            { kind: 'request', label: 'variant', content: `${name}: ${label}` },
            { kind: 'response', label: 'status', content: `HTTP ${base.status} → ${r.status}` },
          ],
          cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
          idSeed: `${u.origin}${u.pathname}|malformed-stack|${name}`,
        }, ctx.grantFingerprint));
        break;
      }
      if (!guarded) continue;
      const anon = await safeSend(ctx, { method: 'GET', url }, ANON);
      if (ok(anon) && !isHtml(anon)) {
        out.push(build({
          category: 'error_handling', severity: 'high', confidence: 'likely',
          title: t(`مدخل مشوّه يتجاوز المصادقة: ${u.pathname}`, `Malformed input bypasses authentication: ${u.pathname}`),
          description: t(`بلا تسجيل دخول يرد ${u.pathname} بـ ${anonBase!.status}، لكن مع (${label}) في '${name}' يرد بـ ${anon.status}.`, `Anonymously ${u.pathname} returns ${anonBase!.status}, but with a ${label} in '${name}' it returns ${anon.status}.`),
          impact: t('فحص الصلاحية يفشل مفتوحًا عند خطأ في المعالجة.', 'The authorization check fails open on a parsing error.'),
          remediation: t('اجعل المصادقة تسبق معالجة المدخلات، واجعل أي خطأ يرفض الطلب.', 'Run authentication before input parsing, and make any error deny the request.'),
          asset: u.host, location: `GET ${u.pathname}`,
          evidence: [
            { kind: 'request', label: 'variant', content: `${name}: ${label} · anonymous` },
            { kind: 'response', label: 'status', content: `HTTP ${anonBase!.status} → ${anon.status}` },
          ],
          cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
          idSeed: `${u.origin}${u.pathname}|malformed-open|${name}`,
        }, ctx.grantFingerprint));
        break;
      }
    }
  }
  return out;
}
