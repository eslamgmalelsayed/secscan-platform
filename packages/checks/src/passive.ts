/**
 * Passive scorecard checks (Design §5 wedge #1). One safe GET of the root,
 * then inspect headers/cookies/body. Non-intrusive; suitable for a free
 * external scorecard that needs only proof of ownership.
 */
import type { Finding } from '@secscan/shared';
import { build, header, safeSend, type CheckContext } from './context';

const t = (ar: string, en: string) => ({ ar, en });

export async function securityHeaders(ctx: CheckContext): Promise<Finding[]> {
  const resp = await safeSend(ctx, { method: 'GET', url: ctx.rootUrl });
  if (!resp) return [];
  const present = new Set(Object.keys(resp.headers).map((k) => k.toLowerCase()));
  const want: [string, 'medium' | 'low', string, string][] = [
    ['strict-transport-security', 'medium', 'يفرض HTTPS ويمنع SSL stripping', 'forces HTTPS, prevents SSL stripping'],
    ['content-security-policy', 'medium', 'يحد مصادر السكربت ويخفف XSS', 'limits script sources, mitigates XSS'],
    ['x-content-type-options', 'low', 'يمنع MIME sniffing', 'stops MIME sniffing'],
    ['x-frame-options', 'low', 'يمنع clickjacking', 'prevents clickjacking'],
  ];
  const out: Finding[] = [];
  for (const [h, sev, whyAr, whyEn] of want) {
    if (!present.has(h)) {
      out.push(build({
        category: 'security_header', severity: sev, confidence: 'confirmed',
        title: t(`هيدر أمني ناقص: ${h}`, `Missing security header: ${h}`),
        description: t(`الاستجابة لا تضبط '${h}'. ${whyAr}.`, `The response does not set '${h}'. ${whyEn}.`),
        impact: t('إضعاف دفاعات المتصفح.', 'Weakens browser-side defenses.'),
        remediation: t(`اضبط '${h}' على الحافة أو في التطبيق.`, `Set '${h}' at the edge or app layer.`),
        asset: new URL(ctx.rootUrl).host, location: `GET ${new URL(ctx.rootUrl).pathname}`,
        evidence: [{ kind: 'response', label: 'missing header', content: h }],
        cvss: { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'N', A: 'N' },
        idSeed: `${ctx.rootUrl}|${h}`,
      }, ctx.grantFingerprint));
    }
  }
  return out;
}

export async function cookies(ctx: CheckContext): Promise<Finding[]> {
  const resp = await safeSend(ctx, { method: 'GET', url: ctx.rootUrl });
  if (!resp) return [];
  const sc = header(resp, 'set-cookie');
  if (!sc) return [];
  const low = sc.toLowerCase();
  const name = sc.split('=', 1)[0].trim();
  const missing = (['secure', 'httponly'] as const).filter((f) => !low.includes(f));
  if (!low.includes('samesite')) missing.push('samesite' as any);
  if (missing.length === 0) return [];
  return [build({
    category: 'insecure_cookie', severity: 'medium', confidence: 'confirmed',
    title: t(`كوكي '${name}' ناقصها أعلام: ${missing.join(', ')}`, `Cookie '${name}' missing flags: ${missing.join(', ')}`),
    description: t('كوكي جلسة بدون هذه الأعلام معرّضة للسرقة وCSRF.', 'Session cookies without these flags are exposed to theft and CSRF.'),
    impact: t('اختطاف الجلسة أو CSRF.', 'Session hijacking or CSRF.'),
    remediation: t('اضبط Secure و HttpOnly و SameSite=Lax/Strict.', 'Set Secure, HttpOnly and SameSite=Lax/Strict.'),
    asset: new URL(ctx.rootUrl).host,
    evidence: [{ kind: 'response', label: 'set-cookie', content: low }],
    cvss: { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N' },
    idSeed: `${ctx.rootUrl}|cookie|${name}`,
  }, ctx.grantFingerprint)];
}

export async function tlsRedirect(ctx: CheckContext): Promise<Finding[]> {
  const httpUrl = ctx.rootUrl.replace(/^https:/, 'http:');
  const resp = await safeSend(ctx, { method: 'GET', url: httpUrl });
  if (!resp) return [];
  const loc = (header(resp, 'location') ?? '').toLowerCase();
  if (resp.status >= 300 && resp.status < 400 && loc.startsWith('https://')) return [];
  return [build({
    category: 'tls', severity: 'medium', confidence: 'confirmed',
    title: t('HTTP لا يُحوَّل إلى HTTPS', 'Plain HTTP is not redirected to HTTPS'),
    description: t(`GET عبر http:// رجع ${resp.status} بدل تحويل إلى https://.`, `GET over http:// returned ${resp.status} instead of redirecting to https://.`),
    impact: t('اعتراض الاتصال (SSL stripping).', 'Traffic interception (SSL stripping).'),
    remediation: t('حوّل كل http:// إلى https:// وفعّل HSTS.', 'Redirect all http:// to https:// and enable HSTS.'),
    asset: new URL(ctx.rootUrl).host,
    evidence: [{ kind: 'response', label: 'http status', content: String(resp.status) }],
    cvss: { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'N' },
    idSeed: `${ctx.rootUrl}|tls-redirect`,
  }, ctx.grantFingerprint)];
}

const LEAKY = ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator'];
const STACK = ['traceback (most recent call last)', 'java.lang.', 'at org.springframework', 'you have an error in your sql syntax', 'system.web.'];

export async function infoDisclosure(ctx: CheckContext): Promise<Finding[]> {
  const resp = await safeSend(ctx, { method: 'GET', url: ctx.rootUrl });
  if (!resp) return [];
  const out: Finding[] = [];
  for (const h of LEAKY) {
    const v = header(resp, h);
    if (v && /\d/.test(v)) {
      out.push(build({
        category: 'info_disclosure', severity: 'low', confidence: 'confirmed',
        title: t(`كشف إصدار في '${h}'`, `Version disclosure in '${h}'`),
        description: t(`الهيدر '${h}: ${v}' يكشف البرنامج/الإصدار.`, `Header '${h}: ${v}' reveals software/version.`),
        impact: t('يسهّل على المهاجم استهداف ثغرات معروفة.', 'Helps an attacker target known vulnerabilities.'),
        remediation: t(`أخفِ أو عمّم الهيدر '${h}'.`, `Suppress or genericize the '${h}' header.`),
        asset: new URL(ctx.rootUrl).host,
        evidence: [{ kind: 'response', label: h, content: v }],
        cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
        idSeed: `${ctx.rootUrl}|leak|${h}`,
      }, ctx.grantFingerprint));
    }
  }
  const body = resp.body.toLowerCase();
  if (STACK.some((s) => body.includes(s))) {
    out.push(build({
      category: 'info_disclosure', severity: 'medium', confidence: 'likely',
      title: t('أثر خطأ/تتبع مكدّس في جسم الاستجابة', 'Stack trace / framework error in response body'),
      description: t('جسم الاستجابة يحتوي ما يشبه تتبع مكدّس.', 'The response body contains what looks like a stack trace.'),
      impact: t('كشف تفاصيل داخلية للمهاجم.', 'Leaks internal detail to an attacker.'),
      remediation: t('أرجِع صفحات خطأ عامة في الإنتاج.', 'Return generic error pages in production.'),
      asset: new URL(ctx.rootUrl).host,
      evidence: [{ kind: 'response', label: 'signature', content: 'stack-trace pattern present' }],
      cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
      idSeed: `${ctx.rootUrl}|stacktrace`,
    }, ctx.grantFingerprint));
  }
  return out;
}

const SECRET_PATTERNS: [RegExp, string][] = [
  [/AKIA[0-9A-Z]{16}/, 'AWS access key id'],
  [/AIza[0-9A-Za-z_\-]{35}/, 'Google API key'],
  [/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, 'private key'],
  [/(?:secret|api[_-]?key|token)["']?\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']/i, 'inline secret assignment'],
];

export async function secretsInResponse(ctx: CheckContext): Promise<Finding[]> {
  const resp = await safeSend(ctx, { method: 'GET', url: ctx.rootUrl });
  if (!resp) return [];
  const out: Finding[] = [];
  for (const [re, label] of SECRET_PATTERNS) {
    if (re.test(resp.body)) {
      out.push(build({
        category: 'secret_exposure', severity: 'high', confidence: 'likely',
        title: t(`سر محتمل مكشوف: ${label}`, `Possible exposed secret: ${label}`),
        description: t('نمط يشبه سرًا ظهر في محتوى يصل للعميل (قد يكون في bundle/JS).', 'A secret-like pattern appeared in client-delivered content (possibly a JS bundle).'),
        impact: t('تسريب مفتاح/سر قد يُستغل مباشرة.', 'Leaked key/secret that may be directly abused.'),
        remediation: t('أزِل السر من الكود العميل، دوّر المفتاح، وانقله للخادم.', 'Remove the secret from client code, rotate it, move it server-side.'),
        asset: new URL(ctx.rootUrl).host,
        evidence: [{ kind: 'response', label: 'pattern', content: label }],
        cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
        idSeed: `${ctx.rootUrl}|secret|${label}`,
      }, ctx.grantFingerprint));
    }
  }
  return out;
}
