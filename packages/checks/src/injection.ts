/**
 * Injection-class DETECTION — non-destructive, read-only, GET-only.
 *
 * Each check sends a benign probe and looks for an unambiguous tell:
 *   - SSTI: a template-engine evaluated our arithmetic (823*… = a number we
 *     never wrote literally), so the server renders untrusted templates.
 *   - Path traversal: a traversal sequence returned a file-content signature
 *     (`root:…:0:0:` / win.ini), so the path parameter reaches the filesystem.
 *   - NoSQL: an operator-injection differential (`[$ne]` vs `[$eq]`) reproducibly
 *     changes the result set, so the parameter is interpreted as a query operator.
 *   - Host-header: a poisoned Host/X-Forwarded-Host is reflected into the body or
 *     a Location, enabling cache/password-reset poisoning.
 *
 * None of these ship an exploit payload, dump data, or change state. They prove
 * the input is mishandled and stop there. Heavy exploitation stays out (§4).
 */
import { randomInt } from 'node:crypto';
import type { Finding } from '@secscan/shared';
import { bodyDigest, type RecordedRequest } from '@secscan/engine';
import { build, header, identityFor, safeSend, type CheckContext } from './context';

const t = (ar: string, en: string) => ({ ar, en });
const loc = (flow: RecordedRequest) => `${flow.method} ${new URL(flow.url).pathname}`;

function withParam(url: string, name: string, value: string): string {
  const u = new URL(url); u.searchParams.set(name, value); return u.toString();
}
function digest(resp: { body: string; headers: Record<string, string> }): string {
  return bodyDigest(resp.body, resp.headers['content-type'] ?? resp.headers['Content-Type'] ?? '');
}
function getParams(flow: RecordedRequest): [string, string][] {
  try { return [...new URL(flow.url).searchParams.entries()]; } catch { return []; }
}

/** Server-side template injection: our arithmetic came back evaluated. */
export async function ssti(ctx: CheckContext): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const flow of ctx.flows) {
    if (flow.method.toUpperCase() !== 'GET') continue;
    const as = identityFor(ctx, flow);
    for (const [name] of getParams(flow)) {
      const a = randomInt(10_000, 99_999), b = randomInt(11, 99);
      const product = String(a * b);
      const expr = `${a}*${b}`;
      // template syntaxes across engines; all evaluate a*b if interpreted
      const payloads = [`{{${expr}}}`, `\${${expr}}`, `#{${expr}}`, `<%=${expr}%>`, `*{${expr}}`];
      let hit = false;
      for (const p of payloads) {
        const resp = await safeSend(ctx, { ...flow, url: withParam(flow.url, name, p) }, as);
        if (!resp) continue;
        // evaluated (product present) but NOT merely reflected (expr absent)
        if (resp.body.includes(product) && !resp.body.includes(expr)) { hit = true; break; }
      }
      if (hit) {
        out.push(build({
          category: 'injection', severity: 'critical', confidence: 'confirmed',
          title: t(`حقن قوالب من جهة الخادم (SSTI) في '${name}'`, `Server-side template injection in '${name}'`),
          description: t('تعبير حسابي حميد جرى تقييمه في استجابة الخادم — محرك القوالب يفسّر إدخال المستخدم.', 'A benign arithmetic expression was evaluated in the server response — the template engine interprets user input.'),
          impact: t('تنفيذ تعبيرات القوالب قد يصل إلى تنفيذ أوامر على الخادم.', 'Template-expression execution, often escalating to server-side code execution.'),
          remediation: t('لا تُمرّر إدخال المستخدم إلى محرك القوالب؛ استخدم قوالب منطقية ثابتة ومرّر البيانات كمتغيّرات.', 'Never render user input as a template; use logic-less templates and pass data as variables.'),
          asset: new URL(flow.url).host, location: loc(flow),
          evidence: [{ kind: 'note', label: 'evaluated', content: `${a}*${b} => ${product} returned without the literal expression` }],
          cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },
          idSeed: `${flow.url}|ssti|${name}`,
        }, ctx.grantFingerprint));
      }
    }
  }
  return out;
}

const TRAVERSALS = ['../../../../../../etc/passwd', '....//....//....//....//etc/passwd', '..%2f..%2f..%2f..%2f..%2fetc%2fpasswd', '/../../../../windows/win.ini'];
const FILE_SIGNATURES = [/root:.*:0:0:/, /\[extensions\]/i, /for 16-bit app support/i];

/** Path traversal: a traversal sequence returned file-content signatures. */
export async function pathTraversal(ctx: CheckContext): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const flow of ctx.flows) {
    if (flow.method.toUpperCase() !== 'GET') continue;
    const as = identityFor(ctx, flow);
    for (const [name] of getParams(flow)) {
      let hit: string | null = null;
      for (const seq of TRAVERSALS) {
        const resp = await safeSend(ctx, { ...flow, url: withParam(flow.url, name, seq) }, as);
        if (resp && FILE_SIGNATURES.some((re) => re.test(resp.body))) { hit = seq; break; }
      }
      if (hit) {
        out.push(build({
          category: 'injection', severity: 'high', confidence: 'confirmed',
          title: t(`اجتياز مسار (path traversal) في '${name}'`, `Path traversal in '${name}'`),
          description: t('تسلسل اجتياز أعاد محتوى ملف نظام — البارامتر يصل إلى نظام الملفات دون تقييد.', 'A traversal sequence returned system-file content — the parameter reaches the filesystem unrestricted.'),
          impact: t('قراءة ملفات عشوائية على الخادم (أسرار، إعدادات).', 'Arbitrary file read on the server (secrets, config).'),
          remediation: t('امنع فواصل المسار، استخدم قوائم بيضاء للأسماء، وحلّ المسار داخل مجلد ثابت (canonicalize).', 'Reject path separators, allow-list filenames, and resolve within a fixed base directory (canonicalize).'),
          asset: new URL(flow.url).host, location: loc(flow),
          evidence: [{ kind: 'note', label: 'signature', content: 'system file content returned (e.g. root:…:0:0:)' }],
          cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
          idSeed: `${flow.url}|path|${name}`,
        }, ctx.grantFingerprint));
      }
    }
  }
  return out;
}

/** NoSQL operator injection: `[$ne]` (match-all) reproducibly diverges from
 *  baseline while `[$eq]=<baseVal>` stays equal — the value is a query operand. */
export async function nosqlDifferential(ctx: CheckContext): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const flow of ctx.flows) {
    if (flow.method.toUpperCase() !== 'GET') continue;
    const as = identityFor(ctx, flow);
    const baseline = await safeSend(ctx, flow, as);
    if (!baseline) continue;
    const baseDigest = digest(baseline);
    for (const [name, baseVal] of getParams(flow)) {
      // build name[$op]=val by hand (URLSearchParams would escape the brackets differently per server; keep it explicit)
      const bracket = (op: string, val: string) => {
        const u = new URL(flow.url); u.searchParams.delete(name);
        const qs = u.searchParams.toString();
        return `${u.origin}${u.pathname}?${qs ? qs + '&' : ''}${encodeURIComponent(name)}%5B%24${op}%5D=${encodeURIComponent(val)}`;
      };
      let matches = 0;
      for (let i = 0; i < 2; i++) {
        const ne = await safeSend(ctx, { ...flow, url: bracket('ne', '__secscan_absent__') }, as); // match-all
        const eq = await safeSend(ctx, { ...flow, url: bracket('eq', baseVal) }, as);               // equivalent to baseline
        if (!ne || !eq) break;
        if (digest(ne) !== baseDigest && digest(eq) === baseDigest) matches++;
        else break;
      }
      if (matches === 2) {
        out.push(build({
          category: 'injection', severity: 'high', confidence: 'confirmed',
          title: t(`حقن NoSQL عبر معامل في '${name}'`, `NoSQL operator injection in '${name}'`),
          description: t("معامل '$ne' غيّر مجموعة النتائج بينما '$eq' طابق الأساس، وتكرر — البارامتر يُفسَّر كمعامل استعلام.", "A '$ne' operator changed the result set while '$eq' matched the baseline, reproducibly — the parameter is interpreted as a query operator."),
          impact: t('تجاوز مرشّحات الاستعلام والمصادقة وقراءة بيانات غير مصرّح بها.', 'Bypass of query filters/authentication and unauthorized data reads.'),
          remediation: t('تحقّق من نوع الإدخال، وارفض كائنات المعاملات، واستخدم استعلامات مُقيَّدة بالنوع.', 'Validate input types, reject operator objects, and use type-pinned queries.'),
          asset: new URL(flow.url).host, location: loc(flow),
          evidence: [{ kind: 'note', label: 'differential', content: '$ne diverged from baseline; $eq matched (reproduced x2)' }],
          cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' },
          idSeed: `${flow.url}|nosql|${name}`,
        }, ctx.grantFingerprint));
      }
    }
  }
  return out;
}

/** Host-header injection: a poisoned Host/X-Forwarded-Host is reflected into the
 *  body or a redirect Location — the app trusts the client-supplied host. */
export async function hostHeaderInjection(ctx: CheckContext): Promise<Finding[]> {
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const flow of ctx.flows) {
    if (flow.method.toUpperCase() !== 'GET') continue;
    const key = new URL(flow.url).pathname;
    if (seen.has(key)) continue; seen.add(key);
    const poison = `secscan-hhi-${randomInt(1e6, 9e6)}.example`;
    const probe: RecordedRequest = { ...flow, headers: { ...(flow.headers ?? {}), Host: poison, 'X-Forwarded-Host': poison } };
    const resp = await safeSend(ctx, probe, identityFor(ctx, flow));
    if (!resp) continue;
    const inLocation = (header(resp, 'location') ?? '').includes(poison);
    const inBody = resp.body.includes(poison);
    if (inLocation || inBody) {
      out.push(build({
        category: 'injection', severity: 'medium', confidence: 'likely',
        title: t('حقن ترويسة Host', 'Host-header injection'),
        description: t(`ترويسة Host/X-Forwarded-Host مسمومة انعكست في ${inLocation ? 'Location' : 'جسم الاستجابة'} — التطبيق يثق بالمضيف القادم من العميل.`, `A poisoned Host/X-Forwarded-Host was reflected into the ${inLocation ? 'Location header' : 'response body'} — the app trusts the client-supplied host.`),
        impact: t('تسميم ذاكرة التخزين، وروابط إعادة تعيين كلمة المرور إلى نطاق المهاجم.', 'Cache poisoning and password-reset links pointing at an attacker host.'),
        remediation: t('استخدم قائمة بيضاء للمضيفين المسموح بهم، ولا تبنِ روابط مطلقة من ترويسة Host.', 'Allow-list permitted hosts; never build absolute URLs from the Host header.'),
        asset: new URL(flow.url).host, location: loc(flow),
        evidence: [{ kind: 'note', label: 'reflected', content: `${inLocation ? 'Location' : 'body'} echoed the injected host` }],
        cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N' },
        idSeed: `${flow.url}|hhi`,
      }, ctx.grantFingerprint));
    }
  }
  return out;
}
