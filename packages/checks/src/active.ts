/**
 * Active checks — DETECTION ONLY, non-destructive by construction.
 *
 * These send probes against recorded, in-scope flows through the guarded
 * client, using benign markers and read-only differentials. They DETECT that
 * input is mishandled and prove it to the owner so they can fix it. They do
 * NOT ship exploit payloads, do NOT exfiltrate data (no UNION dumping), and do
 * NOT perform destructive operations. Heavy exploitation tooling (sqlmap-style)
 * is out of scope here by design (spec §4: separate engine doc with a partner).
 */
import { randomBytes } from 'node:crypto';
import type { Finding } from '@secscan/shared';
import { bodyDigest, type RecordedRequest } from '@secscan/engine';
import { build, header, identityFor, safeSend, type CheckContext } from './context';

const t = (ar: string, en: string) => ({ ar, en });

function withParam(url: string, name: string, value: string): string {
  const u = new URL(url);
  u.searchParams.set(name, value);
  return u.toString();
}
function digest(resp: { body: string; headers: Record<string, string> }): string {
  const ct = resp.headers['content-type'] ?? resp.headers['Content-Type'] ?? '';
  return bodyDigest(resp.body, ct);
}

/** The characters that must be encoded in HTML. Appended to the marker so an
 *  encoded reflection (`&lt;`) can be told from a raw one. No script, no tag:
 *  a canary, not a payload. */
const HTML_SPECIALS = '<"\'>';

/** Reflected input (potential XSS). Reported only when the HTML specials come
 *  back RAW; an encoded reflection is correct behaviour and is not a finding.
 *  Reflection is necessary-but-not-sufficient for XSS, so always needs_review. */
export async function reflectedInput(ctx: CheckContext): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const flow of ctx.flows) {
    if (flow.method.toUpperCase() !== 'GET') continue;
    let params: URLSearchParams;
    try { params = new URL(flow.url).searchParams; } catch { continue; }
    for (const [name] of params) {
      const marker = 'sxz' + randomBytes(4).toString('hex');
      const probe: RecordedRequest = { ...flow, url: withParam(flow.url, name, marker + HTML_SPECIALS) };
      const resp = await safeSend(ctx, probe, identityFor(ctx, flow));
      if (!resp) continue;
      const ct = (header(resp, 'content-type') ?? '').toLowerCase();
      if (resp.body.includes(marker + HTML_SPECIALS) && ct.includes('html')) {
        out.push(build({
          category: 'xss', severity: 'medium', confidence: 'needs_review',
          title: t(`إدخال منعكس بدون ترميز في '${name}'`, `Input reflected unescaped in '${name}'`),
          description: t('علامة حميدة ظهرت حرفيًا في استجابة HTML — مرشّح لـ reflected XSS، يحتاج تأكيد السياق.', 'A benign marker appeared verbatim in an HTML response — a reflected-XSS candidate; needs context confirmation.'),
          impact: t('احتمال تنفيذ سكربت في متصفح الضحية.', 'Possible script execution in a victim browser.'),
          remediation: t('رمّز المخرجات حسب السياق واستخدم CSP صارم.', 'Context-encode output and apply a strict CSP.'),
          asset: new URL(flow.url).host, location: `${flow.method} ${new URL(flow.url).pathname}`,
          evidence: [
            { kind: 'request', label: 'reflected param', content: name },
            { kind: 'note', label: 'encoding', content: 'HTML specials < " \' > returned unencoded' },
          ],
          cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'L', I: 'L', A: 'N' },
          idSeed: `${flow.url}|refl|${name}`,
        }, ctx.grantFingerprint));
      }
    }
  }
  return out;
}

const SQL_ERRORS = [
  'you have an error in your sql syntax', 'warning: mysql', 'unclosed quotation mark',
  'quoted string not properly terminated', 'sqlite3.operationalerror', 'pg::syntaxerror',
  'ora-00933', 'odbc sql server driver',
];
const SQLI_TRUE = "' AND '1'='1";
const SQLI_FALSE = "' AND '1'='2";

/** SQL injection — read-only differential + error signatures. Reproduced
 *  boolean difference => confirmed; an error signature => likely (review). */
export async function sqliDifferential(ctx: CheckContext): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const flow of ctx.flows) {
    if (flow.method.toUpperCase() !== 'GET') continue;
    let entries: [string, string][];
    try { entries = [...new URL(flow.url).searchParams.entries()]; } catch { continue; }
    const as = identityFor(ctx, flow);
    const baseline = await safeSend(ctx, flow, as); // one baseline per flow, not per param
    if (!baseline) continue;
    const baseDigest = digest(baseline);
    for (const [name, baseVal] of entries) {
      // error-based
      const errResp = await safeSend(ctx, { ...flow, url: withParam(flow.url, name, baseVal + "'") }, as);
      if (errResp && SQL_ERRORS.some((s) => errResp.body.toLowerCase().includes(s))) {
        out.push(build({
          category: 'injection', severity: 'high', confidence: 'likely',
          title: t(`خطأ SQL ظهر عبر '${name}'`, `SQL error provoked via '${name}'`),
          description: t("إضافة علامة اقتباس لـ '" + name + "' أظهرت توقيع خطأ قاعدة بيانات.", `Appending a quote to '${name}' surfaced a database error signature.`),
          impact: t('احتمال حقن SQL يؤدي لقراءة/تعديل بيانات.', 'Possible SQL injection leading to data read/modification.'),
          remediation: t('استخدم استعلامات مُعاملة (prepared statements) ولا تدمج الإدخال في SQL.', 'Use parameterized queries; never concatenate input into SQL.'),
          asset: new URL(flow.url).host, location: `${flow.method} ${new URL(flow.url).pathname}`,
          evidence: [{ kind: 'response', label: 'db error', content: 'SQL error signature present' }],
          cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },
          idSeed: `${flow.url}|sqli-err|${name}`,
        }, ctx.grantFingerprint));
        continue;
      }

      // boolean-based, reproduced twice
      let matches = 0;
      for (let i = 0; i < 2; i++) {
        const tResp = await safeSend(ctx, { ...flow, url: withParam(flow.url, name, baseVal + SQLI_TRUE) }, as);
        const fResp = await safeSend(ctx, { ...flow, url: withParam(flow.url, name, baseVal + SQLI_FALSE) }, as);
        if (!tResp || !fResp) break;
        if (digest(tResp) === baseDigest && digest(fResp) !== baseDigest) matches++;
        else break;
      }
      if (matches === 2) {
        out.push(build({
          category: 'injection', severity: 'critical', confidence: 'confirmed',
          title: t(`حقن SQL منطقي (boolean) في '${name}'`, `Boolean-based SQL injection in '${name}'`),
          description: t('شرط TRUE أعاد استجابة الأساس وFALSE غيّرها، وتكرر — البارامتر يُفسَّر كـ SQL.', 'A TRUE condition returned the baseline and FALSE changed it, reproducibly — the parameter is interpreted as SQL.'),
          impact: t('قراءة/تعديل بيانات قاعدة البيانات.', 'Read/modify database data.'),
          remediation: t('استخدم استعلامات مُعاملة، وتحقق من المدخلات، وأقل صلاحية لحساب القاعدة.', 'Use parameterized queries, validate input, least-privilege the DB account.'),
          asset: new URL(flow.url).host, location: `${flow.method} ${new URL(flow.url).pathname}`,
          evidence: [
            { kind: 'note', label: 'true-condition', content: 'matched baseline (reproduced x2)' },
            { kind: 'note', label: 'false-condition', content: 'diverged from baseline (reproduced x2)' },
          ],
          cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'L' },
          idSeed: `${flow.url}|sqli-bool|${name}`,
        }, ctx.grantFingerprint));
      }
    }
  }
  return out;
}
