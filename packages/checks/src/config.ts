/**
 * Safe, deterministic configuration checks on recorded flows (non-destructive):
 *   CORS misconfiguration  — reflect an arbitrary Origin with credentials
 *   Open redirect          — a canary external host echoed into Location
 * Both send one benign probe through the guarded client; no payloads.
 */
import type { Finding } from '@secscan/shared';
import type { RecordedRequest } from '@secscan/engine';
import { build, header, safeSend, type CheckContext } from './context';

const t = (ar: string, en: string) => ({ ar, en });
const CANARY = 'https://secscan-canary.example';
const REDIRECT_PARAMS = new Set(['next', 'url', 'redirect', 'return', 'returnurl', 'dest', 'destination', 'continue', 'r', 'u']);

function withParam(url: string, name: string, value: string): string {
  const u = new URL(url);
  u.searchParams.set(name, value);
  return u.toString();
}

export async function corsMisconfig(ctx: CheckContext): Promise<Finding[]> {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const flow of ctx.flows) {
    if (seen.has(flow.url)) continue;
    seen.add(flow.url);
    const probe: RecordedRequest = { ...flow, headers: { ...(flow.headers ?? {}), origin: CANARY } };
    const resp = await safeSend(ctx, probe);
    if (!resp) continue;
    const acao = (header(resp, 'access-control-allow-origin') ?? '').trim();
    const acac = (header(resp, 'access-control-allow-credentials') ?? '').toLowerCase();
    if (acao === CANARY && acac === 'true') {
      out.push(build({
        category: 'cors', severity: 'high', confidence: 'confirmed',
        title: t('إعداد CORS يعكس أي أصل مع الاعتمادات', 'CORS reflects arbitrary origin with credentials'),
        description: t('النقطة تعكس Origin عشوائيًا في ACAO مع السماح بالاعتمادات — أي موقع يقرأ استجابات مصادَق عليها.', 'The endpoint reflects an arbitrary Origin into ACAO while allowing credentials — any site can read authenticated responses.'),
        impact: t('سرقة بيانات المستخدم المصادَق عبر موقع خبيث.', "Theft of the authenticated user's data via a malicious site."),
        remediation: t('اعكس قائمة أصول موثوقة فقط، ولا تجمع أبدًا أصلًا منعكسًا مع الاعتمادات.', 'Reflect only an allow-list of trusted origins; never pair a reflected origin with credentials.'),
        asset: new URL(flow.url).host, location: `${flow.method} ${new URL(flow.url).pathname}`,
        evidence: [{ kind: 'response', label: 'ACAO/ACAC', content: `${acao} / ${acac}` }],
        cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'H', I: 'L', A: 'N' },
        idSeed: `${flow.url}|cors`,
      }, ctx.grantFingerprint));
    }
  }
  return out;
}

export async function openRedirect(ctx: CheckContext): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const flow of ctx.flows) {
    if (flow.method.toUpperCase() !== 'GET') continue;
    let params: URLSearchParams;
    try { params = new URL(flow.url).searchParams; } catch { continue; }
    for (const [name] of params) {
      if (!REDIRECT_PARAMS.has(name.toLowerCase())) continue;
      const probe: RecordedRequest = { ...flow, url: withParam(flow.url, name, `${CANARY}/benign`) };
      const resp = await safeSend(ctx, probe);
      if (!resp) continue;
      const loc = (header(resp, 'location') ?? '').toLowerCase();
      if (resp.status >= 300 && resp.status < 400 && loc.startsWith(CANARY.toLowerCase())) {
        out.push(build({
          category: 'open_redirect', severity: 'medium', confidence: 'confirmed',
          title: t(`إعادة توجيه مفتوحة عبر '${name}'`, `Open redirect via '${name}'`),
          description: t(`'${name}' يُعكس في هيدر Location لإعادة توجيه لمضيف خارجي دون تحقق.`, `'${name}' is reflected into the Location header, redirecting to an external host unchecked.`),
          impact: t('تصيّد وتجاوز الثقة عبر نطاقك.', 'Phishing and trust abuse via your domain.'),
          remediation: t('اسمح بوجهات من قائمة بيضاء أو مسارات نسبية فقط.', 'Allow-list redirect destinations or use relative paths only.'),
          asset: new URL(flow.url).host, location: `${flow.method} ${new URL(flow.url).pathname}`,
          evidence: [{ kind: 'response', label: 'Location', content: loc }],
          cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N' },
          idSeed: `${flow.url}|open-redirect|${name}`,
        }, ctx.grantFingerprint));
      }
    }
  }
  return out;
}
