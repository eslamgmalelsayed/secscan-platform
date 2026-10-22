/**
 * Business-logic & API-hardening checks — detection, non-destructive.
 *
 * GraphQL introspection, missing CSRF token, and missing rate limiting are
 * read-only GET probes. Mass assignment is the one WRITE-based check: it resends
 * a recorded state-changing request with an extra privileged field. It is gated
 * by the engine itself — the GuardedClient refuses any state-changing request
 * unless the grant sets `allowStateChanging` (staging), so on a normal grant the
 * write never leaves the process and the check silently finds nothing. No check
 * here ships an exploit payload, exfiltrates data, or damages state.
 */
import type { Finding } from '@secscan/shared';
import type { RecordedRequest } from '@secscan/engine';
import { build, header, identityFor, safeSend, type CheckContext } from './context';

const t = (ar: string, en: string) => ({ ar, en });
const loc = (f: RecordedRequest) => `${f.method} ${new URL(f.url).pathname}`;

/** GraphQL introspection enabled: the endpoint answers an __schema query. */
const GQL_PATHS = ['/graphql', '/api/graphql', '/v1/graphql'];
export async function graphqlIntrospection(ctx: CheckContext): Promise<Finding[]> {
  const out: Finding[] = [];
  const seen = new Set<string>();
  const candidates: { url: string; flow?: RecordedRequest }[] = [];
  for (const f of ctx.flows) if (/graphql/i.test(new URL(f.url).pathname)) candidates.push({ url: f.url, flow: f });
  try { const r = new URL(ctx.rootUrl); for (const p of GQL_PATHS) candidates.push({ url: `${r.origin}${p}` }); } catch { /* bad root */ }

  for (const c of candidates) {
    const u = new URL(c.url);
    if (seen.has(u.pathname)) continue; seen.add(u.pathname);
    const probe = `${u.origin}${u.pathname}?query=${encodeURIComponent('{__schema{queryType{name}}}')}`;
    const resp = await safeSend(ctx, { method: 'GET', url: probe }, c.flow ? identityFor(ctx, c.flow) : undefined);
    if (!resp || resp.status < 200 || resp.status >= 300) continue;
    if (/__schema|"queryType"/.test(resp.body)) {
      out.push(build({
        category: 'info_disclosure', severity: 'medium', confidence: 'confirmed',
        title: t('استعلام بنية GraphQL مفعّل (introspection)', 'GraphQL introspection enabled'),
        description: t('نقطة GraphQL ردّت على استعلام __schema فكشفت المخطط كاملًا.', 'The GraphQL endpoint answered an __schema query, exposing the full schema.'),
        impact: t('كشف كل الأنواع والحقول والعمليات يسهّل بناء الهجمات.', 'Full type/field/operation disclosure eases attack construction.'),
        remediation: t('عطّل introspection في الإنتاج وافرض حدود عمق/تعقيد الاستعلام.', 'Disable introspection in production; enforce query depth/complexity limits.'),
        asset: u.host, location: `GET ${u.pathname}`,
        evidence: [{ kind: 'response', label: 'introspection', content: '__schema / queryType returned' }],
        cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
        idSeed: `${u.origin}${u.pathname}|gql-introspection`,
      }, ctx.grantFingerprint));
    }
  }
  return out;
}

/** A POST form served without an anti-CSRF token field. */
const FORM_RE = /<form\b[^>]*>[\s\S]*?<\/form>/gi;
const TOKEN_RE = /(csrf|xsrf|_token|authenticity_token|requestverificationtoken)/i;
export async function csrfToken(ctx: CheckContext): Promise<Finding[]> {
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const f of ctx.flows) {
    if (f.method.toUpperCase() !== 'GET') continue;
    const key = new URL(f.url).pathname;
    if (seen.has(key)) continue; seen.add(key);
    const resp = await safeSend(ctx, f, identityFor(ctx, f));
    if (!resp) continue;
    if (!(header(resp, 'content-type') ?? '').toLowerCase().includes('html')) continue;
    for (const m of resp.body.match(FORM_RE) ?? []) {
      if (/method\s*=\s*["']?\s*post/i.test(m) && !TOKEN_RE.test(m)) {
        out.push(build({
          category: 'csrf', severity: 'medium', confidence: 'likely',
          title: t('نموذج POST بلا رمز CSRF', 'POST form without an anti-CSRF token'),
          description: t('نموذج يرسل POST لا يحتوي حقل رمز CSRF — قد تُزوَّر الطلبات عبر المواقع.', 'A POST form carries no anti-CSRF token field — requests may be forged cross-site.'),
          impact: t('تنفيذ إجراءات نيابة عن المستخدم دون علمه.', 'Actions performed on behalf of a user without their intent.'),
          remediation: t('أضف رمز CSRF لكل نموذج مغيّر للحالة واضبط كوكيز SameSite.', 'Add a per-form CSRF token for state-changing requests; set SameSite cookies.'),
          asset: new URL(f.url).host, location: loc(f),
          evidence: [{ kind: 'note', label: 'form', content: 'POST form with no csrf/xsrf/_token field' }],
          cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'N', I: 'H', A: 'N' },
          idSeed: `${f.url}|csrf`,
        }, ctx.grantFingerprint));
        break;
      }
    }
  }
  return out;
}

/** Missing rate limiting: a short bounded burst is never throttled (429 / limit
 *  headers). Bounded to a few endpoints; a `likely` signal for human review. */
export async function rateLimitAbsence(ctx: CheckContext): Promise<Finding[]> {
  const out: Finding[] = [];
  const tested = new Set<string>();
  const BURST = 8;
  for (const f of ctx.flows) {
    if (f.method.toUpperCase() !== 'GET') continue;
    const key = new URL(f.url).pathname;
    if (tested.has(key)) continue; tested.add(key);
    if (tested.size > 1) break; // keep it quiet and fast: one endpoint
    const as = identityFor(ctx, f);
    let ok = 0, throttled = false;
    for (let i = 0; i < BURST; i++) {
      const r = await safeSend(ctx, f, as);
      if (!r) { throttled = true; break; }
      if (r.status === 429 || header(r, 'retry-after') || header(r, 'x-ratelimit-remaining')) { throttled = true; break; }
      if (r.status >= 200 && r.status < 400) ok++;
    }
    if (!throttled && ok === BURST) {
      out.push(build({
        category: 'rate_limit', severity: 'low', confidence: 'needs_review',
        title: t('غياب تحديد المعدّل', 'Missing rate limiting'),
        description: t(`${BURST} طلبات متتالية لم تُقيَّد (لا 429 ولا ترويسات حد) — قد تكون النقطة عرضة للإساءة.`, `${BURST} rapid requests were never throttled (no 429 or limit headers) — the endpoint may be abuse-prone.`),
        impact: t('إساءة استخدام، تخمين، وحرمان خدمة عبر الحجم.', 'Abuse, brute forcing, and volumetric denial of service.'),
        remediation: t('طبّق تحديد معدّل لكل عميل/نقطة، خصوصًا على المصادقة والعمليات المكلفة.', 'Apply per-client/per-endpoint rate limits, especially on auth and expensive operations.'),
        asset: new URL(f.url).host, location: loc(f),
        evidence: [{ kind: 'note', label: 'burst', content: `${BURST}/${BURST} requests returned 2xx–3xx, none throttled` }],
        cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'L' },
        idSeed: `${f.url}|rate-limit`,
      }, ctx.grantFingerprint));
    }
  }
  return out;
}

/** Mass assignment (WRITE-based, gated by the scope guard). Resends a recorded
 *  state-changing request with extra privileged fields; if the response shows
 *  them accepted, the server binds client input to privileged attributes. */
const PRIV = { isAdmin: true, is_admin: true, role: 'admin' } as const;
const ACCEPTED_RE = /"isadmin"\s*:\s*true|"is_admin"\s*:\s*true|"role"\s*:\s*"admin"/i;
export async function massAssignment(ctx: CheckContext): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const f of ctx.flows) {
    if (!['POST', 'PUT', 'PATCH'].includes(f.method.toUpperCase()) || !f.body) continue;
    let obj: unknown;
    try { obj = JSON.parse(f.body); } catch { continue; }
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) continue;
    if (ACCEPTED_RE.test(f.body)) continue; // already contains such a field; can't attribute
    const probe: RecordedRequest = { ...f, body: JSON.stringify({ ...(obj as object), ...PRIV }) };
    const resp = await safeSend(ctx, probe, identityFor(ctx, f)); // gated: refused unless grant allows state-changing
    if (!resp || resp.status < 200 || resp.status >= 300) continue;
    if (ACCEPTED_RE.test(resp.body)) {
      out.push(build({
        category: 'mass_assignment', severity: 'high', confidence: 'confirmed',
        title: t('ربط جماعي للخصائص (mass assignment)', 'Mass assignment of privileged fields'),
        description: t('إرسال حقل ذي صلاحية إضافي (isAdmin/role) قُبِل وظهر في الكائن المُنشأ — الخادم يربط إدخال العميل بخصائص محمية.', 'An extra privileged field (isAdmin/role) was accepted and reflected in the created object — the server binds client input to protected attributes.'),
        impact: t('تصعيد صلاحيات بتعيين حقول لا يُفترض أن يتحكّم بها العميل.', 'Privilege escalation by setting fields the client should not control.'),
        remediation: t('استخدم قوائم سماح صريحة للحقول القابلة للكتابة (allow-list)، لا قوائم منع.', 'Bind only an explicit allow-list of writable fields; never a deny-list.'),
        asset: new URL(f.url).host, location: loc(f),
        evidence: [{ kind: 'note', label: 'accepted', content: 'injected privileged field reflected as accepted' }],
        cvss: { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },
        idSeed: `${f.url}|mass-assignment`,
      }, ctx.grantFingerprint));
    }
  }
  return out;
}
