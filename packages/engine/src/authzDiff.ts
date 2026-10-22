/**
 * Authorization-diffing: the deterministic access-control core (Design §9, §11).
 *
 * A legitimate request captured as a privileged identity A is replayed under
 * identity B (another user / tenant / anonymous). If B reproducibly receives
 * A's privileged response, access control was not enforced. We never craft a
 * payload — we re-send the owner's own authorized traffic, in scope, and
 * compare. A finding requires a denied/anonymous reference (so a public page
 * is not mistaken for a bypass) and deterministic reproduction.
 *
 * Guard against the per-session false positive (review 2.1): an equal body on
 * a request that names NO object (`/api/me`) is "same data", not a bypass.
 * Such a request is never a confirmed bola_idor/cross_tenant. Between two
 * identities of the SAME role it is dropped; across roles it is kept as a
 * `likely` function-level candidate for human review, never auto-reported.
 *
 * Guard against the shared-resource false positive: a request may NAME an
 * object (`/api/products/42`) yet return a resource every authenticated user
 * may legitimately see. Response comparison cannot tell that from a private
 * object A owns — only the owner knows. So an object-access match is confirmed
 * ONLY when the owner has labelled the flow `ownsObject`; otherwise it is kept
 * as `likely` for human review, never auto-reported.
 */
import { Finding, type Confidence, type Severity, controlsFor, cvss31, type Cvss31Metrics } from '@secscan/shared';
import { GuardedClient } from './client';
import type { Identity, RecordedRequest, RecordedResponse } from './http';
import { isAnonymous } from './http';
import { requestHasObjectIdentifier } from './identifier';
import { bodyDigest } from './normalize';

export interface DiffConfig {
  replaysForConfirmation: number;
}
const DEFAULT: DiffConfig = { replaysForConfirmation: 2 };

const CVSS_BY_TYPE: Record<'bola_idor' | 'cross_tenant' | 'missing_auth', Cvss31Metrics> = {
  bola_idor:    { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
  cross_tenant: { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'C', C: 'H', I: 'L', A: 'N' },
  missing_auth: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },
};

export type AccessFindingType = 'bola_idor' | 'cross_tenant' | 'missing_auth';

function looksAuthorized(r: RecordedResponse): boolean {
  return r.status >= 200 && r.status < 300 && r.body.length > 0;
}

function digestOf(r: RecordedResponse): string {
  const ct = r.headers['content-type'] ?? r.headers['Content-Type'] ?? '';
  return bodyDigest(r.body, ct);
}

export class AuthorizationDiffer {
  constructor(
    private client: GuardedClient,
    private grantFingerprint: string,
    private cfg: DiffConfig = DEFAULT,
  ) {}

  private async reproduce(
    req: RecordedRequest,
    ident: Identity,
    baseDigest: string,
  ): Promise<{ matches: number; last: RecordedResponse | null }> {
    let matches = 0;
    let last: RecordedResponse | null = null;
    for (let i = 0; i < this.cfg.replaysForConfirmation; i++) {
      const resp = await this.client.send(req, ident);
      last = resp;
      if (looksAuthorized(resp) && digestOf(resp) === baseDigest) matches++;
      else break; // control held at least once => not a finding
    }
    return { matches, last };
  }

  /** Return a confirmed Finding, or null if access control held / resource is public. */
  async testObjectAccess(
    reqAsOwner: RecordedRequest,
    owner: Identity,
    challenger: Identity,
  ): Promise<Finding | null> {
    const baseline = await this.client.send(reqAsOwner, owner);
    if (!looksAuthorized(baseline)) return null;
    const baseDigest = digestOf(baseline);

    // Is the resource public (anyone gets the owner's response) or gated?
    let anonPublic = false;
    try {
      const anonResp = await this.client.send(reqAsOwner, { role: 'anonymous', sessionRef: null });
      anonPublic = looksAuthorized(anonResp) && digestOf(anonResp) === baseDigest;
    } catch {
      anonPublic = false; // anon refused => resource is gated
    }

    let type: AccessFindingType;
    let severity: Severity;
    let confidence: Confidence = 'confirmed';
    let reviewReason: string | undefined;
    let last: RecordedResponse | null;

    if (isAnonymous(challenger)) {
      if (!reqAsOwner.requiresAuth) return null; // don't guess on public/anon
      const r = await this.reproduce(reqAsOwner, challenger, baseDigest);
      if (r.matches < this.cfg.replaysForConfirmation) return null;
      type = 'missing_auth';
      severity = 'critical';
      last = r.last;
    } else {
      if (anonPublic) return null; // same for everyone => public, not a bypass
      const namesObject = requestHasObjectIdentifier(reqAsOwner);
      // No object in the request + same role: the server can only key on the
      // session, so an equal body is the same data twice. Not a finding.
      if (!namesObject && challenger.role === owner.role) return null;
      const r = await this.reproduce(reqAsOwner, challenger, baseDigest);
      if (r.matches < this.cfg.replaysForConfirmation) return null;
      const crossTenant = !!challenger.tenant && !!owner.tenant && challenger.tenant !== owner.tenant;
      type = crossTenant ? 'cross_tenant' : 'bola_idor';
      severity = crossTenant ? 'critical' : 'high';
      // Confirmed ONLY when the owner has labelled this flow owner-of-object.
      // Without the label we cannot distinguish a private object from a resource
      // every authenticated user may see — the finding goes to human review.
      if (!(namesObject && reqAsOwner.ownsObject)) {
        confidence = 'likely';
        reviewReason = !namesObject
          ? 'request names no object identifier; equal body across roles may be function-level access or identically seeded test accounts'
          : 'request names an object but the flow is not labelled owner-of-object; a resource every authenticated user may legitimately see (e.g. a shared or catalog item) is indistinguishable from a private object by response comparison alone — a human must confirm ownership';
      }
      last = r.last;
    }

    return buildFinding({
      type, severity, confidence, reviewReason, reqAsOwner, owner, challenger, baseline, exploit: last!,
      baseDigest, grantFingerprint: this.grantFingerprint,
    });
  }
}

const TEXT: Record<AccessFindingType, { titleAr: string; titleEn: string; impAr: string; impEn: string }> = {
  bola_idor: {
    titleAr: 'تجاوز صلاحيات على مستوى الكائن (IDOR/BOLA)',
    titleEn: 'Broken object-level authorization (IDOR/BOLA)',
    impAr: 'مستخدم يقدر يوصل لبيانات مستخدم آخر.',
    impEn: "A user can access another user's data.",
  },
  cross_tenant: {
    titleAr: 'تسرّب بين المستأجرين (cross-tenant)',
    titleEn: 'Cross-tenant data access',
    impAr: 'عزل البيانات بين العملاء غير مطبّق.',
    impEn: 'Tenant data isolation is not enforced.',
  },
  missing_auth: {
    titleAr: 'غياب المصادقة على مورد محمي',
    titleEn: 'Missing authentication on a protected resource',
    impAr: 'مورد يُفترض أن يكون محمياً متاح بدون تسجيل دخول.',
    impEn: 'A resource meant to be protected is reachable without logging in.',
  },
};

function buildFinding(a: {
  type: AccessFindingType; severity: Severity; confidence: Confidence; reviewReason?: string;
  reqAsOwner: RecordedRequest; owner: Identity; challenger: Identity; baseline: RecordedResponse;
  exploit: RecordedResponse; baseDigest: string; grantFingerprint: string;
}): Finding {
  const t = TEXT[a.type];
  const idSuffix = a.baseDigest.slice(0, 8);
  const who = (i: Identity) =>
    isAnonymous(i) ? (i.role === 'anonymous' ? 'anonymous' : i.role) : `${i.role}${i.tenant ? '/' + i.tenant : ''}`;
  return Finding.parse({
    id: `AC-${a.type}-${idSuffix}`,
    title: { ar: t.titleAr, en: t.titleEn },
    severity: a.severity,
    confidence: a.confidence,
    asset: new URL(a.reqAsOwner.url).host,
    location: `${a.reqAsOwner.method} ${new URL(a.reqAsOwner.url).pathname}`,
    description: {
      ar: `طلب مصرّح به لـ ${who(a.owner)} رجع نفس الاستجابة المميزة عند إعادته كـ ${who(a.challenger)}، وتكرر النتيجة. لم تُطبَّق صلاحيات الوصول على هذا المورد.`,
      en: `A request authorized for ${who(a.owner)} returned the same privileged response when replayed as ${who(a.challenger)}, reproducibly. Access control was not enforced on this resource.`,
    },
    impact: { ar: t.impAr, en: t.impEn },
    remediation: {
      ar: 'طبّق التحقق من الصلاحيات في الخادم لكل طلب: تأكد أن صاحب الجلسة يملك أو يُسمح له بالمورد المطلوب، ولا تعتمد على العميل في تحديد المعرّف.',
      en: 'Enforce authorization server-side on every request: verify the authenticated principal owns or may access the requested object; never rely on the client to scope the id.',
    },
    evidence: [
      { kind: 'request', label: 'authorized baseline', content: `${a.reqAsOwner.method} ${a.reqAsOwner.url} as ${who(a.owner)} -> ${a.baseline.status}` },
      { kind: 'response', label: 'baseline body sha256', content: a.baseDigest },
      { kind: 'request', label: 'replayed as challenger', content: `${a.reqAsOwner.method} ${a.reqAsOwner.url} as ${who(a.challenger)} -> ${a.exploit.status}` },
      { kind: 'note', label: 'grant', content: `fingerprint ${a.grantFingerprint.slice(0, 16)}…` },
      ...(a.confidence !== 'confirmed'
        ? [{ kind: 'note' as const, label: 'review', content: a.reviewReason ?? 'equal body across identities needs human confirmation of ownership' }]
        : []),
    ],
    cvss: cvss31(CVSS_BY_TYPE[a.type]),
    controls: controlsFor(a.type === 'missing_auth' ? 'missing_auth' : 'access_control'),
    source: 'engine/authz-diff',
    firstSeen: new Date().toISOString(),
  });
}
