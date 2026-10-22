/**
 * Static mobile-app analysis — non-destructive, offline. Parses the contents of
 * an APK/IPA (already extracted by the caller) and flags client-side weaknesses:
 * hardcoded secrets, cleartext-traffic allowance, exported components, and the
 * backend endpoints the app talks to (so the server can then be scanned).
 *
 * The caller extracts the archive and passes { name, content } entries; this
 * module never executes code, never touches a device, and never phones home.
 * (The app's BACKEND is covered by the normal web/API scan once its endpoints,
 * surfaced here, are imported.)
 */
import type { Finding } from '@secscan/shared';
import { cvss31, controlsFor, Finding as FindingSchema } from '@secscan/shared';
import { createHash } from 'node:crypto';

export interface MobileEntry { name: string; content: string }
export interface MobileReport { findings: Finding[]; endpoints: string[] }

const t = (ar: string, en: string) => ({ ar, en });

// Reused secret shapes (same spirit as the response secret scan).
const SECRET_RES: { re: RegExp; what: string }[] = [
  { re: /AKIA[0-9A-Z]{16}/, what: 'AWS access key id' },
  { re: /AIza[0-9A-Za-z\-_]{35}/, what: 'Google API key' },
  { re: /sk_live_[0-9A-Za-z]{24,}/, what: 'Stripe live secret key' },
  { re: /gh[pousr]_[0-9A-Za-z]{36,}/, what: 'GitHub token' },
  { re: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, what: 'private key' },
  { re: /xox[baprs]-[0-9A-Za-z-]{10,}/, what: 'Slack token' },
];
const URL_RE = /https?:\/\/[A-Za-z0-9.\-]+(?::\d+)?(?:\/[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]*)?/g;

function mk(args: { category: Parameters<typeof controlsFor>[0]; severity: 'critical' | 'high' | 'medium' | 'low'; confidence: 'confirmed' | 'likely' | 'needs_review'; title: { ar: string; en: string }; description: { ar: string; en: string }; impact: { ar: string; en: string }; remediation: { ar: string; en: string }; location: string; evidence: { kind: 'note'; label: string; content: string }[]; cvss: Parameters<typeof cvss31>[0]; idSeed: string }): Finding {
  return FindingSchema.parse({
    id: `MOB-${args.category}-${createHash('sha256').update(args.idSeed).digest('hex').slice(0, 8)}`,
    title: args.title, severity: args.severity, confidence: args.confidence,
    asset: 'mobile-app', location: args.location,
    description: args.description, impact: args.impact, remediation: args.remediation,
    evidence: args.evidence, cvss: cvss31(args.cvss), controls: controlsFor(args.category),
    source: 'checks/mobile', firstSeen: new Date().toISOString(),
  });
}

export function analyzeMobileArtifact(entries: MobileEntry[]): MobileReport {
  const findings: Finding[] = [];
  const endpoints = new Set<string>();
  const secretsSeen = new Set<string>();

  for (const e of entries) {
    const text = e.content;
    for (const s of SECRET_RES) {
      if (s.re.test(text) && !secretsSeen.has(s.what + e.name)) {
        secretsSeen.add(s.what + e.name);
        findings.push(mk({
          category: 'secret_exposure', severity: 'high', confidence: 'likely',
          title: t(`سر مضمّن في التطبيق: ${s.what}`, `Hardcoded secret in the app: ${s.what}`),
          description: t(`عُثر على ${s.what} داخل ${e.name} — الأسرار المضمّنة قابلة للاستخراج من الحزمة.`, `A ${s.what} was found inside ${e.name} — embedded secrets are extractable from the package.`),
          impact: t('استخدام المفتاح خارج التطبيق وإساءة الخدمات المرتبطة.', 'Off-device key use and abuse of the backing services.'),
          remediation: t('انقل الأسرار للخادم، وأصدر رموزًا قصيرة الأجل للعميل.', 'Move secrets server-side; issue short-lived tokens to the client.'),
          location: e.name, evidence: [{ kind: 'note', label: 'match', content: s.what }],
          cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' }, idSeed: `${e.name}|${s.what}`,
        }));
      }
    }
    // cleartext traffic allowed (Android manifest / network security config)
    if (/usesCleartextTraffic\s*=\s*"true"|cleartextTrafficPermitted\s*=\s*"true"|<key>NSAllowsArbitraryLoads<\/key>\s*<true\/>/i.test(text)) {
      findings.push(mk({
        category: 'tls', severity: 'medium', confidence: 'confirmed',
        title: t('السماح بحركة مرور نصية (cleartext)', 'Cleartext traffic allowed'),
        description: t(`${e.name} يسمح بـ HTTP نصي — حركة التطبيق قابلة للاعتراض والتعديل.`, `${e.name} permits cleartext HTTP — app traffic is interceptable and tamperable.`),
        impact: t('اعتراض بيانات ووسيط في المنتصف على شبكات غير موثوقة.', 'Interception and man-in-the-middle on untrusted networks.'),
        remediation: t('امنع cleartext واطلب HTTPS لكل الوجهات (ATS / network security config).', 'Disallow cleartext and require HTTPS everywhere (ATS / network security config).'),
        location: e.name, evidence: [{ kind: 'note', label: 'config', content: 'cleartext traffic permitted' }],
        cvss: { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' }, idSeed: `${e.name}|cleartext`,
      }));
    }
    // exported components without permission (Android)
    for (const m of text.matchAll(/<(activity|service|receiver|provider)\b[^>]*android:exported\s*=\s*"true"[^>]*>/gi)) {
      if (!/android:permission/i.test(m[0])) {
        findings.push(mk({
          category: 'access_control', severity: 'medium', confidence: 'likely',
          title: t(`مكوّن مُصدَّر بلا إذن (${m[1]})`, `Exported ${m[1]} without a permission`),
          description: t('مكوّن قابل للاستدعاء من تطبيقات أخرى دون حماية بإذن.', 'A component callable by other apps with no permission guard.'),
          impact: t('استدعاء وظائف داخلية من تطبيق خبيث على الجهاز.', 'Invocation of internal functions by a malicious on-device app.'),
          remediation: t('اضبط exported=false أو احمِ المكوّن بإذن بمستوى توقيع.', 'Set exported=false or guard the component with a signature-level permission.'),
          location: e.name, evidence: [{ kind: 'note', label: 'component', content: m[1] }],
          cvss: { AV: 'L', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'N' }, idSeed: `${e.name}|exported|${m[1]}`,
        }));
      }
    }
    for (const u of text.match(URL_RE) ?? []) {
      try { const h = new URL(u).host; if (!/schemas\.android\.com|w3\.org|apache\.org|example\.com/i.test(h)) endpoints.add(`${new URL(u).protocol}//${h}`); } catch { /* skip */ }
    }
  }
  return { findings, endpoints: [...endpoints].sort() };
}
