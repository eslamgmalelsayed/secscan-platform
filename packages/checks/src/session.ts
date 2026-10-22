/**
 * Session-token strength — non-destructive, read-only.
 *
 * Reads Set-Cookie on the root and recorded flows, finds session-like cookies,
 * and measures the token: too short or too low-entropy means it is guessable
 * (a session-prediction / fixation risk). We never brute-force or hijack — we
 * only measure what the server already sent us.
 */
import type { Finding } from '@secscan/shared';
import { build, header, identityFor, safeSend, type CheckContext } from './context';
import { fetchRoot } from './passive';

const t = (ar: string, en: string) => ({ ar, en });
const SESSION_NAMES = /^(sid|sess|session|sessionid|jsessionid|phpsessid|asp\.net_sessionid|connect\.sid|auth|token)$/i;

/** Shannon entropy in bits per character. */
function entropyPerChar(s: string): number {
  if (!s.length) return 0;
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

function setCookies(resp: { headers: Record<string, string> }): string[] {
  // sender normalizes multiple Set-Cookie into one newline-joined value
  const raw = header(resp as any, 'set-cookie');
  return raw ? raw.split('\n') : [];
}

/** A session cookie is weak when its value is short or low-entropy. */
export async function weakSessionToken(ctx: CheckContext): Promise<Finding[]> {
  const out: Finding[] = [];
  const seen = new Set<string>();
  const responses = [await fetchRoot(ctx)];
  for (const f of ctx.flows.slice(0, 8)) responses.push(await safeSend(ctx, f, identityFor(ctx, f)));

  for (const resp of responses) {
    if (!resp) continue;
    for (const c of setCookies(resp)) {
      const [pair] = c.split(';');
      const eq = pair.indexOf('=');
      if (eq < 0) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      if (!SESSION_NAMES.test(name) || !value) continue;
      if (seen.has(name)) continue; seen.add(name);

      const bits = entropyPerChar(value) * value.length;
      const weak = value.length < 16 || bits < 64 || /^\d+$/.test(value);
      if (weak) {
        out.push(build({
          category: 'insecure_cookie', severity: 'high', confidence: 'likely',
          title: t(`رمز جلسة ضعيف في الكوكي '${name}'`, `Weak session token in cookie '${name}'`),
          description: t(`قيمة الكوكي قصيرة أو منخفضة العشوائية (~${Math.round(bits)} bit)، فقد تكون قابلة للتخمين.`, `The cookie value is short or low-entropy (~${Math.round(bits)} bits), so it may be guessable.`),
          impact: t('اختطاف الجلسة بتخمين أو تثبيت المعرّف.', 'Session hijacking by guessing or fixing the identifier.'),
          remediation: t('استخدم ≥128 bit عشوائية آمنة تشفيريًا، وجدّد المعرّف عند تسجيل الدخول.', 'Use ≥128 bits of CSPRNG randomness and regenerate the id on login.'),
          asset: ctx.rootUrl ? new URL(ctx.rootUrl).host : 'target',
          evidence: [{ kind: 'note', label: 'token', content: `name=${name} length=${value.length} entropy≈${Math.round(bits)} bits` }],
          cvss: { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },
          idSeed: `${ctx.rootUrl}|weak-session|${name}`,
        }, ctx.grantFingerprint));
      }
    }
  }
  return out;
}
