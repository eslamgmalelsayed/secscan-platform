/**
 * Passive JWT analysis (offline, no network). Inspects tokens the owner
 * supplied for their test accounts. Detects the classic, deterministic
 * weaknesses: alg=none acceptance risk, a trivially weak HMAC secret, and a
 * missing expiry. No forging, no attacks — just inspection.
 */
import { createHmac } from 'node:crypto';
import type { Finding } from '@secscan/shared';
import { build, type CheckContext } from './context';

const t = (ar: string, en: string) => ({ ar, en });
const WEAK_SECRETS = ['secret', 'password', 'changeme', '123456', 'jwt', 'key', 'admin', 'test', 'your-256-bit-secret'];

function b64urlDecode(seg: string): string {
  return Buffer.from(seg.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

export function analyzeJwt(token: string, grantFingerprint: string, asset = 'token'): Finding[] {
  const parts = token.split('.');
  if (parts.length !== 3) return [];
  let headerObj: any, payloadObj: any;
  try { headerObj = JSON.parse(b64urlDecode(parts[0])); payloadObj = JSON.parse(b64urlDecode(parts[1])); } catch { return []; }
  const out: Finding[] = [];
  const alg = String(headerObj.alg ?? '').toLowerCase();

  if (alg === 'none') {
    out.push(build({
      category: 'jwt', severity: 'critical', confidence: 'confirmed',
      title: t('توكن JWT بخوارزمية none', 'JWT uses alg=none'),
      description: t('الهيدر alg=none يعني توكن بدون توقيع — يمكن انتحال أي مستخدم.', 'alg=none means an unsigned token — any user can be impersonated.'),
      impact: t('انتحال كامل للهوية.', 'Full identity impersonation.'),
      remediation: t('ارفض none؛ ثبّت الخوارزمية المتوقعة وتحقق من التوقيع.', 'Reject none; pin the expected algorithm and verify the signature.'),
      asset, cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },
      idSeed: `${asset}|jwt-none`,
    }, grantFingerprint));
  }

  if (alg === 'hs256') {
    const signingInput = `${parts[0]}.${parts[1]}`;
    for (const secret of WEAK_SECRETS) {
      const sig = createHmac('sha256', secret).update(signingInput).digest('base64url');
      if (sig === parts[2]) {
        out.push(build({
          category: 'jwt', severity: 'high', confidence: 'confirmed',
          title: t('سر توقيع JWT ضعيف', 'Weak JWT signing secret'),
          description: t('تم التحقق من التوقيع بسر من قائمة شائعة — يمكن تزوير التوكنات.', 'The signature verified against a common-list secret — tokens can be forged.'),
          impact: t('تزوير توكنات صالحة لأي مستخدم/دور.', 'Forging valid tokens for any user/role.'),
          remediation: t('استخدم سرًا عشوائيًا طويلًا (≥256 بت) من مخزن أسرار، ودوّره.', 'Use a long random secret (≥256-bit) from a secret store, and rotate it.'),
          asset, evidence: [{ kind: 'note', label: 'secret', content: '[redacted — from common list]' }],
          cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },
          idSeed: `${asset}|jwt-weak-secret`,
        }, grantFingerprint));
        break;
      }
    }
  }

  if (payloadObj && payloadObj.exp === undefined) {
    out.push(build({
      category: 'jwt', severity: 'low', confidence: 'likely',
      title: t('توكن JWT بلا انتهاء صلاحية', 'JWT has no expiry (exp)'),
      description: t('التوكن لا يحتوي على exp — يبقى صالحًا إلى الأبد إن تسرّب.', 'The token has no exp claim — it stays valid forever if leaked.'),
      impact: t('نافذة استغلال غير محدودة عند التسريب.', 'Unbounded abuse window if leaked.'),
      remediation: t('اضبط exp قصيرًا واستخدم توكنات تجديد.', 'Set a short exp and use refresh tokens.'),
      asset, cvss: { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },
      idSeed: `${asset}|jwt-no-exp`,
    }, grantFingerprint));
  }
  return out;
}

export function jwtChecks(ctx: CheckContext): Finding[] {
  const out: Finding[] = [];
  for (const [i, tok] of (ctx.tokens ?? []).entries()) {
    out.push(...analyzeJwt(tok, ctx.grantFingerprint, `token#${i + 1}`));
  }
  return out;
}
