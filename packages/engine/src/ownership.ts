/**
 * Automatic ownership verification (Design §3.1, §6; review 2.3).
 *
 * A grant names a proof method and a token. Verification succeeds only when
 * the token is found where only the site's controller could have put it:
 *   dns_txt    — a TXT record `secscan-verify=<token>` on `_secscan.<host>` or `<host>`
 *   http_token — `<scheme>://<host>/.well-known/secscan-verify.txt` contains the token
 *   meta_tag   — the root page contains `<meta name="secscan-verify" content="<token>">`
 * Every target in the grant must pass. Network calls are injectable for tests.
 */
import { promises as dns } from 'node:dns';
import type { AuthorizationGrant, Target } from './authorization';

export interface OwnershipDeps {
  resolveTxt?: (name: string) => Promise<string[][]>;
  fetchText?: (url: string) => Promise<{ status: number; body: string }>;
}

export interface OwnershipResult {
  ok: boolean;
  /** One line per target: what was checked and what was found. Never includes the token. */
  detail: string[];
}

const WELL_KNOWN = '/.well-known/secscan-verify.txt';

async function defaultFetchText(url: string): Promise<{ status: number; body: string }> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 10_000);
  try {
    const r = await fetch(url, { redirect: 'manual', signal: ctrl.signal, headers: { 'user-agent': 'secscan-ownership/0.1' } });
    return { status: r.status, body: (await r.text()).slice(0, 200_000) };
  } finally {
    clearTimeout(t);
  }
}

export async function verifyOwnership(grant: AuthorizationGrant, deps: OwnershipDeps = {}): Promise<OwnershipResult> {
  const resolveTxt = deps.resolveTxt ?? ((n) => dns.resolveTxt(n));
  const fetchText = deps.fetchText ?? defaultFetchText;
  const detail: string[] = [];
  let ok = true;

  for (const t of grant.targets) {
    const r = await verifyTarget(t, grant.ownershipProof, grant.ownershipToken, resolveTxt, fetchText);
    detail.push(`${t.host}: ${grant.ownershipProof} ${r.ok ? 'verified' : 'NOT verified'} (${r.where})`);
    if (!r.ok) ok = false;
  }
  return { ok, detail };
}

async function verifyTarget(
  t: Target, proof: AuthorizationGrant['ownershipProof'], token: string,
  resolveTxt: NonNullable<OwnershipDeps['resolveTxt']>, fetchText: NonNullable<OwnershipDeps['fetchText']>,
): Promise<{ ok: boolean; where: string }> {
  const origin = `${t.scheme}://${t.host}${t.port ? `:${t.port}` : ''}`;
  try {
    if (proof === 'dns_txt') {
      for (const name of [`_secscan.${t.host}`, t.host]) {
        let records: string[][] = [];
        try { records = await resolveTxt(name); } catch { continue; }
        if (records.some((chunks) => chunks.join('').trim() === `secscan-verify=${token}`)) return { ok: true, where: `TXT ${name}` };
      }
      return { ok: false, where: 'no matching TXT record' };
    }
    if (proof === 'http_token') {
      const r = await fetchText(origin + WELL_KNOWN);
      if (r.status === 200 && r.body.trim() === token) return { ok: true, where: WELL_KNOWN };
      return { ok: false, where: `${WELL_KNOWN} -> ${r.status}` };
    }
    const r = await fetchText(origin + '/');
    const re = new RegExp(`<meta\\s+[^>]*name=["']secscan-verify["'][^>]*content=["']([^"']+)["']`, 'i');
    const m = r.body.match(re);
    if (r.status === 200 && m && m[1] === token) return { ok: true, where: 'meta tag on /' };
    return { ok: false, where: `meta tag ${m ? 'present but mismatched' : 'absent'} (${r.status})` };
  } catch (e) {
    return { ok: false, where: `error: ${String(e).slice(0, 120)}` };
  }
}
