/**
 * Scope enforcement — the mandatory Scope Proxy gate (Design §3, §8).
 * Every outbound request is adjudicated here before it is sent. A request not
 * covered by a live grant is refused (not warned) and the refusal is logged.
 *
 * SSRF / DNS-rebinding guard (review 2.4): the host is resolved ONCE per scan
 * (cached), checked against private/reserved space, and the resolved address
 * is handed back so the transport connects to exactly that address. A name
 * that later re-resolves to 127.0.0.1 cannot redirect the connection, because
 * the connection never resolves it again.
 */
import { promises as dns } from 'node:dns';
import { isIP } from 'node:net';
import { AuthorizationGrant, covers, isLive, targetFromUrl } from './authorization';

export type Decision =
  | 'allow'
  | 'deny_no_grant'
  | 'deny_out_of_scope'
  | 'deny_grant_not_live'
  | 'deny_state_changing'
  | 'deny_private_address';

export interface ScopeVerdict {
  decision: Decision;
  reason: string;
  allowed: boolean;
  /** The address the transport must connect to (set when a resolver ran). */
  address?: string;
}

const STATE_CHANGING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export type HostResolver = (host: string) => string[] | Promise<string[]>;

/** System DNS, all addresses. Used when no resolver is injected. */
export const systemResolver: HostResolver = async (host) =>
  (await dns.lookup(host, { all: true, verbatim: true })).map((a) => a.address);

export interface ScopeGuardOptions {
  /** Refuse hosts that resolve into private/reserved space. Default true. */
  blockPrivateAddresses?: boolean;
  /** Injected for tests; defaults to system DNS when private blocking is on. */
  resolveHost?: HostResolver;
}

export class ScopeGuard {
  private grants: AuthorizationGrant[];
  private blockPrivate: boolean;
  private resolve: HostResolver;
  private cache = new Map<string, Promise<string[]>>();

  constructor(grants: AuthorizationGrant[], opts: ScopeGuardOptions = {}) {
    this.grants = grants;
    this.blockPrivate = opts.blockPrivateAddresses ?? true;
    this.resolve = opts.resolveHost ?? systemResolver;
  }

  async check(
    url: string,
    method: string,
    opts: { isStateChanging?: boolean; at?: Date } = {},
  ): Promise<ScopeVerdict> {
    const at = opts.at ?? new Date();
    let t;
    try {
      t = targetFromUrl(url);
    } catch {
      return verdict('deny_out_of_scope', 'invalid URL');
    }
    if (!t.host) return verdict('deny_out_of_scope', 'no host in URL');

    const covering = this.grants.filter((g) => covers(g, t));
    if (covering.length === 0) return verdict('deny_no_grant', `no grant covers ${t.host}`);

    const live = covering.filter((g) => isLive(g, at));
    if (live.length === 0) return verdict('deny_grant_not_live', `grant(s) for ${t.host} not active`);

    const stateChanging = (opts.isStateChanging ?? false) || STATE_CHANGING_METHODS.has(method.toUpperCase());
    if (stateChanging && !live.some((g) => g.allowStateChanging)) {
      return verdict('deny_state_changing', `${method} ${t.host} is state-changing; no live grant permits it`);
    }

    if (!this.blockPrivate) return verdict('allow', 'covered by live grant');

    const addrs = await this.resolveOnce(t.host);
    if (addrs.length === 0) return verdict('deny_private_address', `${t.host} did not resolve`);
    if (addrs.some(isPrivateIp)) return verdict('deny_private_address', `${t.host} resolves into private/reserved space`);
    return { ...verdict('allow', 'covered by live grant'), address: addrs[0] };
  }

  /**
   * Whether a live grant names this host, without resolving it. For DNS-only
   * checks (mail records, dangling CNAMEs) that never connect to the host.
   */
  coversHost(url: string, at: Date = new Date()): boolean {
    let t;
    try { t = targetFromUrl(url.replace(/^ws(s?):/i, 'http$1:')); } catch { return false; }
    return this.grants.some((g) => covers(g, t) && isLive(g, at));
  }

  /** One lookup per host for the lifetime of this guard (= one scan). */
  private resolveOnce(host: string): Promise<string[]> {
    const bare = host.replace(/^\[|\]$/g, '');
    if (isIP(bare)) return Promise.resolve([bare]);
    let p = this.cache.get(host);
    if (!p) {
      p = Promise.resolve()
        .then(() => this.resolve(host))
        .catch(() => [] as string[]); // cannot resolve safely => treat as unsafe
      this.cache.set(host, p);
    }
    return p;
  }
}

function verdict(decision: Decision, reason: string): ScopeVerdict {
  return { decision, reason, allowed: decision === 'allow' };
}

/** Conservative private/reserved address check for IPv4 and common IPv6. */
export function isPrivateIp(ip: string): boolean {
  const v4 = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true; // link-local
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true; // multicast/reserved
    return false;
  }
  const v6 = ip.toLowerCase();
  if (v6 === '::1' || v6 === '::') return true;
  if (v6.startsWith('fe80') || v6.startsWith('fc') || v6.startsWith('fd')) return true;
  if (v6.startsWith('::ffff:')) return isPrivateIp(v6.slice(7)); // IPv4-mapped
  return false;
}
