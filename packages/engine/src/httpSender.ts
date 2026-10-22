/**
 * A real HTTP transport usable as the engine's Sender, built on global fetch
 * (Node >=22). It applies the identity's session material, does not follow
 * redirects, and enforces a timeout. It is only ever invoked behind
 * GuardedClient, which has already cleared the request against scope (§8).
 */
import { Agent, fetch as undiciFetch } from 'undici';
import type { SendOptions, Sender } from './client';
import type { Identity, RecordedRequest, RecordedResponse } from './http';
import { SecretStore, cookieHeader } from './secretStore';

/** A dispatcher whose DNS lookup always answers with the scope-checked address,
 *  so the TCP connection goes exactly where the guard looked. TLS still
 *  verifies the certificate against the original hostname. */
function pinnedDispatcher(address: string): Agent {
  const family = address.includes(':') ? 6 : 4;
  return new Agent({
    connect: {
      lookup: (_hostname: string, _opts: unknown, cb: (err: Error | null, addr: string, fam: number) => void) => cb(null, address, family),
    },
  });
}

export interface HttpSenderOptions {
  store?: SecretStore;
  timeoutMs?: number;
  maxBodyBytes?: number;
  userAgent?: string;
  fetchImpl?: typeof fetch;
}

export function createHttpSender(opts: HttpSenderOptions = {}): Sender {
  const store = opts.store ?? new SecretStore();
  const timeoutMs = opts.timeoutMs ?? 15_000;
  const maxBody = opts.maxBodyBytes ?? 2_000_000;
  const ua = opts.userAgent ?? 'secscan/0.1 (authorized security test)';
  const doFetch = opts.fetchImpl ?? fetch;

  return async (req: RecordedRequest, ident: Identity, sendOpts: SendOptions = {}): Promise<RecordedResponse> => {
    const mat = store.material(ident.sessionRef);
    const headers: Record<string, string> = { 'user-agent': ua };
    for (const [k, v] of Object.entries(req.headers ?? {})) headers[k.toLowerCase()] = v;
    for (const [k, v] of Object.entries(mat.headers ?? {})) headers[k.toLowerCase()] = v;
    if (mat.cookies && Object.keys(mat.cookies).length) {
      headers['cookie'] = [headers['cookie'], cookieHeader(mat.cookies)].filter(Boolean).join('; ');
    }
    if (mat.bearer) headers['authorization'] = `Bearer ${mat.bearer}`;

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    // When the guard pinned an address, route through undici with a fixed
    // lookup; an injected fetchImpl (tests) still receives the dispatcher.
    const dispatcher = sendOpts.pinnedAddress ? pinnedDispatcher(sendOpts.pinnedAddress) : undefined;
    const fetcher: any = dispatcher && !opts.fetchImpl ? undiciFetch : doFetch;
    try {
      const resp = await fetcher(req.url, {
        method: req.method.toUpperCase(),
        headers,
        body: req.body ?? undefined,
        redirect: 'manual', // see the redirect, don't chase it
        signal: ctrl.signal,
        dispatcher,
      });
      const buf = await resp.arrayBuffer();
      const body = Buffer.from(buf.slice(0, maxBody)).toString('utf-8');
      const h: Record<string, string> = {};
      resp.headers.forEach((v: string, k: string) => { h[k.toLowerCase()] = v; });
      // Several Set-Cookie headers must not be collapsed into one comma-joined
      // value (cookie attributes contain commas). Keep one per line.
      const setCookies = (resp.headers as any).getSetCookie?.() as string[] | undefined;
      if (setCookies?.length) h['set-cookie'] = setCookies.join('\n');
      return { status: resp.status, headers: h, body };
    } catch (e) {
      // Transport failure => status 0, treated downstream as "not authorized".
      return { status: 0, headers: { 'x-secscan-error': String(e).slice(0, 200) }, body: '' };
    } finally {
      clearTimeout(timer);
      await dispatcher?.close().catch(() => undefined);
    }
  };
}
