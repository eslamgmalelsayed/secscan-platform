/**
 * A real HTTP transport usable as the engine's Sender, built on global fetch
 * (Node >=22). It applies the identity's session material, does not follow
 * redirects, and enforces a timeout. It is only ever invoked behind
 * GuardedClient, which has already cleared the request against scope (§8).
 */
import type { Sender } from './client';
import type { Identity, RecordedRequest, RecordedResponse } from './http';
import { SecretStore, cookieHeader } from './secretStore';

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

  return async (req: RecordedRequest, ident: Identity): Promise<RecordedResponse> => {
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
    try {
      const resp = await doFetch(req.url, {
        method: req.method.toUpperCase(),
        headers,
        body: req.body ?? undefined,
        redirect: 'manual', // see the redirect, don't chase it
        signal: ctrl.signal,
      });
      const buf = await resp.arrayBuffer();
      const body = Buffer.from(buf.slice(0, maxBody)).toString('utf-8');
      const h: Record<string, string> = {};
      resp.headers.forEach((v, k) => { h[k.toLowerCase()] = v; });
      return { status: resp.status, headers: h, body };
    } catch (e) {
      // Transport failure => status 0, treated downstream as "not authorized".
      return { status: 0, headers: { 'x-secscan-error': String(e).slice(0, 200) }, body: '' };
    } finally {
      clearTimeout(timer);
    }
  };
}
