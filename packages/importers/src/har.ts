/**
 * Import recorded traffic from a HAR export into RecordedRequest flows (§11).
 * Session cookies and Authorization are stripped — identities are applied at
 * send time from the secret store — and third-party hosts can be filtered out.
 */
import type { RecordedRequest } from '@secscan/engine';

const DROP_HEADERS = new Set(['cookie', 'authorization', 'content-length', 'host', 'connection']);

export interface HarImportOptions {
  capturedAsRole?: string;
  capturedAsTenant?: string | null;
  requiresAuth?: boolean;
  includeHosts?: string[];
  methods?: string[];
}

export function fromHar(harText: string, opts: HarImportOptions = {}): RecordedRequest[] {
  const data = JSON.parse(harText);
  const entries: any[] = data?.log?.entries ?? [];
  const allow = new Set((opts.methods ?? ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']).map((m) => m.toUpperCase()));
  const hostFilter = opts.includeHosts ? new Set(opts.includeHosts.map((h) => h.toLowerCase())) : null;
  const seen = new Set<string>();
  const flows: RecordedRequest[] = [];

  for (const e of entries) {
    const r = e?.request ?? {};
    const method = String(r.method ?? 'GET').toUpperCase();
    const url = String(r.url ?? '');
    if (!url || !allow.has(method)) continue;
    if (hostFilter) {
      let host = '';
      try { host = new URL(url).hostname.toLowerCase(); } catch { continue; }
      if (!hostFilter.has(host)) continue;
    }
    const headers: Record<string, string> = {};
    for (const h of r.headers ?? []) {
      const name = String(h?.name ?? '').trim();
      if (!name || name.startsWith(':') || DROP_HEADERS.has(name.toLowerCase())) continue;
      headers[name] = String(h?.value ?? '');
    }
    const body = r.postData?.text ? String(r.postData.text) : null;
    const key = `${method} ${url} ${body ? '1' : '0'}`;
    if (seen.has(key)) continue;
    seen.add(key);
    flows.push({
      method, url, headers, body,
      capturedAsRole: opts.capturedAsRole ?? 'user',
      capturedAsTenant: opts.capturedAsTenant ?? null,
      requiresAuth: opts.requiresAuth ?? false,
    });
  }
  return flows;
}
