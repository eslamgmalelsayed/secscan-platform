/**
 * Import an OpenAPI 3 spec (JSON) into RecordedRequest flows (§11).
 * Path and required query parameters are filled with sample values. An
 * operation under a non-empty `security` (or global security) is marked
 * requiresAuth — the oracle for missing-authentication findings.
 */
import type { RecordedRequest } from '@secscan/engine';

export interface OpenApiImportOptions {
  baseUrl?: string;
  capturedAsRole?: string;
  capturedAsTenant?: string | null;
  methods?: string[];
}

function sample(schema: any): string {
  if (schema && 'example' in schema) return String(schema.example);
  const t = schema?.type ?? 'string';
  return ({ integer: '1', number: '1', boolean: 'true' } as Record<string, string>)[t] ?? 'test';
}

export function fromOpenApi(specJson: string | object, opts: OpenApiImportOptions = {}): RecordedRequest[] {
  const spec: any = typeof specJson === 'string' ? JSON.parse(specJson) : specJson;
  const servers: any[] = spec.servers ?? [];
  const base = (opts.baseUrl ?? servers[0]?.url ?? '').replace(/\/+$/, '');
  if (!base) throw new Error('no server URL in spec and no baseUrl provided');

  const globalSecurity = Array.isArray(spec.security) && spec.security.length > 0;
  const allow = new Set((opts.methods ?? ['GET']).map((m) => m.toLowerCase()));
  const flows: RecordedRequest[] = [];

  for (const [rawPath, item] of Object.entries<any>(spec.paths ?? {})) {
    if (!item || typeof item !== 'object') continue;
    for (const [method, op] of Object.entries<any>(item)) {
      if (!allow.has(method.toLowerCase()) || !op || typeof op !== 'object') continue;
      const params = [...(op.parameters ?? []), ...(item.parameters ?? [])];
      let path = rawPath;
      const query: string[] = [];
      for (const p of params) {
        if (!p?.name) continue;
        const val = sample(p.schema ?? {});
        if (p.in === 'path') path = path.replace(`{${p.name}}`, val);
        else if (p.in === 'query' && p.required) query.push(`${encodeURIComponent(p.name)}=${encodeURIComponent(val)}`);
      }
      const url = base + path + (query.length ? `?${query.join('&')}` : '');
      const requiresAuth = globalSecurity || (Array.isArray(op.security) && op.security.length > 0);
      flows.push({
        method: method.toUpperCase(), url, headers: { accept: 'application/json' },
        capturedAsRole: opts.capturedAsRole ?? 'user',
        capturedAsTenant: opts.capturedAsTenant ?? null,
        requiresAuth,
      });
    }
  }
  return flows;
}
