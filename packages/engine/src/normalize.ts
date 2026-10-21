/**
 * Normalize responses before comparison (Design §9).
 * A byte-diff is useless: timestamps, CSRF tokens, request ids and nonces
 * differ on every call. Normalization strips that volatile surface so the
 * authorization diff compares substance, not noise — avoiding the ARTEMIS
 * class of error (reading a superficial difference as a real one).
 */
import { createHash } from 'node:crypto';

const VOLATILE_HEADERS = new Set([
  'date', 'set-cookie', 'x-request-id', 'x-correlation-id', 'etag',
  'last-modified', 'cf-ray', 'x-amz-cf-id', 'age', 'report-to',
]);

const VOLATILE_JSON_KEY =
  /(^|_)(csrf|token|nonce|timestamp|updated_at|created_at|request_id|trace|session|expires|iat|exp)($|_)/i;

const ISO_TS = /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?/g;
const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;

export function normalizeHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (!VOLATILE_HEADERS.has(k.toLowerCase())) out[k.toLowerCase()] = v;
  }
  return out;
}

function scrubScalar(v: unknown): unknown {
  if (typeof v === 'string') return v.replace(ISO_TS, '<TS>').replace(UUID, '<UUID>');
  return v;
}

function scrubJson(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(scrubJson);
  if (obj && typeof obj === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      out[k] = VOLATILE_JSON_KEY.test(k) ? '<VOLATILE>' : scrubJson(v);
    }
    return out;
  }
  return scrubScalar(obj);
}

/** Canonical comparable string form of a response body. */
export function normalizeBody(body: string, contentType = ''): string {
  const looksJson = contentType.toLowerCase().includes('json') ||
    ['{', '['].includes(body.trim().charAt(0));
  if (looksJson) {
    try {
      return stableStringify(scrubJson(JSON.parse(body)));
    } catch {
      /* fall through */
    }
  }
  return body.replace(ISO_TS, '<TS>').replace(UUID, '<UUID>');
}

/** Deterministic JSON with sorted keys, so equal content compares equal. */
export function stableStringify(obj: unknown): string {
  return JSON.stringify(sortDeep(obj));
}

function sortDeep(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(sortDeep);
  if (obj && typeof obj === 'object') {
    return Object.fromEntries(
      Object.keys(obj as Record<string, unknown>).sort().map((k) => [k, sortDeep((obj as any)[k])]),
    );
  }
  return obj;
}

export function bodyDigest(body: string, contentType = ''): string {
  return createHash('sha256').update(normalizeBody(body, contentType)).digest('hex');
}
