/**
 * Normalize responses before comparison (Design §9).
 * A byte-diff is useless: timestamps, CSRF tokens, request ids and nonces
 * differ on every call. Normalization strips that volatile surface so the
 * authorization diff compares substance, not noise — avoiding the ARTEMIS
 * class of error (reading a superficial difference as a real one).
 *
 * The opposite error matters just as much: scrubbing too much makes two
 * DIFFERENT users' data look identical (a secure /me endpoint reported as an
 * IDOR). So in JSON, entity identifiers are kept verbatim: UUIDs are only
 * removed under known-volatile keys, never wholesale. Timestamps embedded in
 * free text are still scrubbed (they are noise far more often than identity).
 */
import { createHash } from 'node:crypto';

const VOLATILE_HEADERS = new Set([
  'date', 'set-cookie', 'x-request-id', 'x-correlation-id', 'etag',
  'last-modified', 'cf-ray', 'x-amz-cf-id', 'age', 'report-to',
]);

/** Matched against the snake_cased key, so `updatedAt` / `csrfToken` count too. */
const VOLATILE_JSON_KEY =
  /(^|_)(csrf|token|nonce|timestamp|updated_at|created_at|request_id|correlation_id|trace|session|expires|iat|exp)($|_)/i;

const snakeCase = (k: string): string => k.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
export const isVolatileKey = (k: string): boolean => VOLATILE_JSON_KEY.test(snakeCase(k));

const ISO_TS = /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?/g;
const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;

export function normalizeHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (!VOLATILE_HEADERS.has(k.toLowerCase())) out[k.toLowerCase()] = v;
  }
  return out;
}

/** JSON scalar: timestamps are noise; UUIDs are identity and are KEPT. */
function scrubScalar(v: unknown): unknown {
  if (typeof v === 'string') return v.replace(ISO_TS, '<TS>');
  return v;
}

function scrubJson(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(scrubJson);
  if (obj && typeof obj === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      out[k] = isVolatileKey(k) ? '<VOLATILE>' : scrubJson(v);
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
  // Non-JSON (HTML etc.) has no key structure to tell a CSRF nonce from an
  // entity id, so both are scrubbed; HTML diffs are coarser by nature.
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
