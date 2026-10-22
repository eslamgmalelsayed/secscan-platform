/**
 * Does a recorded request name a specific object? (Design §9, review 2.1.)
 *
 * Object-level authorization (IDOR/BOLA) can only be broken on a request that
 * carries an object identifier the server trusts. A request with no
 * identifier (`/api/me`, `/dashboard`, `/orders?page=1`) can only be keyed on
 * the session, so two identities receiving equal bodies there means "same
 * data", not "bypass". The differ therefore refuses to classify such a
 * request as bola_idor / cross_tenant. The rules are deterministic and
 * deliberately conservative.
 */
import type { RecordedRequest } from './http';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NUMERIC = /^\d+$/;
const LONG_HEX = /^[0-9a-f]{12,}$/i;

/** Parameter / field names that denote an identifier (tested after snake_casing). */
const ID_NAME = /(^|_)(id|uuid|guid|key|ref|no|num|number|code|sku|slug|handle)$/;

const snakeCase = (k: string): string => k.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();

export const isIdentifierValue = (v: string): boolean => UUID.test(v) || NUMERIC.test(v) || LONG_HEX.test(v);
export const isIdentifierName = (name: string): boolean => ID_NAME.test(snakeCase(name));

function paramsHaveIdentifier(params: Iterable<[string, string]>): boolean {
  for (const [name, value] of params) {
    if (isIdentifierName(name)) return true;
    if (UUID.test(value)) return true; // a UUID value is an identifier whatever it is called
  }
  return false;
}

function jsonHasIdentifier(obj: unknown, depth = 0): boolean {
  if (depth > 4 || !obj || typeof obj !== 'object') return false;
  if (Array.isArray(obj)) return obj.some((v) => jsonHasIdentifier(v, depth + 1));
  for (const [k, v] of Object.entries(obj)) {
    if (isIdentifierName(k) && (typeof v === 'string' || typeof v === 'number')) return true;
    if (typeof v === 'string' && UUID.test(v)) return true;
    if (jsonHasIdentifier(v, depth + 1)) return true;
  }
  return false;
}

export function requestHasObjectIdentifier(req: Pick<RecordedRequest, 'method' | 'url' | 'body' | 'headers'>): boolean {
  let u: URL;
  try { u = new URL(req.url); } catch { return false; }

  if (u.pathname.split('/').filter(Boolean).some(isIdentifierValue)) return true;
  if (paramsHaveIdentifier(u.searchParams)) return true;

  if (req.body) {
    const ct = Object.entries(req.headers ?? {}).find(([k]) => k.toLowerCase() === 'content-type')?.[1]?.toLowerCase() ?? '';
    const trimmed = req.body.trim();
    if (ct.includes('json') || trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try { if (jsonHasIdentifier(JSON.parse(trimmed))) return true; } catch { /* not JSON */ }
    }
    if (ct.includes('x-www-form-urlencoded') || (!ct && /^[^=&\s]+=[^&]*(&|$)/.test(trimmed))) {
      if (paramsHaveIdentifier(new URLSearchParams(trimmed))) return true;
    }
  }
  return false;
}
