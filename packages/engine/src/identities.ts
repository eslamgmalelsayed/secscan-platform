/**
 * Test-account intake (Design §7, review 2.2).
 *
 * The owner supplies test accounts as a map keyed "role" or "role/tenant":
 *
 *   {
 *     "customer/t1": { "cookies": { "sid": "..." } },
 *     "customer/t2": { "headers": { "x-api-key": "..." } },
 *     "admin":       { "bearer": "eyJ..." }
 *   }
 *
 * Each entry becomes an Identity whose sessionRef is the key, and its
 * material is placed in a SecretStore. Secrets never leave the store: the
 * returned identities carry only the opaque key.
 */
import { z } from 'zod';
import type { Identity } from './http';
import { SecretStore, type SessionMaterial } from './secretStore';

export const IdentityMaterial = z.object({
  cookies: z.record(z.string()).optional(),
  headers: z.record(z.string()).optional(),
  bearer: z.string().optional(),
  /** Optional URL that returns 2xx only while this session is valid (liveness probe). */
  liveness: z.string().url().optional(),
}).refine((m) => m.cookies || m.headers || m.bearer, { message: 'cookies, headers or bearer required' });
export type IdentityMaterial = z.infer<typeof IdentityMaterial>;

export const IdentitiesFile = z.record(z.string().min(1), IdentityMaterial);
export type IdentitiesFile = z.infer<typeof IdentitiesFile>;

export interface LoadedIdentities {
  store: SecretStore;
  identities: Identity[];
  /** sessionRef -> liveness URL, for callers that verify sessions before a scan. */
  liveness: Record<string, string>;
}

export function parseIdentityKey(key: string): { role: string; tenant: string | null } {
  const i = key.indexOf('/');
  return i < 0 ? { role: key, tenant: null } : { role: key.slice(0, i), tenant: key.slice(i + 1) || null };
}

export function loadIdentities(input: unknown, store: SecretStore = new SecretStore()): LoadedIdentities {
  const file = IdentitiesFile.parse(input);
  const identities: Identity[] = [];
  const liveness: Record<string, string> = {};
  for (const [key, mat] of Object.entries(file)) {
    const { role, tenant } = parseIdentityKey(key);
    const material: SessionMaterial = { cookies: mat.cookies, headers: mat.headers, bearer: mat.bearer };
    store.put(key, material);
    identities.push({ role, tenant, sessionRef: key });
    if (mat.liveness) liveness[key] = mat.liveness;
  }
  return { store, identities, liveness };
}
