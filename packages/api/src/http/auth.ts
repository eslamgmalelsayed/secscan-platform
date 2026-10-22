/**
 * API authentication (review 2.3).
 *
 * Every route except GET /health requires `Authorization: Bearer <token>`
 * when tokens are configured. Each token is bound to a name, and that name is
 * the audit-log actor: a caller can no longer write `actor: "admin"` in a
 * request body to impersonate someone. Admin-only routes additionally need
 * the admin token (x-admin-token), checked in the controllers.
 *
 * Tokens are compared as SHA-256 digests with timingSafeEqual, so neither
 * length nor content leaks through timing.
 */
import { createHash, timingSafeEqual } from 'node:crypto';

export interface ApiAuth {
  /** name -> token */
  tokens: Record<string, string>;
}

/** Parses "alice@corp:tok1,ci-bot:tok2". Names may contain ':'-free text only. */
export function parseApiTokens(spec: string | undefined): ApiAuth | undefined {
  if (!spec?.trim()) return undefined;
  const tokens: Record<string, string> = {};
  for (const part of spec.split(',').map((p) => p.trim()).filter(Boolean)) {
    const i = part.indexOf(':');
    if (i <= 0 || i === part.length - 1) throw new Error(`SECSCAN_API_TOKENS entry must be name:token (got '${part.slice(0, 20)}…')`);
    const name = part.slice(0, i).trim();
    const token = part.slice(i + 1).trim();
    if (token.length < 16) throw new Error(`token for '${name}' is shorter than 16 characters`);
    tokens[name] = token;
  }
  return { tokens };
}

const digest = (s: string) => createHash('sha256').update(s).digest();

export function safeEqual(a: string, b: string): boolean {
  return timingSafeEqual(digest(a), digest(b));
}

/** Returns the caller's name, or null when the token is missing/unknown. */
export function authenticate(auth: ApiAuth, authorizationHeader: string | undefined): string | null {
  const m = /^Bearer\s+(.+)$/i.exec(authorizationHeader ?? '');
  if (!m) return null;
  const presented = m[1].trim();
  let who: string | null = null;
  // Check every entry (no early exit) so timing does not reveal which name matched.
  for (const [name, token] of Object.entries(auth.tokens)) if (safeEqual(presented, token)) who = name;
  return who;
}

export const PUBLIC_ROUTES = new Set(['GET /health']);
