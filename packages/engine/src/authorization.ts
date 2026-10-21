/**
 * The authorization model and gate (Design §3, §6).
 * Nothing active runs against a target not covered by a live grant whose
 * owner (not a middle-man) has signed. Grants are tamper-evident.
 */
import { createHmac } from 'node:crypto';
import { z } from 'zod';

export const OwnershipProof = z.enum(['dns_txt', 'http_token', 'meta_tag']);
export type OwnershipProof = z.infer<typeof OwnershipProof>;

export const GrantStatus = z.enum(['pending_owner', 'active', 'expired', 'revoked']);
export type GrantStatus = z.infer<typeof GrantStatus>;

export const Target = z.object({
  host: z.string().min(1),
  scheme: z.enum(['http', 'https']).default('https'),
  port: z.number().int().positive().nullable().default(null),
});
export type Target = z.infer<typeof Target>;

export const AuthorizationChainLink = z.object({
  party: z.string().min(1),
  email: z.string().email(),
  role: z.enum(['requester', 'system_owner', 'platform_owner']),
  signedAt: z.string().datetime(),
  statement: z.string().min(1),
});
export type AuthorizationChainLink = z.infer<typeof AuthorizationChainLink>;

export const AuthorizationGrant = z.object({
  grantId: z.string().min(1),
  targets: z.array(Target).min(1),
  ownershipProof: OwnershipProof,
  ownershipToken: z.string().min(1),
  chain: z.array(AuthorizationChainLink).min(1),
  notBefore: z.string().datetime(),
  notAfter: z.string().datetime(),
  allowStateChanging: z.boolean().default(false),
  status: GrantStatus.default('pending_owner'),
});
export type AuthorizationGrant = z.infer<typeof AuthorizationGrant>;

export function normalizedHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.+$/, '');
}

export interface ParsedTarget { host: string; scheme: string; port: number | null }

export function targetFromUrl(url: string): ParsedTarget {
  const u = new URL(url);
  return {
    host: normalizedHost(u.hostname),
    scheme: u.protocol.replace(':', ''),
    port: u.port ? Number(u.port) : null,
  };
}

/** Scheme-agnostic host match; port null in a grant means "any port". */
export function covers(grant: AuthorizationGrant, t: ParsedTarget): boolean {
  return grant.targets.some(
    (g) => normalizedHost(g.host) === t.host && (g.port == null || g.port === t.port),
  );
}

export function isLive(grant: AuthorizationGrant, at: Date = new Date()): boolean {
  return (
    grant.status === 'active' &&
    new Date(grant.notBefore) <= at &&
    at <= new Date(grant.notAfter)
  );
}

/** A grant is not active until a party with role 'system_owner' signs (§6). */
export function requiresOwnerSignature(grant: AuthorizationGrant): boolean {
  return !grant.chain.some((l) => l.role === 'system_owner');
}

/** Tamper-evident digest tying every report back to its exact authorization. */
export function fingerprint(grant: AuthorizationGrant, secret: string): string {
  const payload = JSON.stringify({
    grantId: grant.grantId,
    targets: grant.targets,
    ownership: [grant.ownershipProof, grant.ownershipToken],
    chain: grant.chain,
    window: [grant.notBefore, grant.notAfter],
    allowStateChanging: grant.allowStateChanging,
  });
  return createHmac('sha256', secret).update(payload).digest('hex');
}
