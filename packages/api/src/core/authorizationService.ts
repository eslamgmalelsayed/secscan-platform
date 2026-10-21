/**
 * Grant lifecycle and the pre-scan gate (Design §3, §6).
 * No scan runs unless a grant is (a) ownership-verified, (b) owner-signed,
 * (c) admin-approved, and (d) live. Every transition is written to the
 * append-only audit log.
 */
import { AuthorizationGrant, type AuthorizationChainLink, isLive } from '@secscan/engine';
import { AppendOnlyAuditLog } from './audit';
import type { GrantRecord, GrantRepo } from './repositories';

export class AuthorizationError extends Error {
  constructor(msg: string) { super(msg); this.name = 'AuthorizationError'; }
}

export class AuthorizationService {
  constructor(private grants: GrantRepo, private audit: AppendOnlyAuditLog) {}

  createGrant(input: unknown, actor: string): GrantRecord {
    const grant = AuthorizationGrant.parse(input);
    if (this.grants.get(grant.grantId)) throw new AuthorizationError(`grant ${grant.grantId} already exists`);
    const rec: GrantRecord = { grant: { ...grant, status: 'pending_owner' }, ownershipVerified: false, adminApproved: false };
    this.grants.save(rec);
    this.audit.append({ actor, action: 'grant_created', grantId: grant.grantId, detail: `targets: ${grant.targets.map((t) => t.host).join(',')}` });
    return rec;
  }

  recordOwnershipVerified(grantId: string, actor: string): GrantRecord {
    const rec = this.require(grantId);
    rec.ownershipVerified = true;
    this.grants.save(rec);
    this.audit.append({ actor, action: 'ownership_verified', grantId, detail: rec.grant.ownershipProof });
    return rec;
  }

  ownerSign(grantId: string, link: AuthorizationChainLink, actor: string): GrantRecord {
    const rec = this.require(grantId);
    if (link.role !== 'system_owner') throw new AuthorizationError('owner signature must have role system_owner');
    rec.grant = { ...rec.grant, chain: [...rec.grant.chain, link] };
    this.audit.append({ actor, action: 'owner_signed', grantId, detail: link.party });
    this.maybeActivate(rec, actor);
    this.grants.save(rec);
    return rec;
  }

  adminApprove(grantId: string, actor: string): GrantRecord {
    const rec = this.require(grantId);
    rec.adminApproved = true;
    this.audit.append({ actor, action: 'admin_approved', grantId });
    this.maybeActivate(rec, actor);
    this.grants.save(rec);
    return rec;
  }

  revoke(grantId: string, actor: string): GrantRecord {
    const rec = this.require(grantId);
    rec.grant = { ...rec.grant, status: 'revoked' };
    this.grants.save(rec);
    this.audit.append({ actor, action: 'grant_revoked', grantId });
    return rec;
  }

  /** Throws unless the grant may be used for an active scan right now. */
  assertScanAllowed(grantId: string): GrantRecord {
    const rec = this.require(grantId);
    const ownerSigned = rec.grant.chain.some((l) => l.role === 'system_owner');
    if (!rec.ownershipVerified) throw new AuthorizationError('ownership not verified');
    if (!ownerSigned) throw new AuthorizationError('owner has not signed');
    if (!rec.adminApproved) throw new AuthorizationError('admin has not approved');
    if (rec.grant.status !== 'active' || !isLive(rec.grant)) throw new AuthorizationError('grant is not active/live');
    return rec;
  }

  private maybeActivate(rec: GrantRecord, actor: string): void {
    const ownerSigned = rec.grant.chain.some((l) => l.role === 'system_owner');
    if (rec.ownershipVerified && ownerSigned && rec.adminApproved && rec.grant.status === 'pending_owner') {
      rec.grant = { ...rec.grant, status: 'active' };
      this.audit.append({ actor, action: 'grant_activated', grantId: rec.grant.grantId });
    }
  }

  private require(grantId: string): GrantRecord {
    const rec = this.grants.get(grantId);
    if (!rec) throw new AuthorizationError(`grant ${grantId} not found`);
    return rec;
  }
}
