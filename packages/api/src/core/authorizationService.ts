/**
 * Grant lifecycle and the pre-scan gate (Design §3, §6).
 * No scan runs unless a grant is (a) ownership-verified, (b) owner-signed,
 * (c) admin-approved, and (d) live. Every transition is written to the
 * append-only audit log.
 *
 * Owner signature is a two-step email OTP (ownerSignature.ts). A manual
 * signature exists for lab targets that have no mailbox; it is admin-only at
 * the HTTP layer and audited under its own action.
 */
import {
  AuthorizationGrant, AuthorizationChainLink, isLive, verifyOwnership,
  type OwnershipDeps, type OwnershipResult,
} from '@secscan/engine';
import { z } from 'zod';
import type { AuditStore } from './audit';
import type { GrantRecord, GrantRepo } from './repositories';
import {
  InMemoryOwnerChallengeStore, OTP_MAX_ATTEMPTS, OTP_TTL_MS, codeMatches, emailDomainCoversTargets,
  hashCode, maskEmail, newChallengeId, newCode,
  type Mailer, type OwnerChallengeStore,
} from './ownerSignature';

export class AuthorizationError extends Error {
  constructor(msg: string) { super(msg); this.name = 'AuthorizationError'; }
}

export interface OwnerSignDeps {
  mailer: Mailer;
  challenges?: OwnerChallengeStore;
  /** HMAC key for stored codes. */
  secret: string;
  now?: () => Date;
}

export const OwnerSignRequest = z.object({
  party: z.string().min(1).max(200),
  email: z.string().email(),
  statement: z.string().min(1).max(2000),
});

export class AuthorizationService {
  private challenges: OwnerChallengeStore;
  private now: () => Date;

  constructor(private grants: GrantRepo, private audit: AuditStore, private owner?: OwnerSignDeps) {
    this.challenges = owner?.challenges ?? new InMemoryOwnerChallengeStore();
    this.now = owner?.now ?? (() => new Date());
  }

  async createGrant(input: unknown, actor: string): Promise<GrantRecord> {
    const grant = AuthorizationGrant.parse(input);
    if (await this.grants.get(grant.grantId)) throw new AuthorizationError(`grant ${grant.grantId} already exists`);
    const rec: GrantRecord = { grant: { ...grant, status: 'pending_owner' }, ownershipVerified: false, adminApproved: false };
    await this.grants.save(rec);
    await this.audit.append({ actor, action: 'grant_created', grantId: grant.grantId, detail: `targets: ${grant.targets.map((t) => t.host).join(',')}` });
    return rec;
  }

  /** Automatic proof (§3.1): flips the flag only when every target passes. A
   *  failure is audited too, so repeated attempts are visible. */
  async verifyOwnership(grantId: string, actor: string, deps?: OwnershipDeps): Promise<GrantRecord & { verification: OwnershipResult }> {
    const rec = await this.require(grantId);
    const verification = await verifyOwnership(rec.grant, deps);
    if (verification.ok) {
      rec.ownershipVerified = true;
      rec.ownershipMethod = 'automatic';
      await this.grants.save(rec);
    }
    await this.audit.append({
      actor, action: verification.ok ? 'ownership_verified' : 'ownership_verification_failed',
      grantId, detail: `${rec.grant.ownershipProof}: ${verification.detail.join('; ')}`,
    });
    return { ...rec, verification };
  }

  /** Manual override for lab targets that cannot host a proof. */
  async recordOwnershipVerified(grantId: string, actor: string): Promise<GrantRecord> {
    const rec = await this.require(grantId);
    rec.ownershipVerified = true;
    rec.ownershipMethod = 'manual';
    await this.grants.save(rec);
    await this.audit.append({ actor, action: 'ownership_recorded_manually', grantId, detail: rec.grant.ownershipProof });
    return rec;
  }

  /** Step 1 of owner sign-off: email a one-time code to a mailbox on the target's domain. */
  async requestOwnerSignature(grantId: string, input: unknown, actor: string): Promise<{ challengeId: string; expiresAt: string }> {
    if (!this.owner) throw new AuthorizationError('owner sign-off by email is not configured');
    const rec = await this.require(grantId);
    if (rec.grant.status !== 'pending_owner') throw new AuthorizationError(`grant is ${rec.grant.status}; owner sign-off is only for pending grants`);
    const req = OwnerSignRequest.parse(input);
    if (!emailDomainCoversTargets(req.email, rec.grant.targets)) {
      throw new AuthorizationError('owner email must be on the domain of every target in the grant');
    }
    const id = newChallengeId();
    const code = newCode();
    const expiresAt = new Date(this.now().getTime() + OTP_TTL_MS).toISOString();
    await this.challenges.put({
      id, grantId, party: req.party, email: req.email.toLowerCase(), statement: req.statement,
      codeHash: hashCode(this.owner.secret, id, code), expiresAt, attempts: 0,
    });
    await this.owner.mailer.send({
      to: req.email,
      subject: `Security testing authorization request for ${rec.grant.targets.map((t) => t.host).join(', ')}`,
      text: [
        `${actor} has asked to run authorized security testing against:`,
        ...rec.grant.targets.map((t) => `  - ${t.scheme}://${t.host}${t.port ? `:${t.port}` : ''}`),
        `Window: ${rec.grant.notBefore} to ${rec.grant.notAfter}`,
        `State-changing requests permitted: ${rec.grant.allowStateChanging ? 'YES' : 'no'}`,
        '',
        `Statement you are signing: "${req.statement}"`,
        '',
        `If you own these systems and agree, give this code to the requester: ${code}`,
        `It expires in ${OTP_TTL_MS / 60_000} minutes. If you did not expect this, ignore it; nothing will run.`,
      ].join('\n'),
    });
    await this.audit.append({ actor, action: 'owner_signature_requested', grantId, detail: `${req.party} <${maskEmail(req.email)}>` });
    return { challengeId: id, expiresAt };
  }

  /** Step 2: the code proves the owner received the request. The server writes the chain link. */
  async confirmOwnerSignature(grantId: string, challengeId: string, code: string, actor: string): Promise<GrantRecord> {
    if (!this.owner) throw new AuthorizationError('owner sign-off by email is not configured');
    const rec = await this.require(grantId);
    const c = await this.challenges.get(challengeId);
    if (!c || c.grantId !== grantId) throw new AuthorizationError('unknown or mismatched challenge');
    if (this.now() > new Date(c.expiresAt)) {
      await this.challenges.delete(c.id);
      await this.audit.append({ actor, action: 'owner_signature_expired', grantId });
      throw new AuthorizationError('code expired; request a new one');
    }
    if (!codeMatches(this.owner.secret, c, String(code ?? '').trim())) {
      c.attempts += 1;
      if (c.attempts >= OTP_MAX_ATTEMPTS) await this.challenges.delete(c.id);
      else await this.challenges.put(c);
      await this.audit.append({ actor, action: 'owner_signature_code_rejected', grantId, detail: `attempt ${c.attempts}/${OTP_MAX_ATTEMPTS}` });
      throw new AuthorizationError(c.attempts >= OTP_MAX_ATTEMPTS ? 'too many attempts; request a new code' : 'incorrect code');
    }
    await this.challenges.delete(c.id);
    const link: AuthorizationChainLink = {
      party: c.party, email: c.email, role: 'system_owner', signedAt: this.now().toISOString(), statement: c.statement,
    };
    rec.grant = { ...rec.grant, chain: [...rec.grant.chain, link] };
    await this.audit.append({ actor, action: 'owner_signed', grantId, detail: `${c.party} <${maskEmail(c.email)}> via email code` });
    await this.maybeActivate(rec, actor);
    await this.grants.save(rec);
    return rec;
  }

  /** Lab-only manual signature (no mailbox on a lab host). Admin-only at the HTTP layer. */
  async ownerSign(grantId: string, linkInput: unknown, actor: string): Promise<GrantRecord> {
    const rec = await this.require(grantId);
    const link: AuthorizationChainLink = AuthorizationChainLink.parse(linkInput);
    if (link.role !== 'system_owner') throw new AuthorizationError('owner signature must have role system_owner');
    rec.grant = { ...rec.grant, chain: [...rec.grant.chain, { ...link, signedAt: this.now().toISOString() }] };
    await this.audit.append({ actor, action: 'owner_signed_manually', grantId, detail: link.party });
    await this.maybeActivate(rec, actor);
    await this.grants.save(rec);
    return rec;
  }

  async adminApprove(grantId: string, actor: string): Promise<GrantRecord> {
    const rec = await this.require(grantId);
    rec.adminApproved = true;
    await this.audit.append({ actor, action: 'admin_approved', grantId });
    await this.maybeActivate(rec, actor);
    await this.grants.save(rec);
    return rec;
  }

  async revoke(grantId: string, actor: string): Promise<GrantRecord> {
    const rec = await this.require(grantId);
    rec.grant = { ...rec.grant, status: 'revoked' };
    await this.grants.save(rec);
    await this.audit.append({ actor, action: 'grant_revoked', grantId });
    return rec;
  }

  /** Throws unless the grant may be used for an active scan right now. */
  async assertScanAllowed(grantId: string): Promise<GrantRecord> {
    const rec = await this.require(grantId);
    const ownerSigned = rec.grant.chain.some((l) => l.role === 'system_owner');
    if (!rec.ownershipVerified) throw new AuthorizationError('ownership not verified');
    if (!ownerSigned) throw new AuthorizationError('owner has not signed');
    if (!rec.adminApproved) throw new AuthorizationError('admin has not approved');
    if (rec.grant.status !== 'active' || !isLive(rec.grant)) throw new AuthorizationError('grant is not active/live');
    return rec;
  }

  private async maybeActivate(rec: GrantRecord, actor: string): Promise<void> {
    const ownerSigned = rec.grant.chain.some((l) => l.role === 'system_owner');
    if (rec.ownershipVerified && ownerSigned && rec.adminApproved && rec.grant.status === 'pending_owner') {
      rec.grant = { ...rec.grant, status: 'active' };
      await this.audit.append({ actor, action: 'grant_activated', grantId: rec.grant.grantId });
    }
  }

  private async require(grantId: string): Promise<GrantRecord> {
    const rec = await this.grants.get(grantId);
    if (!rec) throw new AuthorizationError(`grant ${grantId} not found`);
    return rec;
  }
}
