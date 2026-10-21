/**
 * Test accounts as a first-class object (Design §7).
 * The platform requires role × tenant × credentials for test accounts (never
 * real users'), verifies each session is live before a scan, and marks a
 * session invalid if its liveness probe fails — so a dead session produces a
 * "skipped", never a false finding.
 */
import type { GuardedClient } from './client';
import type { Identity, RecordedRequest } from './http';

export interface RegisteredIdentity {
  identity: Identity;
  /** A request that returns an authorized (2xx, non-empty) response iff the
   *  identity's session is still valid. */
  liveness: RecordedRequest;
  valid: boolean;
}

export class SessionRegistry {
  private items = new Map<string, RegisteredIdentity>();

  /** key is "role" or "role/tenant". */
  register(identity: Identity, liveness: RecordedRequest): void {
    this.items.set(this.key(identity), { identity, liveness, valid: true });
  }

  private key(i: Identity): string {
    return i.tenant ? `${i.role}/${i.tenant}` : i.role;
  }

  identities(): Identity[] {
    return [...this.items.values()].filter((r) => r.valid).map((r) => r.identity);
  }

  byRole(role: string, tenant?: string | null): Identity | undefined {
    return this.items.get(tenant ? `${role}/${tenant}` : role)?.identity;
  }

  /** Verify every session; mark invalid ones. Returns the list that failed. */
  async verifyAll(client: GuardedClient): Promise<Identity[]> {
    const failed: Identity[] = [];
    for (const rec of this.items.values()) {
      let ok = false;
      try {
        const r = await client.send(rec.liveness, rec.identity);
        ok = r.status >= 200 && r.status < 300 && r.body.length > 0;
      } catch {
        ok = false;
      }
      rec.valid = ok;
      if (!ok) failed.push(rec.identity);
    }
    return failed;
  }
}
