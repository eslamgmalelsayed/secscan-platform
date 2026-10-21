/**
 * Persistence abstraction. In-memory implementations run the whole platform
 * without a database (for tests and local dev); a Prisma/Postgres adapter
 * (see prisma/schema.prisma) implements the same interfaces in production.
 */
import type { AuthorizationGrant } from '@secscan/engine';
import type { Engagement, Finding } from '@secscan/shared';

export interface GrantRecord {
  grant: AuthorizationGrant;
  ownershipVerified: boolean;
  adminApproved: boolean;
}

export interface ScanRecord {
  id: string;
  engagementId: string;
  grantId: string;
  status: 'queued' | 'running' | 'done' | 'failed';
  findings: Finding[];
  notTested: string[];
  telemetry?: Record<string, number | null>;
  createdAt: string;
}

export interface GrantRepo {
  save(rec: GrantRecord): void;
  get(grantId: string): GrantRecord | undefined;
  list(): GrantRecord[];
}
export interface EngagementRepo {
  save(e: Engagement): void;
  get(id: string): Engagement | undefined;
}
export interface ScanRepo {
  save(s: ScanRecord): void;
  get(id: string): ScanRecord | undefined;
  list(engagementId?: string): ScanRecord[];
}

export class InMemoryGrantRepo implements GrantRepo {
  private m = new Map<string, GrantRecord>();
  save(rec: GrantRecord) { this.m.set(rec.grant.grantId, rec); }
  get(id: string) { return this.m.get(id); }
  list() { return [...this.m.values()]; }
}
export class InMemoryEngagementRepo implements EngagementRepo {
  private m = new Map<string, Engagement>();
  save(e: Engagement) { this.m.set(e.id, e); }
  get(id: string) { return this.m.get(id); }
}
export class InMemoryScanRepo implements ScanRepo {
  private m = new Map<string, ScanRecord>();
  save(s: ScanRecord) { this.m.set(s.id, s); }
  get(id: string) { return this.m.get(id); }
  list(engagementId?: string) {
    const all = [...this.m.values()];
    return engagementId ? all.filter((s) => s.engagementId === engagementId) : all;
  }
}
