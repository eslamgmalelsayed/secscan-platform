/**
 * Persistence abstraction. In-memory implementations run the whole platform
 * without a database (tests, local dev); `PrismaStores` (prismaRepositories.ts)
 * implements the same interfaces on Postgres. All methods are async so a real
 * database can sit behind them.
 */
import type { AuthorizationGrant } from '@secscan/engine';
import type { Engagement, Finding } from '@secscan/shared';

export interface GrantRecord {
  grant: AuthorizationGrant;
  ownershipVerified: boolean;
  /** How ownershipVerified was set: an automatic proof or an admin override. */
  ownershipMethod?: 'automatic' | 'manual';
  adminApproved: boolean;
}

export interface ScanRecord {
  id: string;
  engagementId: string;
  grantId: string;
  status: 'queued' | 'running' | 'done' | 'failed';
  findings: Finding[];
  /** Below the confirmation bar: for human review, never in a client report. */
  review?: Finding[];
  notTested: string[];
  telemetry?: Record<string, number | null>;
  createdAt: string;
}

export interface GrantRepo {
  save(rec: GrantRecord): Promise<void>;
  get(grantId: string): Promise<GrantRecord | undefined>;
  list(): Promise<GrantRecord[]>;
}
export interface EngagementRepo {
  save(e: Engagement): Promise<void>;
  get(id: string): Promise<Engagement | undefined>;
  list(): Promise<Engagement[]>;
}
export interface ScanRepo {
  save(s: ScanRecord): Promise<void>;
  get(id: string): Promise<ScanRecord | undefined>;
  list(engagementId?: string): Promise<ScanRecord[]>;
}

/** Deep copy so callers never mutate stored state through a returned object
 *  (a database adapter has this property naturally; the in-memory one must too). */
const clone = <T>(v: T): T => structuredClone(v);

export class InMemoryGrantRepo implements GrantRepo {
  private m = new Map<string, GrantRecord>();
  async save(rec: GrantRecord) { this.m.set(rec.grant.grantId, clone(rec)); }
  async get(id: string) { const r = this.m.get(id); return r && clone(r); }
  async list() { return [...this.m.values()].map(clone); }
}
export class InMemoryEngagementRepo implements EngagementRepo {
  private m = new Map<string, Engagement>();
  async save(e: Engagement) { this.m.set(e.id, clone(e)); }
  async get(id: string) { const e = this.m.get(id); return e && clone(e); }
  async list() { return [...this.m.values()].map(clone); }
}
export class InMemoryScanRepo implements ScanRepo {
  private m = new Map<string, ScanRecord>();
  async save(s: ScanRecord) { this.m.set(s.id, clone(s)); }
  async get(id: string) { const s = this.m.get(id); return s && clone(s); }
  async list(engagementId?: string) {
    const all = [...this.m.values()].map(clone);
    return engagementId ? all.filter((s) => s.engagementId === engagementId) : all;
  }
}
