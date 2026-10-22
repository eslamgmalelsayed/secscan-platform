/**
 * Append-only authorization log (Design §6).
 * Every authorization step is recorded. There is deliberately no update or
 * delete — entries can only be appended and read. `AuditStore` is the
 * interface; the Prisma store implements it with INSERT/SELECT only.
 */
export interface AuditEntry {
  id: string;
  at: string; // ISO timestamp
  actor: string; // who performed it (email / "admin" / "system")
  action: string; // e.g. grant_created, owner_signed, scan_run
  grantId?: string;
  detail?: string;
}

export type AuditInput = Omit<AuditEntry, 'id' | 'at'> & { at?: string };

export interface AuditStore {
  append(e: AuditInput): Promise<AuditEntry>;
  /** Oldest first. */
  list(grantId?: string): Promise<AuditEntry[]>;
}

export class AppendOnlyAuditLog implements AuditStore {
  private entries: AuditEntry[] = [];
  private seq = 0;

  async append(e: AuditInput): Promise<AuditEntry> {
    const entry: AuditEntry = {
      id: `ae-${++this.seq}`,
      at: e.at ?? new Date().toISOString(),
      actor: e.actor,
      action: e.action,
      grantId: e.grantId,
      detail: e.detail,
    };
    this.entries.push(entry);
    return { ...entry };
  }

  /** Read-only view (a copy); callers cannot mutate the log through it. */
  async list(grantId?: string): Promise<AuditEntry[]> {
    const all = this.entries.map((x) => ({ ...x }));
    return grantId ? all.filter((x) => x.grantId === grantId) : all;
  }
}
