/**
 * Append-only authorization log (Design §6).
 * Every authorization step is recorded. There is deliberately no update or
 * delete — entries can only be appended and read.
 */
export interface AuditEntry {
  id: string;
  at: string; // ISO timestamp
  actor: string; // who performed it (email / "admin" / "system")
  action: string; // e.g. grant_created, owner_signed, scan_run
  grantId?: string;
  detail?: string;
}

export class AppendOnlyAuditLog {
  private entries: AuditEntry[] = [];
  private seq = 0;

  append(e: Omit<AuditEntry, 'id' | 'at'> & { at?: string }): AuditEntry {
    const entry: AuditEntry = {
      id: `ae-${++this.seq}`,
      at: e.at ?? new Date().toISOString(),
      actor: e.actor,
      action: e.action,
      grantId: e.grantId,
      detail: e.detail,
    };
    this.entries.push(entry);
    return entry;
  }

  /** Read-only view (a copy); callers cannot mutate the log through it. */
  list(grantId?: string): AuditEntry[] {
    const all = this.entries.map((x) => ({ ...x }));
    return grantId ? all.filter((x) => x.grantId === grantId) : all;
  }
}
