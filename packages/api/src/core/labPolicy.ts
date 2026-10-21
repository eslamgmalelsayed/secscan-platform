/**
 * The §3.2 lock. Until the legal questions in §13 are resolved, the platform
 * is restricted to an internal lab allow-list; any other target is rejected.
 * This is a hard gate, not configuration a scan can override.
 */
export class LabPolicy {
  constructor(
    /** Flip to true ONLY once §13 legal work is signed off. */
    public readonly legalResolved: boolean,
    /** Exact hostnames permitted while legalResolved is false. */
    private readonly labAllowList: string[] = [],
  ) {}

  private allow = new Set(this.labAllowList.map((h) => h.toLowerCase()));

  isTargetAllowed(host: string): boolean {
    if (this.legalResolved) return true;
    return this.allow.has(host.toLowerCase());
  }

  assertTargetAllowed(host: string): void {
    if (!this.isTargetAllowed(host)) {
      throw new LabPolicyError(
        `target '${host}' is not in the lab allow-list; active testing of external targets is locked until legal sign-off (§3.2/§13)`,
      );
    }
  }

  /** In lab mode, targets are internal, so private addresses are expected. */
  get blockPrivateAddresses(): boolean {
    return this.legalResolved;
  }
}

export class LabPolicyError extends Error {
  constructor(msg: string) { super(msg); this.name = 'LabPolicyError'; }
}
