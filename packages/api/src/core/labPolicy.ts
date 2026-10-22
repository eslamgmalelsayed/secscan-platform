/**
 * The §3.2 lock. Until the legal questions in §13 are resolved, the platform
 * is restricted to an internal lab allow-list; any other target is rejected.
 * This is a hard gate, not configuration a scan can override.
 *
 * Private-address blocking is a SEPARATE decision (review 2.4): a lab target
 * may legitimately live on a private network, but that is opted into
 * explicitly per deployment, never implied by the legal flag.
 */
export interface LabPolicyOptions {
  /** Permit targets that resolve to private/reserved addresses (local lab). Default false. */
  allowPrivateTargets?: boolean;
}

export class LabPolicy {
  private allow: Set<string>;
  private readonly allowPrivate: boolean;

  constructor(
    /** Flip to true ONLY once §13 legal work is signed off. */
    public readonly legalResolved: boolean,
    /** Exact hostnames permitted while legalResolved is false. */
    labAllowList: string[] = [],
    opts: LabPolicyOptions = {},
  ) {
    this.allow = new Set(labAllowList.map((h) => h.toLowerCase()));
    this.allowPrivate = opts.allowPrivateTargets ?? false;
  }

  /** Permit a host at runtime. Used ONLY by dev-trust quick scans, where a
   *  local tester asserts ownership of the URL they paste; never reachable
   *  without SECSCAN_DEV_TRUST. The lab lock stays closed for everything else. */
  allowHost(host: string): void {
    this.allow.add(host.toLowerCase());
  }

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

  /** Whether the scope guard must refuse private/reserved addresses. */
  get blockPrivateAddresses(): boolean {
    return !this.allowPrivate;
  }
}

export class LabPolicyError extends Error {
  constructor(msg: string) { super(msg); this.name = 'LabPolicyError'; }
}
