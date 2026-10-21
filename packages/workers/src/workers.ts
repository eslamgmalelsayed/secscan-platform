/**
 * Worker logic (Design §4). Three stages, each a pure handler registered on a
 * Queue so they compose without infra:
 *
 *   Discovery  — expand a grant's targets into a worklist (passive only here;
 *                active tool selection is deferred to the separate engine doc).
 *   Scan       — run one authorized scan job via an injected runner (the API's
 *                ScanService in production), through the mandatory scope gate.
 *   Validator  — re-test a finding (e.g. after a fix) via an injected retest.
 *
 * None of these reach the network themselves; they orchestrate injected
 * functions, so the safety gate lives in exactly one place (the engine's
 * GuardedClient) no matter how jobs are scheduled.
 */
import type { JobHandler, Queue } from './queue';

// ---- Discovery ----
export interface DiscoveryJob { grantId: string; hosts: string[] }
export interface Worklist { grantId: string; targets: string[] }

export function discoveryHandler(): JobHandler<DiscoveryJob, Worklist> {
  return async (job) => ({
    grantId: job.data.grantId,
    targets: [...new Set(job.data.hosts.map((h) => h.toLowerCase()))],
  });
}

// ---- Scan ----
export interface ScanJob {
  engagementId: string;
  grantId: string;
  flows: unknown[];
  identities: unknown[];
}
export interface ScanOutcome { scanId: string; status: string; confirmed: number }

/** `runner` is the API ScanService.run (scope-gated); injected for testability. */
export function scanHandler(
  runner: (job: ScanJob) => Promise<{ id: string; status: string; findings: unknown[] }>,
): JobHandler<ScanJob, ScanOutcome> {
  return async (job) => {
    const r = await runner(job.data);
    return { scanId: r.id, status: r.status, confirmed: r.findings.length };
  };
}

// ---- Validator ----
export interface ValidateJob { findingId: string }
export interface ValidationResult { findingId: string; result: 'fixed' | 'still_open' }

/** `retest` returns true if the issue is gone now. */
export function validatorHandler(
  retest: (findingId: string) => Promise<boolean>,
): JobHandler<ValidateJob, ValidationResult> {
  return async (job) => ({
    findingId: job.data.findingId,
    result: (await retest(job.data.findingId)) ? 'fixed' : 'still_open',
  });
}

/** Register a handler on a queue (sugar). */
export function attach<T, R>(queue: Queue<T, R>, handler: JobHandler<T, R>): Queue<T, R> {
  queue.process(handler);
  return queue;
}
