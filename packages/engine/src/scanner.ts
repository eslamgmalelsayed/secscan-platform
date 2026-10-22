/**
 * Runs the deterministic access-control differ across every recorded flow and
 * every pair of owner-supplied identities, collects Findings, de-duplicates,
 * and splits them: confirmed -> report-ready, everything else -> human review.
 * Scope refusals are carried through so a report can state what was NOT tested.
 *
 * Coverage gaps are never silent (review 2.6): a flow whose captured role has
 * no supplied identity is listed in `notTested`, as is a flow that produced
 * only transport failures, so "0 findings" can be told apart from "0 tested".
 */
import { Finding, SEVERITY_ORDER, reportable, sortFindings } from '@secscan/shared';
import { AuthorizationDiffer, type DiffConfig } from './authzDiff';
import { GuardedClient, ScopeRefused } from './client';
import type { Identity, RecordedRequest } from './http';
import { ScanStopped } from './pacing';

export interface ScanResult {
  reportReady: Finding[];
  needsReview: Finding[];
  notTested: string[]; // scope refusals, verbatim
  errors: string[];
  summary(): {
    reportReady: number;
    needsReview: number;
    bySeverity: Record<string, number>;
    notTested: number;
  };
}

export interface ScannerInput {
  client: GuardedClient;
  grantFingerprint: string;
  flows: RecordedRequest[];
  identities: Identity[];
  diff?: DiffConfig;
}

export async function runAccessControlScan(input: ScannerInput): Promise<ScanResult> {
  const differ = new AuthorizationDiffer(input.client, input.grantFingerprint, input.diff);
  const found: Finding[] = [];
  const errors: string[] = [];
  const skipped: string[] = [];
  const anon: Identity = { role: 'anonymous', sessionRef: null };
  const challengers = [...input.identities, anon];

  let stopped: ScanStopped | null = null;
  outer: for (const flow of input.flows) {
    if (!flow.capturedAsRole) continue; // public/unlabeled flow: not an authz candidate (checks still cover it)
    const owner = ownerFor(flow, input.identities);
    if (!owner) {
      const who = `${flow.capturedAsRole ?? '(none)'}${flow.capturedAsTenant ? `/${flow.capturedAsTenant}` : ''}`;
      skipped.push(`skipped: no identity supplied for role '${who}' — ${flow.method} ${flow.url}`);
      continue;
    }
    for (const challenger of challengers) {
      if (sameIdentity(owner, challenger)) continue;
      try {
        const f = await differ.testObjectAccess(flow, owner, challenger);
        if (f) found.push(f);
      } catch (e) {
        if (e instanceof ScanStopped) { stopped = e; break outer; } // kill switch / deadline: keep what we have
        // Scope refusals surface via client.refused; record only unexpected errors.
        if (!(e instanceof ScopeRefused)) errors.push(String(e));
      }
    }
  }
  if (stopped) skipped.push(`stopped: ${stopped.reason} after ${stopped.requestsSent} request(s); remaining flows not tested`);

  const deduped = dedupById(found);
  const reportReady = sortFindings(reportable(deduped));
  const reportReadyIds = new Set(reportReady.map((f) => f.id));
  const needsReview = sortFindings(deduped.filter((f) => !reportReadyIds.has(f.id)));
  const notTested = [...skipped, ...input.client.refused.map((r) => `${r.decision}: ${r.reason}`)];

  return {
    reportReady,
    needsReview,
    notTested,
    errors,
    summary() {
      const bySeverity: Record<string, number> = {};
      for (const s of SEVERITY_ORDER) {
        const n = reportReady.filter((f) => f.severity === s).length;
        if (n) bySeverity[s] = n;
      }
      return {
        reportReady: reportReady.length,
        needsReview: needsReview.length,
        bySeverity,
        notTested: notTested.length,
      };
    },
  };
}

/** Exact role+tenant match first; a flow with no tenant recorded (HAR default)
 *  falls back to the first identity of that role. A flow with no role at all
 *  has no owner and is skipped (reported), never silently run as anonymous. */
function ownerFor(flow: RecordedRequest, identities: Identity[]): Identity | undefined {
  if (!flow.capturedAsRole) return undefined;
  const exact = identities.find((i) => i.role === flow.capturedAsRole && (i.tenant ?? null) === (flow.capturedAsTenant ?? null));
  if (exact) return exact;
  if (flow.capturedAsTenant == null) return identities.find((i) => i.role === flow.capturedAsRole);
  return undefined;
}
function sameIdentity(a: Identity, b: Identity): boolean {
  return a.role === b.role && (a.tenant ?? null) === (b.tenant ?? null) &&
    (a.sessionRef ?? null) === (b.sessionRef ?? null);
}
function dedupById(findings: Finding[]): Finding[] {
  const seen = new Map<string, Finding>();
  for (const f of findings) if (!seen.has(f.id)) seen.set(f.id, f);
  return [...seen.values()];
}
