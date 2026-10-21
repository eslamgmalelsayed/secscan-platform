/**
 * Runs the deterministic access-control differ across every recorded flow and
 * every pair of owner-supplied identities, collects Findings, de-duplicates,
 * and splits them: confirmed -> report-ready, everything else -> human review.
 * Scope refusals are carried through so a report can state what was NOT tested.
 */
import { Finding, SEVERITY_ORDER, reportable, sortFindings } from '@secscan/shared';
import { AuthorizationDiffer, type DiffConfig } from './authzDiff';
import { GuardedClient } from './client';
import type { Identity, RecordedRequest } from './http';

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
  const anon: Identity = { role: 'anonymous', sessionRef: null };
  const challengers = [...input.identities, anon];

  for (const flow of input.flows) {
    const owner = input.identities.find((i) => sameRole(i, flow)) ?? anon;
    for (const challenger of challengers) {
      if (sameIdentity(owner, challenger)) continue;
      try {
        const f = await differ.testObjectAccess(flow, owner, challenger);
        if (f) found.push(f);
      } catch (e) {
        // Scope refusals surface via client.refused; record only unexpected errors.
        if (!String(e).startsWith('deny_')) errors.push(String(e));
      }
    }
  }

  const deduped = dedupById(found);
  const reportReady = sortFindings(reportable(deduped));
  const reportReadyIds = new Set(reportReady.map((f) => f.id));
  const needsReview = sortFindings(deduped.filter((f) => !reportReadyIds.has(f.id)));
  const notTested = input.client.refused.map((r) => `${r.decision}: ${r.reason}`);

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

function sameRole(i: Identity, flow: RecordedRequest): boolean {
  return i.role === flow.capturedAsRole && (i.tenant ?? null) === (flow.capturedAsTenant ?? null);
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
