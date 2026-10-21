/**
 * Runs the check suite and splits results the same way the scanner does:
 * confirmed -> report-ready, everything else -> human review. All checks go
 * through the guarded client, so scope is enforced regardless of which run.
 */
import { type Finding, reportable, sortFindings } from '@secscan/shared';
import type { CheckContext } from './context';
import { securityHeaders, cookies, tlsRedirect, infoDisclosure, secretsInResponse } from './passive';
import { corsMisconfig, openRedirect } from './config';
import { reflectedInput, sqliDifferential } from './active';
import { jwtChecks } from './jwt';

export interface ChecksResult {
  reportReady: Finding[];
  needsReview: Finding[];
  notTested: string[];
}

export interface RunChecksOptions {
  passive?: boolean;
  config?: boolean;
  active?: boolean;
  jwt?: boolean;
}

export async function runChecks(ctx: CheckContext, opts: RunChecksOptions = {}): Promise<ChecksResult> {
  const run = {
    passive: opts.passive ?? true,
    config: opts.config ?? true,
    active: opts.active ?? true,
    jwt: opts.jwt ?? true,
  };
  const findings: Finding[] = [];
  if (run.passive) {
    for (const check of [securityHeaders, cookies, tlsRedirect, infoDisclosure, secretsInResponse]) {
      findings.push(...(await check(ctx)));
    }
  }
  if (run.config) {
    findings.push(...(await corsMisconfig(ctx)));
    findings.push(...(await openRedirect(ctx)));
  }
  if (run.active) {
    findings.push(...(await reflectedInput(ctx)));
    findings.push(...(await sqliDifferential(ctx)));
  }
  if (run.jwt) findings.push(...jwtChecks(ctx));

  const seen = new Set<string>();
  const deduped = findings.filter((f) => (seen.has(f.id) ? false : (seen.add(f.id), true)));
  const reportReady = sortFindings(reportable(deduped));
  const ready = new Set(reportReady.map((f) => f.id));
  const needsReview = sortFindings(deduped.filter((f) => !ready.has(f.id)));
  return { reportReady, needsReview, notTested: ctx.client.refused.map((r) => `${r.decision}: ${r.reason}`) };
}
