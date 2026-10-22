/**
 * Shared context + Finding builder for checks. Every check runs through the
 * engine's GuardedClient (so scope is enforced) and emits a @secscan/shared
 * Finding with CVSS + multi-framework controls from @secscan/shared.
 */
import { createHash } from 'node:crypto';
import {
  Finding, type Confidence, type Severity, type LocalizedText,
  cvss31, controlsFor, type Cvss31Metrics, type FindingCategory,
} from '@secscan/shared';
import { ScopeRefused, type GuardedClient, type Identity, type RecordedRequest, type RecordedResponse } from '@secscan/engine';

export interface CheckContext {
  client: GuardedClient;
  grantFingerprint: string;
  rootUrl: string;
  flows: RecordedRequest[];
  /** JWTs supplied for analysis (from owner test-account material). */
  tokens?: string[];
  /** Owner-supplied test identities. Flow-based probes run as the identity
   *  that captured the flow (review 2.5), so endpoints behind login are
   *  actually exercised; root scorecard checks stay anonymous. */
  identities?: Identity[];
}

export const ANON: Identity = { role: 'anonymous', sessionRef: null };

/** The identity that captured `flow`: exact role+tenant, else first of that role, else anonymous. */
export function identityFor(ctx: CheckContext, flow: RecordedRequest): Identity {
  const ids = ctx.identities ?? [];
  if (!flow.capturedAsRole) return ANON;
  return ids.find((i) => i.role === flow.capturedAsRole && (i.tenant ?? null) === (flow.capturedAsTenant ?? null))
    ?? (flow.capturedAsTenant == null ? ids.find((i) => i.role === flow.capturedAsRole) : undefined)
    ?? ANON;
}

export async function safeSend(
  ctx: CheckContext, req: RecordedRequest, identity: Identity = ANON,
): Promise<RecordedResponse | null> {
  try {
    return await ctx.client.send(req, identity);
  } catch (e) {
    if (e instanceof ScopeRefused) return null;
    throw e;
  }
}

export function header(resp: RecordedResponse, name: string): string | undefined {
  const lk = name.toLowerCase();
  for (const [k, v] of Object.entries(resp.headers)) if (k.toLowerCase() === lk) return v;
  return undefined;
}

export interface BuildArgs {
  category: FindingCategory;
  severity: Severity;
  confidence: Confidence;
  title: LocalizedText;
  description: LocalizedText;
  impact: LocalizedText;
  remediation: LocalizedText;
  asset: string;
  location?: string;
  evidence?: { kind: 'request' | 'response' | 'note'; label?: string; content: string }[];
  cvss?: Cvss31Metrics;
  idSeed: string;
}

export function build(args: BuildArgs, grantFingerprint: string): Finding {
  const id = `CHK-${args.category}-${createHash('sha256').update(args.idSeed).digest('hex').slice(0, 8)}`;
  const cvss = args.cvss ? cvss31(args.cvss) : undefined;
  return Finding.parse({
    id,
    title: args.title,
    severity: args.severity,
    cvss,
    confidence: args.confidence,
    asset: args.asset,
    location: args.location,
    description: args.description,
    impact: args.impact,
    remediation: args.remediation,
    evidence: [
      ...(args.evidence ?? []),
      { kind: 'note', label: 'grant', content: `fingerprint ${grantFingerprint.slice(0, 16)}…` },
    ],
    controls: controlsFor(args.category),
    source: 'checks',
    firstSeen: new Date().toISOString(),
  });
}
