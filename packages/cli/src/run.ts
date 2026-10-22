/**
 * One-command local scan (review §4.2). Wraps the API core graph directly —
 * no HTTP, no database — so a single call goes from "I own this site" to a
 * bilingual report.
 *
 * Because it auto-walks the authorization lifecycle, it is a DEV-TRUST path:
 * the caller is asserting, on their own machine, that they own the target.
 * The §3.2 lab lock still applies (only the given host is allowed), scope is
 * still enforced per request, and the run is still non-destructive.
 */
import { randomBytes } from 'node:crypto';
import { buildCore, LabPolicy } from '@secscan/api';
import {
  SecretStore, createHttpSender, loadIdentities,
  type Identity, type RecordedRequest, type Sender,
} from '@secscan/engine';
import { Engagement } from '@secscan/shared';

export interface CliScan {
  host: string;
  root?: string;
  flows: RecordedRequest[];
  identitiesFile?: unknown;      // parsed identities JSON (optional)
  allowPrivate?: boolean;
  rps?: number;
  maxMs?: number;
  stateChanging?: boolean;
  tokens?: string[];
  actor?: string;
  /** When set and `flows` is empty, crawl the public surface from `root` to
   *  discover endpoints (the one-URL `quick` path). */
  discover?: { maxPages?: number };
}

export interface CliDeps {
  sender?: Sender;               // injected in tests; defaults to real HTTP
  fingerprintSecret?: string;
}

export interface CliResult {
  scanId: string;
  status: string;
  confirmed: number;
  review: number;
  notTested: string[];
  telemetry?: Record<string, number | null>;
  reportAr: string;
  reportEn: string;
  grantId: string;
}

export async function runScan(opts: CliScan, deps: CliDeps = {}): Promise<CliResult> {
  const root = opts.root ?? `https://${opts.host}/`;
  const u = new URL(root);
  const scheme = u.protocol.replace(':', '');
  const port = u.port ? Number(u.port) : null;

  const store = new SecretStore();
  const loaded = opts.identitiesFile ? loadIdentities(opts.identitiesFile, store) : null;
  const identities: Identity[] = loaded?.identities ?? [];

  const core = buildCore({
    lab: new LabPolicy(false, [opts.host], { allowPrivateTargets: !!opts.allowPrivate }),
    sender: deps.sender ?? createHttpSender({ store }),
    fingerprintSecret: deps.fingerprintSecret ?? randomBytes(32).toString('hex'),
    identities,
    liveness: loaded?.liveness,
    pacing: { requestsPerSecond: opts.rps, maxDurationMs: opts.maxMs },
  });

  const now = Date.now();
  const grantId = `cli-${opts.host}-${now}`;
  const notBefore = new Date(now - 60_000).toISOString();
  const notAfter = new Date(now + 24 * 3_600_000).toISOString();

  await core.auth.createGrant({
    grantId,
    targets: [{ host: opts.host, scheme, port }],
    ownershipProof: 'dns_txt', ownershipToken: `secscan-verify-${grantId}`,
    chain: [{ party: 'cli-requester', email: 'cli@secscan.dev', role: 'requester', signedAt: notBefore, statement: 'cli dev-trust request' }],
    notBefore, notAfter, allowStateChanging: !!opts.stateChanging, status: 'pending_owner',
  }, 'cli');

  // Dev-trust: walk ownership -> owner-sign -> approve locally.
  await core.auth.recordOwnershipVerified(grantId, 'cli-dev-trust');
  await core.auth.ownerSign(grantId, {
    party: 'cli-owner', email: 'owner@secscan.dev', role: 'system_owner',
    signedAt: new Date().toISOString(), statement: 'cli dev-trust owner sign-off',
  }, 'cli-dev-trust');
  await core.auth.adminApprove(grantId, 'cli-dev-trust');

  const engagementId = `eng-${opts.host}`;
  const environment = opts.allowPrivate ? 'lab' : scheme === 'http' ? 'staging' : 'production';
  await core.engagements.save(Engagement.parse({
    id: engagementId, client: opts.host, preparedBy: 'SecScan CLI', assets: [opts.host],
    environment, authorizationRef: grantId, window: { start: notBefore, end: notAfter },
    methodology: { ar: 'اختبار صلاحيات حتمي وفحوصات غير مدمّرة', en: 'Deterministic authorization testing and non-destructive checks' },
    limitations: { ar: 'ضمن النطاق المصرّح به فقط', en: 'Authorized scope only' },
  }));

  const scan = await core.scan.run({
    engagementId, grantId, flows: opts.flows, identities,
    rootUrl: root, actor: opts.actor ?? 'cli', tokens: opts.tokens, discover: opts.discover,
  });

  return {
    scanId: scan.id, status: scan.status,
    confirmed: scan.findings.length, review: scan.review?.length ?? 0,
    notTested: scan.notTested, telemetry: scan.telemetry,
    reportAr: await core.report.render(engagementId, scan.id, 'ar'),
    reportEn: await core.report.render(engagementId, scan.id, 'en'),
    grantId,
  };
}
