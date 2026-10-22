/**
 * Runs a scope-gated access-control scan (Design §3, §8, §9).
 * Enforces, in order: grant is scan-allowed (AuthorizationService), every
 * target is permitted by LabPolicy (§3.2), then every outbound request is
 * additionally gated by the engine's ScopeGuard inside GuardedClient.
 *
 * Also (§7, §8): every outbound request is paced (rate limit + deadline +
 * abort), and each identity with a liveness URL is verified before the scan;
 * a dead session is dropped and reported, never allowed to produce a result.
 */
import {
  GuardedClient, ScopeGuard, fingerprint as grantFingerprint, pacedSender, runAccessControlScan,
  type HostResolver, type Identity, type PacingOptions, type RecordedRequest, type Sender,
} from '@secscan/engine';
import { runChecks } from '@secscan/checks';
import type { AuditStore } from './audit';
import { AuthorizationService } from './authorizationService';
import { LabPolicy } from './labPolicy';
import type { ScanRecord, ScanRepo } from './repositories';

export interface ScanRequest {
  engagementId: string;
  grantId: string;
  flows: RecordedRequest[];
  identities: Identity[];
  actor: string;
  /** Root URL for passive/scorecard checks; defaults to the grant's first target. */
  rootUrl?: string;
  /** Optional JWTs (from test-account material) for passive JWT analysis. */
  tokens?: string[];
  /** Skip the non-authz check suite (passive/config/active/jwt). */
  skipChecks?: boolean;
  /** Kill switch (Ctrl+C / admin stop). */
  signal?: AbortSignal;
}

export interface ScanServiceDeps {
  auth: AuthorizationService;
  lab: LabPolicy;
  scans: ScanRepo;
  audit: AuditStore;
  sender: Sender;
  fingerprintSecret: string;
  resolveHost?: HostResolver;
  /** Rate limit / deadline for every outbound request. */
  pacing?: Pick<PacingOptions, 'requestsPerSecond' | 'maxDurationMs'>;
  /** sessionRef -> URL that returns 2xx only while that session is valid. */
  liveness?: Record<string, string>;
}

export class ScanService {
  constructor(private d: ScanServiceDeps) {}

  async run(req: ScanRequest): Promise<ScanRecord> {
    const rec = await this.d.auth.assertScanAllowed(req.grantId);

    // §3.2 hard gate: every grant target AND every flow host must be allowed.
    for (const t of rec.grant.targets) this.d.lab.assertTargetAllowed(t.host);
    for (const f of req.flows) this.d.lab.assertTargetAllowed(new URL(f.url).hostname);

    const id = `scan-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
    const fp = grantFingerprint(rec.grant, this.d.fingerprintSecret);
    const guard = new ScopeGuard([rec.grant], {
      blockPrivateAddresses: this.d.lab.blockPrivateAddresses,
      resolveHost: this.d.resolveHost,
    });
    const sender = pacedSender(this.d.sender, { ...this.d.pacing, signal: req.signal });
    const client = new GuardedClient(guard, sender);

    // §7: verify sessions that have a liveness probe; drop and report dead ones.
    const skipped: string[] = [];
    const identities: Identity[] = [];
    for (const ident of req.identities) {
      const url = ident.sessionRef ? this.d.liveness?.[ident.sessionRef] : undefined;
      if (!url) { identities.push(ident); continue; }
      let ok = false;
      try {
        const r = await client.send({ method: 'GET', url }, ident);
        ok = r.status >= 200 && r.status < 300 && r.body.length > 0;
      } catch { ok = false; }
      if (ok) identities.push(ident);
      else skipped.push(`skipped: session '${ident.sessionRef}' failed its liveness probe (${url}); identity dropped`);
    }

    let result;
    try {
      result = await runAccessControlScan({
        client, grantFingerprint: fp, flows: req.flows, identities,
      });
    } catch (e) {
      const failed: ScanRecord = {
        id, engagementId: req.engagementId, grantId: req.grantId, status: 'failed',
        findings: [], notTested: client.refused.map((r) => `${r.decision}: ${r.reason}`),
        createdAt: new Date().toISOString(),
      };
      await this.d.scans.save(failed);
      await this.d.audit.append({ actor: req.actor, action: 'scan_failed', grantId: req.grantId, detail: String(e) });
      return failed;
    }

    // Non-destructive check suite (passive scorecard + safe config + active
    // detection + JWT), through the SAME guarded client, so scope still holds.
    let checksReady = 0, checksReview = 0, checksNotes: string[] = [];
    const findings = [...result.reportReady];
    const review = [...result.needsReview];
    if (!req.skipChecks) {
      const first = rec.grant.targets[0];
      const rootUrl = req.rootUrl ?? `${first.scheme}://${first.host}/`;
      const checks = await runChecks({ client, grantFingerprint: fp, rootUrl, flows: req.flows, tokens: req.tokens, identities });
      findings.push(...checks.reportReady);
      review.push(...checks.needsReview);
      checksReady = checks.reportReady.length;
      checksReview = checks.needsReview.length;
      checksNotes = checks.notTested.filter((n) => n.startsWith('stopped:') || n.startsWith('error:'));
    }

    const notTested = [...new Set([...skipped, ...result.notTested, ...checksNotes, ...client.refused.map((r) => `${r.decision}: ${r.reason}`)])];
    const scan: ScanRecord = {
      id, engagementId: req.engagementId, grantId: req.grantId, status: 'done',
      findings, review, notTested,
      telemetry: {
        confirmedFindings: findings.length,
        needsReview: result.needsReview.length + checksReview,
        authzConfirmed: result.reportReady.length,
        checksConfirmed: checksReady,
        requests: sender.stats.requests,
        durationMs: Date.now() - sender.stats.startedAt,
      },
      createdAt: new Date().toISOString(),
    };
    await this.d.scans.save(scan);
    await this.d.audit.append({
      actor: req.actor, action: 'scan_run', grantId: req.grantId,
      detail: `confirmed=${findings.length} (authz=${result.reportReady.length} checks=${checksReady}) review=${result.needsReview.length + checksReview} notTested=${notTested.length}`,
    });
    return scan;
  }
}
