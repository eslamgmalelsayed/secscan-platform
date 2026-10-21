/**
 * Runs a scope-gated access-control scan (Design §3, §8, §9).
 * Enforces, in order: grant is scan-allowed (AuthorizationService), every
 * target is permitted by LabPolicy (§3.2), then every outbound request is
 * additionally gated by the engine's ScopeGuard inside GuardedClient.
 */
import {
  GuardedClient, ScopeGuard, fingerprint as grantFingerprint, runAccessControlScan,
  type HostResolver, type Identity, type RecordedRequest, type Sender,
} from '@secscan/engine';
import { runChecks } from '@secscan/checks';
import { AppendOnlyAuditLog } from './audit';
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
}

export interface ScanServiceDeps {
  auth: AuthorizationService;
  lab: LabPolicy;
  scans: ScanRepo;
  audit: AppendOnlyAuditLog;
  sender: Sender;
  fingerprintSecret: string;
  resolveHost?: HostResolver;
}

export class ScanService {
  constructor(private d: ScanServiceDeps) {}

  async run(req: ScanRequest): Promise<ScanRecord> {
    const rec = this.d.auth.assertScanAllowed(req.grantId);

    // §3.2 hard gate: every grant target AND every flow host must be allowed.
    for (const t of rec.grant.targets) this.d.lab.assertTargetAllowed(t.host);
    for (const f of req.flows) this.d.lab.assertTargetAllowed(new URL(f.url).hostname);

    const id = `scan-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
    const fp = grantFingerprint(rec.grant, this.d.fingerprintSecret);
    const guard = new ScopeGuard([rec.grant], {
      blockPrivateAddresses: this.d.lab.blockPrivateAddresses,
      resolveHost: this.d.resolveHost,
    });
    const client = new GuardedClient(guard, this.d.sender);

    let result;
    try {
      result = await runAccessControlScan({
        client, grantFingerprint: fp, flows: req.flows, identities: req.identities,
      });
    } catch (e) {
      const failed: ScanRecord = {
        id, engagementId: req.engagementId, grantId: req.grantId, status: 'failed',
        findings: [], notTested: client.refused.map((r) => `${r.decision}: ${r.reason}`),
        createdAt: new Date().toISOString(),
      };
      this.d.scans.save(failed);
      this.d.audit.append({ actor: req.actor, action: 'scan_failed', grantId: req.grantId, detail: String(e) });
      return failed;
    }

    // Non-destructive check suite (passive scorecard + safe config + active
    // detection + JWT), through the SAME guarded client, so scope still holds.
    let checksReady = 0, checksReview = 0;
    const findings = [...result.reportReady];
    if (!req.skipChecks) {
      const first = rec.grant.targets[0];
      const rootUrl = req.rootUrl ?? `${first.scheme}://${first.host}/`;
      const checks = await runChecks({ client, grantFingerprint: fp, rootUrl, flows: req.flows, tokens: req.tokens });
      findings.push(...checks.reportReady);
      checksReady = checks.reportReady.length;
      checksReview = checks.needsReview.length;
    }

    const notTested = [...new Set([...result.notTested, ...client.refused.map((r) => `${r.decision}: ${r.reason}`)])];
    const scan: ScanRecord = {
      id, engagementId: req.engagementId, grantId: req.grantId, status: 'done',
      findings, notTested,
      telemetry: {
        confirmedFindings: findings.length,
        needsReview: result.needsReview.length + checksReview,
        authzConfirmed: result.reportReady.length,
        checksConfirmed: checksReady,
      },
      createdAt: new Date().toISOString(),
    };
    this.d.scans.save(scan);
    this.d.audit.append({
      actor: req.actor, action: 'scan_run', grantId: req.grantId,
      detail: `confirmed=${findings.length} (authz=${result.reportReady.length} checks=${checksReady}) review=${result.needsReview.length + checksReview} notTested=${notTested.length}`,
    });
    return scan;
  }
}
