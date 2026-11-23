/**
 * Scope-gated scans (Design §3, §8, §9) with an optional queue (review gap 1).
 *
 * Preconditions are checked up front (grant scan-allowed, every target lab-
 * allowed, and the engagement exists — review gap 5), so a bad request fails
 * immediately instead of at report time.
 *
 * enqueue(): if a scanQueue is configured, a 'queued' record is saved, a job
 * (carrying NO secrets — identities travel as keys only) is pushed, and the
 * request returns right away. A worker process then calls execute(), which
 * moves the record queued -> running -> done. With no queue (dev/CLI/tests)
 * enqueue() runs the scan inline and returns the finished record.
 *
 * Every outbound request is paced (rate limit + deadline) and abortable; the
 * stop signal (review gap 3) is polled so an operator can halt a running scan.
 */
import {
  GuardedClient, ScanStopped, ScopeGuard, discoverFlows, fingerprint as grantFingerprint, pacedSender, runAccessControlScan,
  type HostResolver, type Identity, type PacingOptions, type RecordedRequest, type Sender,
} from '@secscan/engine';
import { runChecks } from '@secscan/checks';
import type { AuditStore } from './audit';
import { AuthorizationService } from './authorizationService';
import { LabPolicy } from './labPolicy';
import type { EngagementRepo, ScanRecord, ScanRepo } from './repositories';
import { InMemoryStopSignal, pollStop, type StopSignal } from './stopSignal';

export class ScanPreconditionError extends Error {
  constructor(msg: string) { super(msg); this.name = 'ScanPreconditionError'; }
}

export interface ScanRequest {
  engagementId: string;
  grantId: string;
  flows: RecordedRequest[];
  identities: Identity[];
  actor: string;
  rootUrl?: string;
  tokens?: string[];
  skipChecks?: boolean;
  signal?: AbortSignal;
  /** When set and `flows` is empty, the scan crawls the public surface from
   *  `rootUrl` (or the grant's first target) to discover GET endpoints itself —
   *  the one-URL path. Discovered flows are anonymous; the IDOR engine still
   *  needs identities. */
  discover?: { maxPages?: number; maxFlows?: number };
}

/** Job placed on the queue. Carries identity KEYS only — never secrets, which
 *  the worker resolves from its own SecretStore (review gap 1). */
export interface QueuedScan {
  scanId: string;
  engagementId: string;
  grantId: string;
  flows: RecordedRequest[];
  identities: Identity[];
  rootUrl?: string;
  skipChecks?: boolean;
  actor: string;
  discover?: { maxPages?: number; maxFlows?: number };
}

export interface ScanQueue {
  add(job: QueuedScan): Promise<void>;
}

export interface ScanServiceDeps {
  auth: AuthorizationService;
  lab: LabPolicy;
  scans: ScanRepo;
  engagements: EngagementRepo;
  audit: AuditStore;
  sender: Sender;
  fingerprintSecret: string;
  resolveHost?: HostResolver;
  pacing?: Pick<PacingOptions, 'requestsPerSecond' | 'maxDurationMs'>;
  liveness?: Record<string, string>;
  /** When set, enqueue() queues the scan for a worker; otherwise it runs inline. */
  scanQueue?: ScanQueue;
  /** Shared stop flag; defaults to in-memory (single-process). */
  stopSignal?: StopSignal;
}

const newId = () => `scan-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;

export class ScanService {
  private stop: StopSignal;
  constructor(private d: ScanServiceDeps) {
    this.stop = d.stopSignal ?? new InMemoryStopSignal();
  }

  /** Validate everything that should reject the request synchronously. */
  private async preflight(req: { engagementId: string; grantId: string; flows: RecordedRequest[]; discover?: unknown; rootUrl?: string }) {
    const rec = await this.d.auth.assertScanAllowed(req.grantId);
    for (const t of rec.grant.targets) this.d.lab.assertTargetAllowed(t.host);
    for (const f of req.flows) this.d.lab.assertTargetAllowed(new URL(f.url).hostname);
    if (req.rootUrl) this.d.lab.assertTargetAllowed(new URL(req.rootUrl).hostname);
    if (!req.flows.length && !req.discover) {
      throw new ScanPreconditionError('no flows supplied and discovery is off: import flows or enable discover');
    }
    if (!(await this.d.engagements.get(req.engagementId))) {
      throw new ScanPreconditionError(`engagement ${req.engagementId} not found`);
    }
    return rec;
  }

  /** Enqueue for a worker, or run inline when no queue is configured. */
  async enqueue(req: ScanRequest): Promise<ScanRecord> {
    await this.preflight(req);
    const id = newId();
    if (!this.d.scanQueue) return this.execute(id, req);
    const queued: ScanRecord = {
      id, engagementId: req.engagementId, grantId: req.grantId, status: 'queued',
      findings: [], review: [], notTested: [], createdAt: new Date().toISOString(),
    };
    await this.d.scans.save(queued);
    await this.d.scanQueue.add({
      scanId: id, engagementId: req.engagementId, grantId: req.grantId, flows: req.flows,
      identities: req.identities, rootUrl: req.rootUrl, skipChecks: req.skipChecks, actor: req.actor,
      discover: req.discover,
    });
    await this.d.audit.append({ actor: req.actor, action: 'scan_queued', grantId: req.grantId, detail: id });
    return queued;
  }

  /** Inline convenience (CLI, tests): run to completion and return the record. */
  async run(req: ScanRequest): Promise<ScanRecord> {
    return this.execute(newId(), req);
  }

  /** Run one scan to completion, updating the record through running -> done. */
  async execute(scanId: string, req: ScanRequest): Promise<ScanRecord> {
    const rec = await this.preflight(req); // re-checked at run time (grant may have been revoked)
    const createdAt = (await this.d.scans.get(scanId))?.createdAt ?? new Date().toISOString();
    await this.d.scans.save({
      id: scanId, engagementId: req.engagementId, grantId: req.grantId, status: 'running',
      findings: [], review: [], notTested: [], createdAt,
    });

    const fp = grantFingerprint(rec.grant, this.d.fingerprintSecret);
    const guard = new ScopeGuard([rec.grant], {
      blockPrivateAddresses: this.d.lab.blockPrivateAddresses, resolveHost: this.d.resolveHost,
    });
    const controller = new AbortController();
    if (req.signal?.aborted) controller.abort();
    else req.signal?.addEventListener('abort', () => controller.abort(), { once: true });
    const stopPoll = pollStop(this.stop, scanId, controller);
    const sender = pacedSender(this.d.sender, { ...this.d.pacing, signal: controller.signal });
    const client = new GuardedClient(guard, sender);
    let stopped = false;

    try {
      // One-URL path: when no flows were supplied, crawl the public surface from
      // the root through this same scope-guarded, paced client. When test
      // identities are supplied we crawl AS the first one and stamp its role, so
      // the discovered endpoints become authorization candidates and the full
      // suite (authz-diffing + checks) runs on the logged-in surface; the authz
      // engine then replays each under the other identities. With no identities
      // the crawl is anonymous — public surface only, no object-level checks.
      const discoverNotes: string[] = [];
      let flows = req.flows;
      const rootForCrawl = req.rootUrl ?? `${rec.grant.targets[0].scheme}://${rec.grant.targets[0].host}/`;
      if (!flows.length && req.discover) {
        const crawlAs = req.identities[0]; // undefined => anonymous crawl
        flows = await discoverFlows(client, rootForCrawl, {
          maxPages: req.discover.maxPages, maxFlows: req.discover.maxFlows,
          identity: crawlAs, capturedAsRole: crawlAs?.role, capturedAsTenant: crawlAs?.tenant ?? null,
        });
        discoverNotes.push(`discovered ${flows.length} endpoint(s) by crawling ${rootForCrawl}${crawlAs ? ` as '${crawlAs.role}${crawlAs.tenant ? '/' + crawlAs.tenant : ''}'` : ' anonymously'}`);
        if (!req.identities.length) {
          discoverNotes.push('crawl ran anonymously: object-level (IDOR/cross-tenant) checks need test identities and were not run');
        } else {
          discoverNotes.push('authorization checks ran on the discovered surface; an object match on a crawled endpoint goes to review as `likely` (no owner label) — confirm ownership to promote it');
        }
      }

      // §7: verify sessions that have a liveness probe; drop and report dead ones.
      const skipped: string[] = [...discoverNotes];
      const identities: Identity[] = [];
      for (const ident of req.identities) {
        const url = ident.sessionRef ? this.d.liveness?.[ident.sessionRef] : undefined;
        if (!url) { identities.push(ident); continue; }
        let ok = false;
        try { const r = await client.send({ method: 'GET', url }, ident); ok = r.status >= 200 && r.status < 300 && r.body.length > 0; } catch { ok = false; }
        if (ok) identities.push(ident);
        else skipped.push(`skipped: session '${ident.sessionRef}' failed its liveness probe (${url}); identity dropped`);
      }

      let result;
      try {
        result = await runAccessControlScan({ client, grantFingerprint: fp, flows, identities });
      } catch (e) {
        if (e instanceof ScanStopped) { stopped = true; result = { reportReady: [], needsReview: [], notTested: [`stopped: ${e.reason} during access-control run`] }; }
        else throw e;
      }
      // runAccessControlScan catches ScanStopped internally and reports it as a
      // "stopped:" note rather than rethrowing — treat that as a stop too.
      if (result.notTested.some((n) => n.startsWith('stopped:'))) stopped = true;

      let checksReady = 0, checksReview = 0, checksNotes: string[] = [];
      const findings = [...result.reportReady];
      const review = [...result.needsReview];
      if (!req.skipChecks && !stopped) {
        const first = rec.grant.targets[0];
        const rootUrl = req.rootUrl ?? `${first.scheme}://${first.host}/`;
        const checks = await runChecks({ client, grantFingerprint: fp, rootUrl, flows, tokens: req.tokens, identities });
        findings.push(...checks.reportReady);
        review.push(...checks.needsReview);
        checksReady = checks.reportReady.length;
        checksReview = checks.needsReview.length;
        checksNotes = checks.notTested.filter((n) => n.startsWith('stopped:') || n.startsWith('error:'));
        if (checksNotes.some((n) => n.startsWith('stopped:'))) stopped = true;
      }

      const notTested = [...new Set([...skipped, ...result.notTested, ...checksNotes, ...client.refused.map((r) => `${r.decision}: ${r.reason}`)])];
      if (stopped) notTested.push('stopped by operator: results are partial');
      const scan: ScanRecord = {
        id: scanId, engagementId: req.engagementId, grantId: req.grantId, status: stopped ? 'partial' : 'done',
        findings, review, notTested,
        telemetry: {
          confirmedFindings: findings.length, needsReview: result.needsReview.length + checksReview,
          authzConfirmed: result.reportReady.length, checksConfirmed: checksReady,
          requests: sender.stats.requests, durationMs: Date.now() - sender.stats.startedAt,
          stopped: stopped ? 1 : 0,
        },
        createdAt,
      };
      await this.d.scans.save(scan);
      await this.d.audit.append({
        actor: req.actor, action: stopped ? 'scan_stopped' : 'scan_run', grantId: req.grantId,
        detail: `confirmed=${findings.length} (authz=${result.reportReady.length} checks=${checksReady}) review=${result.needsReview.length + checksReview} notTested=${notTested.length}`,
      });
      return scan;
    } catch (e) {
      const failed: ScanRecord = {
        id: scanId, engagementId: req.engagementId, grantId: req.grantId, status: 'failed',
        findings: [], review: [], notTested: client.refused.map((r) => `${r.decision}: ${r.reason}`), createdAt,
      };
      await this.d.scans.save(failed);
      await this.d.audit.append({ actor: req.actor, action: 'scan_failed', grantId: req.grantId, detail: String(e).slice(0, 300) });
      return failed;
    } finally {
      stopPoll();
      await this.stop.clear(scanId);
    }
  }

  /** Operator stop: flag the scan; the running execute() polls and aborts. */
  async requestStop(scanId: string, actor: string): Promise<void> {
    await this.stop.request(scanId);
    await this.d.audit.append({ actor, action: 'scan_stop_requested', detail: scanId });
  }
}
