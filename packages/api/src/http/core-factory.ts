/** Builds the core service graph used by both the HTTP app and the smoke test. */
import type { HostResolver, PacingOptions, Sender } from '@secscan/engine';
import {
  AppendOnlyAuditLog, AuthorizationService, LabPolicy, ReportService, ScanService,
  InMemoryGrantRepo, InMemoryEngagementRepo, InMemoryScanRepo,
} from '../core';

export interface CoreOptions {
  lab: LabPolicy;
  sender: Sender;
  fingerprintSecret: string;
  resolveHost?: HostResolver;
  pacing?: Pick<PacingOptions, 'requestsPerSecond' | 'maxDurationMs'>;
  liveness?: Record<string, string>;
}

export interface CoreGraph {
  audit: AppendOnlyAuditLog;
  grants: InMemoryGrantRepo;
  engagements: InMemoryEngagementRepo;
  scans: InMemoryScanRepo;
  auth: AuthorizationService;
  scan: ScanService;
  report: ReportService;
  lab: LabPolicy;
}

export function buildCore(opts: CoreOptions): CoreGraph {
  const audit = new AppendOnlyAuditLog();
  const grants = new InMemoryGrantRepo();
  const engagements = new InMemoryEngagementRepo();
  const scans = new InMemoryScanRepo();
  const auth = new AuthorizationService(grants, audit);
  const scan = new ScanService({
    auth, lab: opts.lab, scans, audit,
    sender: opts.sender, fingerprintSecret: opts.fingerprintSecret, resolveHost: opts.resolveHost,
    pacing: opts.pacing, liveness: opts.liveness,
  });
  const report = new ReportService(engagements, scans);
  return { audit, grants, engagements, scans, auth, scan, report, lab: opts.lab };
}

export const CORE = 'SECSCAN_CORE';
