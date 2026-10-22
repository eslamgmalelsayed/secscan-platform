/** Builds the core service graph used by both the HTTP app and the smoke test. */
import type { HostResolver, Identity, OwnershipDeps, PacingOptions, Sender } from '@secscan/engine';
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
  /** Injected DNS/HTTP for ownership proofs (tests); defaults to the real network. */
  ownership?: OwnershipDeps;
  /** Required in the x-admin-token header for approve / revoke / manual ownership.
   *  Unset = open (local dev only); the API logs a warning at boot. */
  adminToken?: string;
  /** Test identities loaded at boot (keys only are ever exposed over HTTP). */
  identities?: Identity[];
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
  ownership?: OwnershipDeps;
  adminToken?: string;
  identities: Identity[];
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
  return { audit, grants, engagements, scans, auth, scan, report, lab: opts.lab, ownership: opts.ownership, adminToken: opts.adminToken, identities: opts.identities ?? [] };
}

export const CORE = 'SECSCAN_CORE';
