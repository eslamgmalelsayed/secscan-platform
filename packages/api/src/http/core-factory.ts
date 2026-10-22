/** Builds the core service graph used by both the HTTP app and the smoke test. */
import type { HostResolver, Identity, OwnershipDeps, PacingOptions, Sender } from '@secscan/engine';
import {
  AppendOnlyAuditLog, AuthorizationService, LabPolicy, ReportService, RetestService, ScanService,
  InMemoryGrantRepo, InMemoryEngagementRepo, InMemoryScanRepo, InMemoryOwnerChallengeStore, InMemoryStopSignal,
  type AuditStore, type EngagementRepo, type GrantRepo, type Mailer, type OwnerChallengeStore, type ScanRepo,
  type ScanQueue, type StopSignal,
} from '../core';
import type { ApiAuth } from './auth';

/** Where state lives. Omit for in-memory (tests, quick local runs). */
export interface CoreStores {
  grants: GrantRepo;
  engagements: EngagementRepo;
  scans: ScanRepo;
  audit: AuditStore;
  challenges: OwnerChallengeStore;
}

export interface CoreOptions {
  lab: LabPolicy;
  sender: Sender;
  fingerprintSecret: string;
  resolveHost?: HostResolver;
  pacing?: Pick<PacingOptions, 'requestsPerSecond' | 'maxDurationMs'>;
  liveness?: Record<string, string>;
  /** Injected DNS/HTTP for ownership proofs (tests); defaults to the real network. */
  ownership?: OwnershipDeps;
  /** Required in the x-admin-token header for approve / revoke / manual ownership / manual sign.
   *  Unset = open (local dev only); the API logs a warning at boot. */
  adminToken?: string;
  /** Bearer tokens for every other route; unset = open (local dev only). */
  auth?: ApiAuth;
  /** Delivers owner sign-off codes. Unset = email sign-off disabled (manual path only). */
  mailer?: Mailer;
  /** Test identities loaded at boot (keys only are ever exposed over HTTP). */
  identities?: Identity[];
  stores?: CoreStores;
  /** When set, POST /scans queues for a worker; otherwise scans run inline. */
  scanQueue?: ScanQueue;
  /** Cross-process stop flag (defaults to in-memory for single-process runs). */
  stopSignal?: StopSignal;
}

export interface CoreGraph {
  audit: AuditStore;
  grants: GrantRepo;
  engagements: EngagementRepo;
  scans: ScanRepo;
  auth: AuthorizationService;
  scan: ScanService;
  report: ReportService;
  lab: LabPolicy;
  ownership?: OwnershipDeps;
  adminToken?: string;
  apiAuth?: ApiAuth;
  ownerEmailEnabled: boolean;
  identities: Identity[];
  retest: RetestService;
  queued: boolean;
}

export function buildCore(opts: CoreOptions): CoreGraph {
  const s: CoreStores = opts.stores ?? {
    grants: new InMemoryGrantRepo(),
    engagements: new InMemoryEngagementRepo(),
    scans: new InMemoryScanRepo(),
    audit: new AppendOnlyAuditLog(),
    challenges: new InMemoryOwnerChallengeStore(),
  };
  const auth = new AuthorizationService(
    s.grants, s.audit,
    opts.mailer ? { mailer: opts.mailer, challenges: s.challenges, secret: opts.fingerprintSecret } : undefined,
  );
  const stopSignal: StopSignal = opts.stopSignal ?? new InMemoryStopSignal();
  const scan = new ScanService({
    auth, lab: opts.lab, scans: s.scans, engagements: s.engagements, audit: s.audit,
    sender: opts.sender, fingerprintSecret: opts.fingerprintSecret, resolveHost: opts.resolveHost,
    pacing: opts.pacing, liveness: opts.liveness, scanQueue: opts.scanQueue, stopSignal,
  });
  const report = new ReportService(s.engagements, s.scans);
  const retest = new RetestService(s.scans, scan);
  return {
    audit: s.audit, grants: s.grants, engagements: s.engagements, scans: s.scans,
    auth, scan, report, retest, lab: opts.lab, ownership: opts.ownership,
    adminToken: opts.adminToken, apiAuth: opts.auth, ownerEmailEnabled: !!opts.mailer,
    identities: opts.identities ?? [], queued: !!opts.scanQueue,
  };
}

export const CORE = 'SECSCAN_CORE';
