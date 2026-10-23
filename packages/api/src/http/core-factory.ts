/** Builds the core service graph used by both the HTTP app and the smoke test. */
import type { HostResolver, Identity, OwnershipDeps, PacingOptions, Sender, SecretStore, SessionMaterial } from '@secscan/engine';
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
  /** The SAME secret store the sender uses, so captured logins resolve at send
   *  time. Required for runtime identity capture; omit for a read-only setup. */
  store?: SecretStore;
  stores?: CoreStores;
  /** When set, POST /scans queues for a worker; otherwise scans run inline. */
  scanQueue?: ScanQueue;
  /** Cross-process stop flag (defaults to in-memory for single-process runs). */
  stopSignal?: StopSignal;
  /** Local dev-trust: enables POST /scans/quick (auto-grant + crawl from a URL).
   *  Loopback only; never for a shared deployment. Default false. */
  devTrust?: boolean;
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
  devTrust: boolean;
  /** Add a test login at runtime: material goes into the shared store, the
   *  identity is appended (used by the next scan). Returns the identity key. */
  captureIdentity(role: string, tenant: string | null, material: SessionMaterial, liveness?: string): { role: string; tenant: string | null; sessionRef: string };
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
  // Mutable so runtime-captured logins are seen by the next scan; the scan
  // service reads the same liveness object.
  const identities: Identity[] = opts.identities ? [...opts.identities] : [];
  const liveness: Record<string, string> = { ...(opts.liveness ?? {}) };
  const scan = new ScanService({
    auth, lab: opts.lab, scans: s.scans, engagements: s.engagements, audit: s.audit,
    sender: opts.sender, fingerprintSecret: opts.fingerprintSecret, resolveHost: opts.resolveHost,
    pacing: opts.pacing, liveness, scanQueue: opts.scanQueue, stopSignal,
  });
  const report = new ReportService(s.engagements, s.scans);
  const retest = new RetestService(s.scans, scan);
  return {
    audit: s.audit, grants: s.grants, engagements: s.engagements, scans: s.scans,
    auth, scan, report, retest, lab: opts.lab, ownership: opts.ownership,
    adminToken: opts.adminToken, apiAuth: opts.auth, ownerEmailEnabled: !!opts.mailer,
    identities, queued: !!opts.scanQueue, devTrust: !!opts.devTrust,
    captureIdentity(role, tenant, material, live) {
      const sessionRef = tenant ? `${role}/${tenant}` : role;
      opts.store?.put(sessionRef, material);
      if (live) liveness[sessionRef] = live;
      if (!identities.some((i) => i.sessionRef === sessionRef)) identities.push({ role, tenant: tenant ?? null, sessionRef });
      return { role, tenant: tenant ?? null, sessionRef };
    },
  };
}

export const CORE = 'SECSCAN_CORE';
