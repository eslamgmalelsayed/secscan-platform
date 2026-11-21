/**
 * Postgres-backed implementations of the core store interfaces (Design §4).
 * Same contracts as the in-memory stores; every write that touches more than
 * one table runs in a transaction so a crash never leaves half a grant/scan.
 */
import { PrismaPg } from '@prisma/adapter-pg';
import type { AuthorizationGrant, AuthorizationChainLink } from '@secscan/engine';
import type { Engagement, Finding, Project } from '@secscan/shared';
import { PrismaClient, type Prisma } from '../generated/prisma/client';
import type { AuditEntry, AuditInput, AuditStore } from '../core/audit';
import type { OwnerChallenge, OwnerChallengeStore } from '../core/ownerSignature';
import type { EngagementRepo, GrantRecord, GrantRepo, ScanRecord, ScanRepo } from '../core/repositories';
import type { CoreStores } from '../http/core-factory';

type Db = InstanceType<typeof PrismaClient>;
const iso = (d: Date) => d.toISOString();

// ---------------- grants ----------------

const grantInclude = {
  targets: { orderBy: { position: 'asc' } },
  chain: { orderBy: { position: 'asc' } },
} as const;

export class PrismaGrantRepo implements GrantRepo {
  constructor(private db: Db) {}

  async save(rec: GrantRecord): Promise<void> {
    const g = rec.grant;
    const data = {
      ownershipProof: g.ownershipProof, ownershipToken: g.ownershipToken,
      ownershipVerified: rec.ownershipVerified, ownershipMethod: rec.ownershipMethod ?? null,
      adminApproved: rec.adminApproved, status: g.status,
      notBefore: new Date(g.notBefore), notAfter: new Date(g.notAfter),
      allowStateChanging: g.allowStateChanging,
    };
    await this.db.$transaction([
      this.db.grant.upsert({ where: { id: g.grantId }, create: { id: g.grantId, ...data }, update: data }),
      this.db.target.deleteMany({ where: { grantId: g.grantId } }),
      this.db.chainLink.deleteMany({ where: { grantId: g.grantId } }),
      this.db.target.createMany({
        data: g.targets.map((t, i) => ({ grantId: g.grantId, position: i, host: t.host, scheme: t.scheme, port: t.port })),
      }),
      this.db.chainLink.createMany({
        data: g.chain.map((l, i) => ({
          grantId: g.grantId, position: i, party: l.party, email: l.email, role: l.role,
          statement: l.statement, signedAt: new Date(l.signedAt),
        })),
      }),
    ]);
  }

  async get(grantId: string): Promise<GrantRecord | undefined> {
    const row = await this.db.grant.findUnique({ where: { id: grantId }, include: grantInclude });
    return row ? toGrantRecord(row) : undefined;
  }

  async list(): Promise<GrantRecord[]> {
    const rows = await this.db.grant.findMany({ include: grantInclude, orderBy: { createdAt: 'asc' } });
    return rows.map(toGrantRecord);
  }
}

function toGrantRecord(row: Prisma.GrantGetPayload<{ include: typeof grantInclude }>): GrantRecord {
  const grant: AuthorizationGrant = {
    grantId: row.id,
    targets: row.targets.map((t: any) => ({ host: t.host, scheme: t.scheme as 'http' | 'https', port: t.port })),
    ownershipProof: row.ownershipProof as AuthorizationGrant['ownershipProof'],
    ownershipToken: row.ownershipToken,
    chain: row.chain.map((l: any): AuthorizationChainLink => ({
      party: l.party, email: l.email, role: l.role as AuthorizationChainLink['role'],
      signedAt: iso(l.signedAt), statement: l.statement,
    })),
    notBefore: iso(row.notBefore),
    notAfter: iso(row.notAfter),
    allowStateChanging: row.allowStateChanging,
    status: row.status,
  };
  return {
    grant,
    ownershipVerified: row.ownershipVerified,
    ownershipMethod: (row.ownershipMethod ?? undefined) as GrantRecord['ownershipMethod'],
    adminApproved: row.adminApproved,
  };
}

// ---------------- engagements ----------------

export class PrismaEngagementRepo implements EngagementRepo {
  constructor(private db: Db) {}

  async save(e: Engagement): Promise<void> {
    const data = {
      client: e.client, preparedBy: e.preparedBy, environment: e.environment,
      authorizationRef: e.authorizationRef,
      windowStart: new Date(e.window.start), windowEnd: new Date(e.window.end),
      assets: e.assets,
      methodologyAr: e.methodology.ar, methodologyEn: e.methodology.en,
      limitationsAr: e.limitations.ar, limitationsEn: e.limitations.en,
    };
    await this.db.engagement.upsert({ where: { id: e.id }, create: { id: e.id, ...data }, update: data });
  }

  async get(id: string): Promise<Engagement | undefined> {
    const r = await this.db.engagement.findUnique({ where: { id } });
    return r ? toEngagement(r) : undefined;
  }

  async list(): Promise<Engagement[]> {
    return (await this.db.engagement.findMany({ orderBy: { id: 'asc' } })).map(toEngagement);
  }
}

function toEngagement(r: Prisma.EngagementGetPayload<object>): Engagement {
  return {
    id: r.id, client: r.client, preparedBy: r.preparedBy, assets: r.assets,
    environment: r.environment, authorizationRef: r.authorizationRef,
    window: { start: iso(r.windowStart), end: iso(r.windowEnd) },
    methodology: { ar: r.methodologyAr, en: r.methodologyEn },
    limitations: { ar: r.limitationsAr, en: r.limitationsEn },
  };
}

// ---------------- scans + findings ----------------

export class PrismaScanRepo implements ScanRepo {
  constructor(private db: Db) {}

  async appendRetest(scanId:string,findingId:string,entry:Finding['retests'][number]) {
    const count=await this.db.$executeRaw`UPDATE "Finding" SET "retests"="retests" || ${JSON.stringify([entry])}::jsonb,
      "status"=CASE WHEN ${entry.result}='still_open' THEN 'open' ELSE "status" END
      WHERE "scanId"=${scanId} AND "id"=${findingId} AND NOT "reviewQueue"`;
    if (!count) throw new Error('finding not found');
  }

  async save(s: ScanRecord): Promise<void> {
    const data = {
      engagementId: s.engagementId, grantId: s.grantId, status: s.status,
      notTested: s.notTested,
      telemetry: (s.telemetry ?? undefined) as Prisma.InputJsonValue | undefined,
      createdAt: new Date(s.createdAt),
    };
    const rows = [
      ...s.findings.map((f) => ({ f, review: false })),
      ...(s.review ?? []).map((f) => ({ f, review: true })),
    ].map(({ f, review }, i) => findingRow(s.id, f, i, review));
    await this.db.$transaction([
      this.db.scan.upsert({ where: { id: s.id }, create: { id: s.id, ...data }, update: data }),
      this.db.finding.deleteMany({ where: { scanId: s.id } }),
      this.db.finding.createMany({ data: rows }),
    ]);
  }

  async get(id: string): Promise<ScanRecord | undefined> {
    const r = await this.db.scan.findUnique({ where: { id }, include: { findings: { orderBy: { position: 'asc' } } } });
    return r ? toScan(r) : undefined;
  }

  async list(engagementId?: string): Promise<ScanRecord[]> {
    const rows = await this.db.scan.findMany({
      where: engagementId ? { engagementId } : undefined,
      include: { findings: { orderBy: { position: 'asc' } } },
      orderBy: { createdAt: 'asc' },
    });
    return rows.map(toScan);
  }
}

function findingRow(scanId: string, f: Finding, position: number, reviewQueue: boolean): Prisma.FindingCreateManyInput {
  return {
    id: f.id, scanId, position, reviewQueue,
    severity: f.severity, cvssScore: f.cvss?.score ?? null, cvssVector: f.cvss?.vector ?? null,
    confidence: f.confidence, status: f.status, asset: f.asset, location: f.location ?? null,
    titleAr: f.title.ar, titleEn: f.title.en,
    descriptionAr: f.description.ar, descriptionEn: f.description.en,
    impactAr: f.impact.ar, impactEn: f.impact.en,
    remediationAr: f.remediation.ar, remediationEn: f.remediation.en,
    evidence: f.evidence as Prisma.InputJsonValue,
    controls: f.controls as Prisma.InputJsonValue,
    retests: f.retests as Prisma.InputJsonValue,
    source: f.source, firstSeen: new Date(f.firstSeen),
  };
}

function toFinding(r: Prisma.FindingGetPayload<object>): Finding {
  return {
    id: r.id,
    title: { ar: r.titleAr, en: r.titleEn },
    severity: r.severity as Finding['severity'],
    ...(r.cvssScore != null ? { cvss: { score: r.cvssScore, ...(r.cvssVector ? { vector: r.cvssVector } : {}) } } : {}),
    confidence: r.confidence as Finding['confidence'],
    status: r.status as Finding['status'],
    asset: r.asset,
    ...(r.location != null ? { location: r.location } : {}),
    description: { ar: r.descriptionAr, en: r.descriptionEn },
    impact: { ar: r.impactAr, en: r.impactEn },
    remediation: { ar: r.remediationAr, en: r.remediationEn },
    evidence: r.evidence as Finding['evidence'],
    controls: r.controls as Finding['controls'],
    source: r.source,
    firstSeen: iso(r.firstSeen),
    retests: r.retests as Finding['retests'],
  };
}

function toScan(r: Prisma.ScanGetPayload<{ include: { findings: true } }>): ScanRecord {
  return {
    id: r.id, engagementId: r.engagementId, grantId: r.grantId,
    status: r.status as ScanRecord['status'],
    findings: r.findings.filter((f: any) => !f.reviewQueue).map(toFinding),
    review: r.findings.filter((f: any) => f.reviewQueue).map(toFinding),
    notTested: r.notTested,
    ...(r.telemetry != null ? { telemetry: r.telemetry as Record<string, number | null> } : {}),
    createdAt: iso(r.createdAt),
  };
}

// ---------------- audit (append-only) ----------------

export class PrismaAuditStore implements AuditStore {
  constructor(private db: Db) {}

  async append(e: AuditInput): Promise<AuditEntry> {
    const r = await this.db.auditEntry.create({
      data: {
        actor: e.actor, action: e.action, detail: e.detail ?? null, grantId: e.grantId ?? null,
        ...(e.at ? { at: new Date(e.at) } : {}),
      },
    });
    return toAudit(r);
  }

  async list(grantId?: string): Promise<AuditEntry[]> {
    const rows = await this.db.auditEntry.findMany({ where: grantId ? { grantId } : undefined, orderBy: { seq: 'asc' } });
    return rows.map(toAudit);
  }
}

function toAudit(r: Prisma.AuditEntryGetPayload<object>): AuditEntry {
  return {
    id: r.id, at: iso(r.at), actor: r.actor, action: r.action,
    ...(r.grantId != null ? { grantId: r.grantId } : {}),
    ...(r.detail != null ? { detail: r.detail } : {}),
  };
}

// ---------------- owner sign-off challenges ----------------

export class PrismaOwnerChallengeStore implements OwnerChallengeStore {
  constructor(private db: Db) {}

  async put(c: OwnerChallenge): Promise<void> {
    const data = {
      grantId: c.grantId, party: c.party, email: c.email, statement: c.statement,
      codeHash: c.codeHash, expiresAt: new Date(c.expiresAt), attempts: c.attempts,
    };
    await this.db.ownerChallenge.upsert({ where: { id: c.id }, create: { id: c.id, ...data }, update: data });
  }

  async get(id: string): Promise<OwnerChallenge | undefined> {
    const r = await this.db.ownerChallenge.findUnique({ where: { id } });
    return r ? { ...r, expiresAt: iso(r.expiresAt) } : undefined;
  }

  async delete(id: string): Promise<void> {
    await this.db.ownerChallenge.deleteMany({ where: { id } });
  }
}

// ---------------- factory ----------------

export interface PrismaStoresHandle {
  stores: CoreStores;
  db: Db;
  close(): Promise<void>;
}

export function createPrismaStores(databaseUrl: string): PrismaStoresHandle {
  const db = new PrismaClient({ adapter: new PrismaPg({ connectionString: databaseUrl }) });
  return {
    db,
    stores: {
      projects: {
        async list() {
          const rows = await db.assessmentProject.findMany({select:{document:true}});
          return rows.map((row:{document:unknown}) => row.document as Project);
        },
        async get(id) {
          const row = await db.assessmentProject.findUnique({where:{id}});
          return row?.document as Project | undefined;
        },
        async save(project, previous) {
          const data = { revision:project.revision, document:project as unknown as Prisma.InputJsonValue };
          if (!previous) return (await db.assessmentProject.createMany({data:[{id:project.id,...data}],skipDuplicates:true})).count === 1;
          return (await db.assessmentProject.updateMany({where:{id:project.id,revision:previous},data})).count === 1;
        },
      },
      grants: new PrismaGrantRepo(db),
      engagements: new PrismaEngagementRepo(db),
      scans: new PrismaScanRepo(db),
      audit: new PrismaAuditStore(db),
      challenges: new PrismaOwnerChallengeStore(db),
    },
    close: () => db.$disconnect(),
  };
}
