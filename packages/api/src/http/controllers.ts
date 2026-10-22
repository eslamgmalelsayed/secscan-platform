import { Body, Controller, ForbiddenException, Get, Headers, Inject, Param, Post, Query } from '@nestjs/common';
import { z } from 'zod';
import { Engagement } from '@secscan/shared';
import type { Lang } from '@secscan/report';
import { fromHar, fromOpenApi } from '@secscan/importers';
import { CORE, type CoreGraph } from './core-factory';

const actorOf = (b: any): string => z.string().min(1).parse(b?.actor ?? 'anonymous');

/** Every request body is schema-checked here, so the core never sees shapes it did not define. */
const FlowSchema = z.object({
  method: z.string().min(1),
  url: z.string().url(),
  headers: z.record(z.string()).optional(),
  body: z.string().nullable().optional(),
  capturedAsRole: z.string().optional(),
  capturedAsTenant: z.string().nullable().optional(),
  requiresAuth: z.boolean().optional(),
});
const IdentitySchema = z.object({
  role: z.string().min(1),
  tenant: z.string().nullable().optional(),
  sessionRef: z.string().nullable().optional(),
});
const ScanBody = z.object({
  engagementId: z.string().min(1),
  grantId: z.string().min(1),
  flows: z.array(FlowSchema).min(1),
  identities: z.array(IdentitySchema),
  rootUrl: z.string().url().optional(),
  tokens: z.array(z.string()).optional(),
  skipChecks: z.boolean().optional(),
});
const LangSchema = z.enum(['ar', 'en']).default('ar');

@Controller('health')
export class HealthController {
  constructor(@Inject(CORE) private core: CoreGraph) {}
  @Get()
  health() {
    return {
      ok: true, legalResolved: this.core.lab.legalResolved,
      adminTokenRequired: !!this.core.adminToken, identities: this.core.identities.length,
    };
  }
}

/** Keys of the identities loaded at boot: role, tenant, sessionRef. Never the material. */
@Controller('identities')
export class IdentitiesController {
  constructor(@Inject(CORE) private core: CoreGraph) {}
  @Get()
  list() { return this.core.identities; }
}

/** Turns a HAR export or an OpenAPI document into flows the UI can edit and submit. */
@Controller('flows')
export class FlowsController {
  @Post('import')
  import(@Body() body: any) {
    const input = z.object({
      kind: z.enum(['har', 'openapi']),
      text: z.string().min(2),
      capturedAsRole: z.string().optional(),
      capturedAsTenant: z.string().nullable().optional(),
      requiresAuth: z.boolean().optional(),
      includeHosts: z.array(z.string()).optional(),
      baseUrl: z.string().url().optional(),
    }).parse(body);
    const flows = input.kind === 'har'
      ? fromHar(input.text, { capturedAsRole: input.capturedAsRole, capturedAsTenant: input.capturedAsTenant, requiresAuth: input.requiresAuth, includeHosts: input.includeHosts })
      : fromOpenApi(input.text, { capturedAsRole: input.capturedAsRole, capturedAsTenant: input.capturedAsTenant, baseUrl: input.baseUrl });
    return { count: flows.length, flows };
  }
}

@Controller('grants')
export class GrantsController {
  constructor(@Inject(CORE) private core: CoreGraph) {}

  @Get()
  list() {
    return this.core.grants.list().map((rec) => ({
      ...summary(rec),
      targets: rec.grant.targets, ownershipProof: rec.grant.ownershipProof,
      notBefore: rec.grant.notBefore, notAfter: rec.grant.notAfter,
      allowStateChanging: rec.grant.allowStateChanging,
      ownerSigned: rec.grant.chain.some((l) => l.role === 'system_owner'),
    }));
  }

  @Post()
  create(@Body() body: any) {
    const rec = this.core.auth.createGrant(body?.grant, actorOf(body));
    return { grantId: rec.grant.grantId, status: rec.grant.status };
  }

  @Get(':id')
  get(@Param('id') id: string) {
    const rec = this.core.grants.get(id);
    if (!rec) throw new NotFoundError(`grant ${id} not found`);
    const { ownershipToken: _omit, ...grant } = rec.grant; // the proof token is never echoed
    return { ...summary(rec), grant };
  }

  /** Automatic proof: DNS TXT / well-known file / meta tag, per the grant. */
  @Post(':id/ownership')
  async ownership(@Param('id') id: string, @Body() body: any) {
    const rec = await this.core.auth.verifyOwnership(id, actorOf(body), this.core.ownership);
    return { ...summary(rec), verification: rec.verification };
  }

  /** Manual override (lab targets). Admin-only. */
  @Post(':id/ownership/manual')
  ownershipManual(@Param('id') id: string, @Body() body: any, @Headers('x-admin-token') token?: string) {
    this.requireAdmin(token);
    return summary(this.core.auth.recordOwnershipVerified(id, actorOf(body)));
  }

  @Post(':id/owner-sign')
  ownerSign(@Param('id') id: string, @Body() body: any) {
    return summary(this.core.auth.ownerSign(id, body?.link, actorOf(body)));
  }

  @Post(':id/approve')
  approve(@Param('id') id: string, @Body() body: any, @Headers('x-admin-token') token?: string) {
    this.requireAdmin(token);
    return summary(this.core.auth.adminApprove(id, actorOf(body)));
  }

  @Post(':id/revoke')
  revoke(@Param('id') id: string, @Body() body: any, @Headers('x-admin-token') token?: string) {
    this.requireAdmin(token);
    return summary(this.core.auth.revoke(id, actorOf(body)));
  }

  private requireAdmin(token?: string): void {
    if (!this.core.adminToken) return; // open: local dev without SECSCAN_ADMIN_TOKEN
    if (token !== this.core.adminToken) throw new ForbiddenException('admin token required');
  }

  @Get(':id/audit')
  audit(@Param('id') id: string) {
    return this.core.audit.list(id);
  }
}

@Controller('engagements')
export class EngagementsController {
  constructor(@Inject(CORE) private core: CoreGraph) {}
  @Get()
  list() { return this.core.engagements.list(); }

  @Post()
  create(@Body() body: any) {
    const eng = Engagement.parse(body?.engagement);
    this.core.engagements.save(eng);
    return { id: eng.id };
  }
}

@Controller('scans')
export class ScansController {
  constructor(@Inject(CORE) private core: CoreGraph) {}

  @Post()
  async run(@Body() body: any) {
    const input = ScanBody.parse(body);
    const scan = await this.core.scan.run({ ...input, actor: actorOf(body) });
    return {
      id: scan.id, status: scan.status, confirmed: scan.findings.length,
      review: scan.review?.length ?? 0, notTested: scan.notTested.length, telemetry: scan.telemetry,
    };
  }

  @Get()
  list(@Query('engagementId') engagementId?: string) {
    return this.core.scans.list(engagementId || undefined).map((s) => ({
      id: s.id, engagementId: s.engagementId, grantId: s.grantId, status: s.status, createdAt: s.createdAt,
      confirmed: s.findings.length, review: s.review?.length ?? 0, notTested: s.notTested.length, telemetry: s.telemetry,
    }));
  }

  @Get(':id')
  get(@Param('id') id: string) {
    const s = this.core.scans.get(id);
    if (!s) throw new NotFoundError(`scan ${id} not found`);
    return s;
  }

  @Get(':id/report')
  report(@Param('id') id: string, @Query('lang') lang?: string) {
    const s = this.core.scans.get(id);
    if (!s) throw new NotFoundError(`scan ${id} not found`);
    const l: Lang = LangSchema.parse(lang);
    return { markdown: this.core.report.render(s.engagementId, id, l) };
  }
}

export class NotFoundError extends Error {
  constructor(msg: string) { super(msg); this.name = 'NotFoundError'; }
}

function summary(rec: { grant: { grantId: string; status: string }; ownershipVerified: boolean; adminApproved: boolean }) {
  return { grantId: rec.grant.grantId, status: rec.grant.status, ownershipVerified: rec.ownershipVerified, adminApproved: rec.adminApproved };
}
