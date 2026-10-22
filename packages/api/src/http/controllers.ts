import { Body, Controller, ForbiddenException, Get, Headers, Inject, Param, Post, Query, Req } from '@nestjs/common';
import { z } from 'zod';
import { Engagement } from '@secscan/shared';
import type { Lang } from '@secscan/report';
import { fromHar, fromOpenApi } from '@secscan/importers';
import { CORE, type CoreGraph } from './core-factory';
import { safeEqual } from './auth';

/** The audit actor. When API tokens are configured it is the token's name
 *  (set by the auth hook in app.ts) and the body's `actor` is ignored. */
function actorOf(req: any, body: any): string {
  const bound = req?.secscanActor as string | undefined;
  if (bound) return bound;
  return z.string().min(1).max(200).parse(body?.actor ?? 'anonymous');
}

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
const ConfirmBody = z.object({ challengeId: z.string().min(1), code: z.string().min(1).max(12) });

@Controller('health')
export class HealthController {
  constructor(@Inject(CORE) private core: CoreGraph) {}
  @Get()
  health() {
    return {
      ok: true, legalResolved: this.core.lab.legalResolved,
      adminTokenRequired: !!this.core.adminToken, apiTokenRequired: !!this.core.apiAuth,
      ownerEmailSignOff: this.core.ownerEmailEnabled, identities: this.core.identities.length,
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

/** Turns a HAR export or an OpenAPI document into flows a client can edit and submit. */
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
  async list() {
    return (await this.core.grants.list()).map((rec) => ({
      ...summary(rec),
      targets: rec.grant.targets, ownershipProof: rec.grant.ownershipProof,
      notBefore: rec.grant.notBefore, notAfter: rec.grant.notAfter,
      allowStateChanging: rec.grant.allowStateChanging,
      ownerSigned: rec.grant.chain.some((l) => l.role === 'system_owner'),
    }));
  }

  @Post()
  async create(@Req() req: any, @Body() body: any) {
    const rec = await this.core.auth.createGrant(body?.grant, actorOf(req, body));
    return { grantId: rec.grant.grantId, status: rec.grant.status };
  }

  @Get(':id')
  async get(@Param('id') id: string) {
    const rec = await this.core.grants.get(id);
    if (!rec) throw new NotFoundError(`grant ${id} not found`);
    const { ownershipToken: _omit, ...grant } = rec.grant; // the proof token is never echoed
    return { ...summary(rec), ownershipMethod: rec.ownershipMethod ?? null, grant };
  }

  /** Automatic proof: DNS TXT / well-known file / meta tag, per the grant. */
  @Post(':id/ownership')
  async ownership(@Req() req: any, @Param('id') id: string, @Body() body: any) {
    const rec = await this.core.auth.verifyOwnership(id, actorOf(req, body), this.core.ownership);
    return { ...summary(rec), verification: rec.verification };
  }

  /** Manual override (lab targets). Admin-only. */
  @Post(':id/ownership/manual')
  async ownershipManual(@Req() req: any, @Param('id') id: string, @Body() body: any, @Headers('x-admin-token') token?: string) {
    this.requireAdmin(token);
    return summary(await this.core.auth.recordOwnershipVerified(id, actorOf(req, body)));
  }

  /** Owner sign-off step 1: email a one-time code to a mailbox on the target's domain. */
  @Post(':id/owner-sign/request')
  async ownerSignRequest(@Req() req: any, @Param('id') id: string, @Body() body: any) {
    return this.core.auth.requestOwnerSignature(id, body?.owner, actorOf(req, body));
  }

  /** Owner sign-off step 2: the code the owner received. */
  @Post(':id/owner-sign/confirm')
  async ownerSignConfirm(@Req() req: any, @Param('id') id: string, @Body() body: any) {
    const b = ConfirmBody.parse(body);
    return summary(await this.core.auth.confirmOwnerSignature(id, b.challengeId, b.code, actorOf(req, body)));
  }

  /** Lab-only manual signature (no mailbox on a lab host). Admin-only. */
  @Post(':id/owner-sign')
  async ownerSign(@Req() req: any, @Param('id') id: string, @Body() body: any, @Headers('x-admin-token') token?: string) {
    this.requireAdmin(token);
    return summary(await this.core.auth.ownerSign(id, body?.link, actorOf(req, body)));
  }

  @Post(':id/approve')
  async approve(@Req() req: any, @Param('id') id: string, @Body() body: any, @Headers('x-admin-token') token?: string) {
    this.requireAdmin(token);
    return summary(await this.core.auth.adminApprove(id, actorOf(req, body)));
  }

  @Post(':id/revoke')
  async revoke(@Req() req: any, @Param('id') id: string, @Body() body: any, @Headers('x-admin-token') token?: string) {
    this.requireAdmin(token);
    return summary(await this.core.auth.revoke(id, actorOf(req, body)));
  }

  @Get(':id/audit')
  audit(@Param('id') id: string) {
    return this.core.audit.list(id);
  }

  private requireAdmin(token?: string): void {
    if (!this.core.adminToken) return; // open: local dev without SECSCAN_ADMIN_TOKEN
    if (!token || !safeEqual(token, this.core.adminToken)) throw new ForbiddenException('admin token required');
  }
}

@Controller('engagements')
export class EngagementsController {
  constructor(@Inject(CORE) private core: CoreGraph) {}
  @Get()
  list() { return this.core.engagements.list(); }

  @Post()
  async create(@Body() body: any) {
    const eng = Engagement.parse(body?.engagement);
    await this.core.engagements.save(eng);
    return { id: eng.id };
  }
}

@Controller('scans')
export class ScansController {
  constructor(@Inject(CORE) private core: CoreGraph) {}

  @Post()
  async run(@Req() req: any, @Body() body: any) {
    const input = ScanBody.parse(body);
    const scan = await this.core.scan.run({ ...input, actor: actorOf(req, body) });
    return {
      id: scan.id, status: scan.status, confirmed: scan.findings.length,
      review: scan.review?.length ?? 0, notTested: scan.notTested.length, telemetry: scan.telemetry,
    };
  }

  @Get()
  async list(@Query('engagementId') engagementId?: string) {
    return (await this.core.scans.list(engagementId || undefined)).map((s) => ({
      id: s.id, engagementId: s.engagementId, grantId: s.grantId, status: s.status, createdAt: s.createdAt,
      confirmed: s.findings.length, review: s.review?.length ?? 0, notTested: s.notTested.length, telemetry: s.telemetry,
    }));
  }

  @Get(':id')
  async get(@Param('id') id: string) {
    const s = await this.core.scans.get(id);
    if (!s) throw new NotFoundError(`scan ${id} not found`);
    return s;
  }

  @Get(':id/report')
  async report(@Param('id') id: string, @Query('lang') lang?: string) {
    const s = await this.core.scans.get(id);
    if (!s) throw new NotFoundError(`scan ${id} not found`);
    const l: Lang = LangSchema.parse(lang);
    return { markdown: await this.core.report.render(s.engagementId, id, l) };
  }
}

export class NotFoundError extends Error {
  constructor(msg: string) { super(msg); this.name = 'NotFoundError'; }
}

function summary(rec: { grant: { grantId: string; status: string }; ownershipVerified: boolean; adminApproved: boolean }) {
  return { grantId: rec.grant.grantId, status: rec.grant.status, ownershipVerified: rec.ownershipVerified, adminApproved: rec.adminApproved };
}
