import { Body, Controller, ForbiddenException, Get, Headers, Inject, Param, Post, Query } from '@nestjs/common';
import { z } from 'zod';
import { Engagement } from '@secscan/shared';
import type { Lang } from '@secscan/report';
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
    return { ok: true, legalResolved: this.core.lab.legalResolved };
  }
}

@Controller('grants')
export class GrantsController {
  constructor(@Inject(CORE) private core: CoreGraph) {}

  @Post()
  create(@Body() body: any) {
    const rec = this.core.auth.createGrant(body?.grant, actorOf(body));
    return { grantId: rec.grant.grantId, status: rec.grant.status };
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
