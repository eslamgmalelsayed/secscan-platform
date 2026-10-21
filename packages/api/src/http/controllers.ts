import { Body, Controller, Get, Inject, Param, Post, Query } from '@nestjs/common';
import { z } from 'zod';
import type { Engagement } from '@secscan/shared';
import type { Lang } from '@secscan/report';
import { CORE, type CoreGraph } from './core-factory';

const actorOf = (b: any): string => z.string().min(1).parse(b?.actor ?? 'anonymous');

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

  @Post(':id/ownership')
  ownership(@Param('id') id: string, @Body() body: any) {
    return summary(this.core.auth.recordOwnershipVerified(id, actorOf(body)));
  }

  @Post(':id/owner-sign')
  ownerSign(@Param('id') id: string, @Body() body: any) {
    return summary(this.core.auth.ownerSign(id, body?.link, actorOf(body)));
  }

  @Post(':id/approve')
  approve(@Param('id') id: string, @Body() body: any) {
    return summary(this.core.auth.adminApprove(id, actorOf(body)));
  }

  @Post(':id/revoke')
  revoke(@Param('id') id: string, @Body() body: any) {
    return summary(this.core.auth.revoke(id, actorOf(body)));
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
    const eng = body?.engagement as Engagement;
    if (!eng?.id) throw new Error('engagement.id required');
    this.core.engagements.save(eng);
    return { id: eng.id };
  }
}

@Controller('scans')
export class ScansController {
  constructor(@Inject(CORE) private core: CoreGraph) {}

  @Post()
  async run(@Body() body: any) {
    const input = z.object({
      engagementId: z.string().min(1),
      grantId: z.string().min(1),
      flows: z.array(z.any()),
      identities: z.array(z.any()),
    }).parse(body);
    const scan = await this.core.scan.run({ ...input, actor: actorOf(body) } as any);
    return { id: scan.id, status: scan.status, confirmed: scan.findings.length, notTested: scan.notTested.length };
  }

  @Get(':id')
  get(@Param('id') id: string) {
    const s = this.core.scans.get(id);
    if (!s) throw new Error(`scan ${id} not found`);
    return s;
  }

  @Get(':id/report')
  report(@Param('id') id: string, @Query('lang') lang?: string) {
    const s = this.core.scans.get(id);
    if (!s) throw new Error(`scan ${id} not found`);
    return { markdown: this.core.report.render(s.engagementId, id, (lang as Lang) ?? 'ar') };
  }
}

function summary(rec: { grant: { grantId: string; status: string }; ownershipVerified: boolean; adminApproved: boolean }) {
  return { grantId: rec.grant.grantId, status: rec.grant.status, ownershipVerified: rec.ownershipVerified, adminApproved: rec.adminApproved };
}
