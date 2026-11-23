import { Body, Controller, ForbiddenException, Get, Inject, Param, Post, Req } from '@nestjs/common';
import { z } from 'zod';
import { CORE, type CoreGraph } from './core-factory';

@Controller('assessments')
export class AssessmentsController {
  constructor(@Inject(CORE) private core: CoreGraph) {}
  private actor(req: { secscanActor?: string }) {
    if (req.secscanActor) return req.secscanActor;
    if (this.core.localProjectAccess) return 'local-operator';
    throw new ForbiddenException('Configure named API tokens or use local mode');
  }
  @Get() list(@Req() req: any) {
    return this.core.assessments.list(this.actor(req));
  }
  @Post() create(@Req() req: any, @Body() body: unknown) {
    return this.core.assessments.create(this.actor(req), body);
  }
  @Post(':id/attachments/:hash') readAttachment(
    @Req() req: any,
    @Param('id') id: string,
    @Param('hash') hash: string,
  ) {
    return this.core.assessments.attachment(this.actor(req), id, hash);
  }
  @Get(':id') get(@Req() req: any, @Param('id') id: string) {
    return this.core.assessments.get(this.actor(req), id);
  }
  @Post(':id') change(@Req() req: any, @Param('id') id: string, @Body() body: unknown) {
    const { revision, action } = z
      .object({ revision: z.number().int().positive(), action: z.unknown() })
      .parse(body);
    return this.core.assessments.change(this.actor(req), id, revision, action);
  }
}

@Controller('project-login')
export class ProjectLoginController {
  @Get() config() {
    return {
      issuer: process.env.SECSCAN_OIDC_ISSUER,
      clientId: process.env.SECSCAN_OIDC_CLIENT_ID,
      audience: process.env.SECSCAN_OIDC_AUDIENCE,
      scope: process.env.SECSCAN_OIDC_SCOPE || 'openid profile',
    };
  }
}
