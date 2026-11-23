import 'reflect-metadata';
import { projectIdentity } from './projectIdentity';
import { AssessmentsController, ProjectLoginController } from './assessments.controller';
import { Module } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { buildCore, CORE, type CoreOptions, type CoreGraph } from './core-factory';
import {
  GrantsController, ScansController, EngagementsController, HealthController,
  IdentitiesController, FlowsController, AgentController,
} from './controllers';
import { DomainErrorFilter } from './errors.filter';
import { PUBLIC_ROUTES, authenticate } from './auth';

/** Build a NestJS (Fastify) app wired to a core graph. */
export async function buildApp(opts: CoreOptions): Promise<NestFastifyApplication> {
  const core: CoreGraph = buildCore(opts);

  @Module({
    controllers: [ProjectLoginController, AssessmentsController, HealthController, GrantsController, ScansController, EngagementsController, IdentitiesController, FlowsController, AgentController],
    providers: [{ provide: CORE, useValue: core }],
  })
  class AppModule {}

  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule, new FastifyAdapter(), { logger: false },
  );
  app.useGlobalFilters(new DomainErrorFilter());

  // Bearer-token authentication for every non-public route (see auth.ts).
  const oidc = projectIdentity();
  if (core.apiAuth || oidc) {
    const apiAuth = core.apiAuth;
    app.getHttpAdapter().getInstance().addHook('onRequest', async (request: any, reply: any) => {
      const path = String(request.url ?? '').split('?')[0];
      if (PUBLIC_ROUTES.has(`${request.method} ${path}`)) return;
      const projectRoute = /^\/assessments(?:\/|$)/.test(path);
      // OIDC only covers project routes. Without API tokens the other routes keep
      // the access rules they had before OIDC was configured.
      if (!apiAuth && !projectRoute) return;
      const header=request.headers.authorization;
      let who=apiAuth ? authenticate(apiAuth,header) : null;
      if (!who && oidc && projectRoute) who=await oidc(header);

      if (!who) {
        reply.code(401).header('www-authenticate', 'Bearer').send({ error: 'authentication required', statusCode: 401 });
        return reply;
      }
      request.secscanActor = who;
    });
  }

  await app.init();
  await app.getHttpAdapter().getInstance().ready();
  return app;
}
