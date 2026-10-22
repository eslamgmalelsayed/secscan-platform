import 'reflect-metadata';
import { Module } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { buildCore, CORE, type CoreOptions, type CoreGraph } from './core-factory';
import {
  GrantsController, ScansController, EngagementsController, HealthController,
  IdentitiesController, FlowsController,
} from './controllers';
import { DomainErrorFilter } from './errors.filter';
import { PUBLIC_ROUTES, authenticate } from './auth';

/** Build a NestJS (Fastify) app wired to a core graph. */
export async function buildApp(opts: CoreOptions): Promise<NestFastifyApplication> {
  const core: CoreGraph = buildCore(opts);

  @Module({
    controllers: [HealthController, GrantsController, ScansController, EngagementsController, IdentitiesController, FlowsController],
    providers: [{ provide: CORE, useValue: core }],
  })
  class AppModule {}

  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule, new FastifyAdapter(), { logger: false },
  );
  app.useGlobalFilters(new DomainErrorFilter());

  // Bearer-token authentication for every non-public route (see auth.ts).
  if (core.apiAuth) {
    const apiAuth = core.apiAuth;
    app.getHttpAdapter().getInstance().addHook('onRequest', async (request: any, reply: any) => {
      const path = String(request.url ?? '').split('?')[0];
      if (PUBLIC_ROUTES.has(`${request.method} ${path}`)) return;
      const who = authenticate(apiAuth, request.headers['authorization']);
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
