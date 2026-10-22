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
  await app.init();
  await app.getHttpAdapter().getInstance().ready();
  return app;
}
