// Prisma 7 configuration: the connection URL for Migrate lives here, not in
// schema.prisma. The runtime client gets its connection via the pg adapter
// (packages/api/src/persistence/prismaStores.ts).
//
// Falls back to the local docker-compose database (same value as .env.example)
// so `prisma generate` works without any environment set up.
import { defineConfig } from 'prisma/config';

const LOCAL_DEV_URL = 'postgresql://secscan:secscan_dev_only@localhost:5432/secscan';

export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: { path: 'prisma/migrations' },
  datasource: { url: process.env.DATABASE_URL ?? LOCAL_DEV_URL },
});
