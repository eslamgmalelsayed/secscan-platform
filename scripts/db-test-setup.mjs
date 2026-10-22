// Creates the secscan_test database (if missing) in the compose Postgres and
// applies migrations to it. Cross-platform: no shell features needed.
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';

const TEST_URL = 'postgresql://secscan:secscan_dev_only@localhost:5432/secscan_test';
const psql = (sql) => execFileSync('docker', ['compose', 'exec', '-T', 'postgres', 'psql', '-U', 'secscan', '-d', 'secscan', '-tAc', sql], { encoding: 'utf8' }).trim();

if (psql("SELECT 1 FROM pg_database WHERE datname='secscan_test'") !== '1') {
  psql('CREATE DATABASE secscan_test');
  console.log('created database secscan_test');
}
// Run the Prisma CLI through node directly: no shell, so it behaves the same on Windows.
const prismaCli = createRequire(import.meta.url).resolve('prisma/build/index.js');
execFileSync(process.execPath, [prismaCli, 'migrate', 'deploy'], {
  stdio: 'inherit', env: { ...process.env, DATABASE_URL: TEST_URL },
});
console.log(`\nready. run tests against real services with:\n  SECSCAN_TEST_DATABASE_URL=${TEST_URL} SECSCAN_TEST_REDIS_URL=redis://127.0.0.1:6379 npm test`);
