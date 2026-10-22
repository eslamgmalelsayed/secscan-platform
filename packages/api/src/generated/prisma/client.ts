// Committed type stub so the project builds and runs offline with NO Postgres
// and NO `prisma generate` (the default in-memory / desktop path never touches
// it). Postgres users run `npm run db:generate -w @secscan/api`, which OVERWRITES
// this file with the real generated client before connecting to a database.
export class PrismaClient {
  constructor(_opts?: any) {}
  $transaction(arg: any): Promise<any> { return Array.isArray(arg) ? Promise.all(arg) : Promise.resolve(arg); }
  $queryRawUnsafe(..._a: any[]): Promise<any> { return Promise.resolve([{ ok: 1 }]); }
  $connect(): Promise<void> { return Promise.resolve(); }
  $disconnect(): Promise<void> { return Promise.resolve(); }
  [k: string]: any;
}
export namespace Prisma {
  export type InputJsonValue = any;
  export type GrantGetPayload<_T = any> = any;
  export type EngagementGetPayload<_T = any> = any;
  export type FindingGetPayload<_T = any> = any;
  export type ScanGetPayload<_T = any> = any;
  export type AuditEntryGetPayload<_T = any> = any;
  export type FindingCreateManyInput = any;
}
