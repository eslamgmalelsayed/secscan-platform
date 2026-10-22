#!/usr/bin/env node
/**
 * secscan — one-command local scan.
 *
 *   secscan scan --host app.example.com --root https://app.example.com \
 *     --har customer.har --role customer --tenant t1 \
 *     --identities identities.json --out report --dev-trust
 *
 * --dev-trust is required: it says "I own this target" and auto-walks the
 * authorization lifecycle locally. Without it the command refuses to run.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { fromHar, fromOpenApi } from '@secscan/importers';
import type { RecordedRequest } from '@secscan/engine';
import { runScan } from './run';

type Args = Record<string, string | boolean>;

function parse(argv: string[]): { cmd: string; args: Args } {
  const cmd = argv[0] && !argv[0].startsWith('--') ? argv[0] : 'scan';
  const args: Args = {};
  for (let i = cmd === argv[0] ? 1 : 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) { args[key] = true; }
    else { args[key] = next; i++; }
  }
  return { cmd, args };
}

const USAGE = `secscan scan — authorized, non-destructive local scan

Required:
  --host <host>           target host (also the only allow-listed target)
  --har <file> | --openapi <file>   recorded flows to replay
  --dev-trust             confirm you own the target (auto-signs locally)

Optional:
  --root <url>            root URL for the scorecard (default https://<host>/)
  --role <role>           capturedAsRole for imported flows
  --tenant <tenant>       capturedAsTenant for HAR flows
  --base-url <url>        OpenAPI server override
  --identities <file>     test accounts JSON ({"role/tenant":{cookies|headers|bearer,liveness?}})
  --tokens <t1,t2>        JWTs to analyze (comma-separated)
  --out <prefix>          report file prefix (default ./report) -> <prefix>.ar.md / .en.md
  --allow-private         permit a target on a private address (local lab)
  --state-changing        allow state-changing replay (staging only)
  --rps <n>               requests/second cap     --max-ms <n>  whole-scan deadline`;

async function main() {
  const { cmd, args } = parse(process.argv.slice(2));
  if (cmd === 'help' || args.help || (cmd !== 'scan')) { console.log(USAGE); process.exit(cmd === 'scan' || cmd === 'help' ? 0 : 1); }

  const host = args.host as string;
  if (!host) fail('--host is required');
  if (!args['dev-trust']) fail('--dev-trust is required (it confirms you own the target and auto-signs locally)');
  if (!args.har && !args.openapi) fail('provide --har <file> or --openapi <file>');

  const role = (args.role as string) || undefined;
  const tenant = (args.tenant as string) || undefined;
  let flows: RecordedRequest[];
  if (args.har) {
    flows = fromHar(readFileSync(args.har as string, 'utf-8'), { capturedAsRole: role, capturedAsTenant: tenant, includeHosts: [host] });
  } else {
    flows = fromOpenApi(readFileSync(args.openapi as string, 'utf-8'), { capturedAsRole: role, capturedAsTenant: tenant, baseUrl: (args['base-url'] as string) || undefined });
  }
  if (!flows.length) fail('no flows found in the import (check the file and --host filter)');

  const identitiesFile = args.identities ? JSON.parse(readFileSync(args.identities as string, 'utf-8')) : undefined;
  const tokens = args.tokens ? String(args.tokens).split(',').map((t) => t.trim()).filter(Boolean) : undefined;
  const out = (args.out as string) || 'report';

  console.log(`[secscan] scanning ${host} — ${flows.length} flow(s)${identitiesFile ? `, ${Object.keys(identitiesFile).length} identit(y/ies)` : ', anonymous'}`);

  const res = await runScan({
    host, root: (args.root as string) || undefined, flows, identitiesFile,
    allowPrivate: !!args['allow-private'], stateChanging: !!args['state-changing'],
    rps: args.rps ? Number(args.rps) : undefined, maxMs: args['max-ms'] ? Number(args['max-ms']) : undefined,
    tokens,
  });

  writeFileSync(`${out}.ar.md`, res.reportAr);
  writeFileSync(`${out}.en.md`, res.reportEn);

  console.log(`\n[secscan] ${res.status} — confirmed=${res.confirmed} review=${res.review} notTested=${res.notTested.length}`);
  if (res.notTested.length) console.log('  not tested:\n' + res.notTested.map((n) => `   - ${n}`).join('\n'));
  console.log(`\n[secscan] reports written: ${out}.ar.md, ${out}.en.md`);
}

function fail(msg: string): never {
  console.error(`[secscan] error: ${msg}\n`);
  console.error(USAGE);
  process.exit(1);
}

main().catch((e) => { console.error(`[secscan] ${e?.message ?? e}`); process.exit(1); });
