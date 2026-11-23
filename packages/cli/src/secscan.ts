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
import { discoverServices, runAgentAudit, wifiSnapshot, type RecordedRequest } from '@secscan/engine';
import { runScan } from './run';

type Args = Record<string, string | boolean>;

function parse(argv: string[]): { cmd: string; args: Args; positionals: string[] } {
  const cmd = argv[0] && !argv[0].startsWith('--') ? argv[0] : 'scan';
  const args: Args = {};
  const positionals: string[] = [];
  for (let i = cmd === argv[0] ? 1 : 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) { positionals.push(a); continue; }
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) { args[key] = true; }
    else { args[key] = next; i++; }
  }
  return { cmd, args, positionals };
}

const USAGE = `secscan — authorized, non-destructive local scanner

  secscan quick <url>       one step: crawl the public surface and scan it
                            (add --identities to cover logins + enable IDOR)
  secscan wifi              export current WiFi posture as JSON
  secscan services <host>   non-destructive connect scan of an owned host
  secscan agent             on-network audit: LAN devices + ARP-spoof + WiFi posture

secscan scan — scan from recorded flows

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
  const { cmd, args, positionals } = parse(process.argv.slice(2));
  if (cmd === 'quick') return quick(positionals[0] ?? (args.url as string), args);
  if (cmd === 'services') return services(positionals[0] ?? (args.host as string), args);
  if (cmd === 'wifi') { console.log(JSON.stringify(wifiSnapshot())); return; }
  if (cmd === 'agent') return agent(args);
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

/**
 * One-step scan: `secscan quick <url>`. No HAR, no flags required — it crawls
 * the public surface and runs the non-destructive suite. Add --identities to
 * cover logged-in pages and enable the IDOR engine.
 */
async function quick(url: string, args: Args) {
  if (!url) fail('usage: secscan quick <url> [--identities f.json] [--max-pages N] [--allow-private] [--out prefix]');
  let host: string, root: string;
  try { const u = new URL(url); host = u.hostname; root = url; } catch { return fail(`not a valid URL: ${url}`); }

  const identitiesFile = args.identities ? JSON.parse(readFileSync(args.identities as string, 'utf-8')) : undefined;
  const out = (args.out as string) || 'report';
  const nIds = identitiesFile ? Object.keys(identitiesFile).length : 0;
  console.log(`[secscan] quick scan of ${host} — crawling the public surface${nIds ? `, ${nIds} identit(y/ies)` : ' anonymously'}`);

  const res = await runScan({
    host, root, flows: [], discover: { maxPages: args['max-pages'] ? Number(args['max-pages']) : undefined },
    identitiesFile, allowPrivate: !!args['allow-private'],
    rps: args.rps ? Number(args.rps) : undefined, maxMs: args['max-ms'] ? Number(args['max-ms']) : undefined,
    tokens: args.tokens ? String(args.tokens).split(',').map((t) => t.trim()).filter(Boolean) : undefined,
  });
  writeFileSync(`${out}.ar.md`, res.reportAr);
  writeFileSync(`${out}.en.md`, res.reportEn);
  console.log(`\n[secscan] ${res.status} — confirmed=${res.confirmed} review=${res.review} notTested=${res.notTested.length}`);
  if (res.notTested.length) console.log('  not tested:\n' + res.notTested.map((n) => `   - ${n}`).join('\n'));
  console.log(`\n[secscan] reports written: ${out}.ar.md, ${out}.en.md`);
  if (!nIds) console.log('[secscan] tip: add --identities to test logged-in pages and turn on the IDOR/cross-tenant engine.');
}

/**
 * `secscan agent` — the on-network agent. Runs on a machine on YOUR network:
 * discovers devices on the local subnet (non-destructive connect scan), reads
 * the ARP table for spoofing signs, and audits the WiFi crypto posture. Audits
 * a network you own; it never attacks other people's gear.
 */
async function agent(args: Args) {
  console.log(`[secscan] agent on ${process.platform} — auditing your own network (non-destructive)`);
  const r = await runAgentAudit({
    cidr: args.cidr as string, gateway: args.gateway as string,
    timeoutMs: args['timeout-ms'] ? Number(args['timeout-ms']) : undefined,
  });

  console.log(`\n[devices] ${r.cidr ? `scanned ${r.cidr}` : 'no private LAN interface found (pass --cidr 192.168.1.0/24)'}`);
  if (!r.devices.length) console.log('  (no open ports found)');
  for (const h of r.devices) console.log(`  - ${h.host}: ${h.ports.join(', ')}`);

  console.log(`\n[arp] ${r.arpEntries} entries${r.gateway ? `, gateway ${r.gateway}` : ''}`);
  if (!r.network.length) console.log('  no spoofing signs');
  for (const f of r.network) console.log(`  ! [${f.severity}] ${f.title} — ${f.detail}`);

  console.log(`\n[wifi] ${r.wifi.ssid ? `SSID '${r.wifi.ssid}'` : 'network'}${r.wifi.security ? ` — ${r.wifi.security}` : ''}`);
  if (!r.wifi.security) console.log('  inconclusive: active connection security unavailable');
  else if (!r.wifiFindings.length) console.log('  no configured WiFi check flagged this connection');
  for (const f of r.wifiFindings) console.log(`  ! [${f.severity}] ${f.title} — ${f.detail}`);

  console.log(`\n[secscan] agent done — ${r.network.length + r.wifiFindings.length} network finding(s).`);
}

/** `secscan services <host>` — non-destructive connect scan of one owned host. */
async function services(host: string, args: Args) {
  if (!host) fail('usage: secscan services <host> [--ports 80,443,8080] [--timeout-ms 1500]');
  const ports = args.ports ? String(args.ports).split(',').map((p) => Number(p.trim())).filter(Boolean) : undefined;
  console.log(`[secscan] connect scan of ${host} (non-destructive; owned host only)…`);
  const open = await discoverServices(host, { ports, timeoutMs: args['timeout-ms'] ? Number(args['timeout-ms']) : undefined });
  if (!open.length) console.log('[secscan] no open ports found in the probed set.');
  else { console.log(`[secscan] open ports:`); for (const o of open) console.log(`   - ${host}:${o.port}`); }
}

function fail(msg: string): never {
  console.error(`[secscan] error: ${msg}\n`);
  console.error(USAGE);
  process.exit(1);
}

main().catch((e) => { console.error(`[secscan] ${e?.message ?? e}`); process.exit(1); });
