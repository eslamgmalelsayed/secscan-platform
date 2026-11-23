// A known LAN service and two operator-selected measurements. No discovery.
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { isIPv4 } from 'node:net';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
const prefix = '/secscan-reference/';
function privateIp(ip) {
  return isIPv4(ip) && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(ip);
}
function target(value) {
  const url = new URL(value);
  if (
    url.protocol !== 'http:' ||
    !privateIp(url.hostname) ||
    url.port !== '48761' ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !/^\/secscan-reference\/[0-9a-f-]{36}$/.test(url.pathname)
  )
    throw new Error('Use the exact URL printed by the reference service');
  return url;
}
export async function measure(value, vantage) {
  const url = target(value);
  if (!['internal', 'guest'].includes(vantage)) throw new Error('Choose internal or guest');
  let reached = false;
  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(3000), redirect: 'error' });
    reached =
      response.ok && response.headers.get('x-secscan-reference') === url.pathname.slice(prefix.length);
    await response.body?.cancel();
  } catch {
    /* Timeout or refusal cannot establish a policy denial. */
  }
  return { service: url.href, vantage, at: new Date().toISOString(), reached };
}
export function compare(internal, guest) {
  target(internal.service);
  if (
    internal.vantage !== 'internal' ||
    guest.vantage !== 'guest' ||
    internal.service !== guest.service ||
    typeof internal.reached !== 'boolean' ||
    typeof guest.reached !== 'boolean'
  )
    throw new Error('Expected matching reference service and internal/guest observations');
  const delta = Date.parse(guest.at) - Date.parse(internal.at);
  if (!Number.isFinite(delta) || delta < 0 || delta > 900000)
    throw new Error('Take the guest measurement within 15 minutes after the baseline');
  return {
    service: internal.service,
    baseline: internal.reached ? 'reachable' : 'unavailable',
    guest: guest.reached ? 'same-service-reachable' : 'unknown',
    evidence: JSON.stringify({ internal, guest }),
  };
}
async function main([cmd, a, b]) {
  if (cmd === 'serve' && privateIp(a)) {
    const id = randomUUID();
    const server = createServer((req, res) => {
      if (req.method !== 'GET' || req.url !== prefix + id) {
        res.writeHead(404);
        res.end();
        return;
      }
      res.writeHead(204, { 'x-secscan-reference': id, 'cache-control': 'no-store' });
      res.end();
    });
    server.listen(48761, a, () => console.log('http://' + a + ':48761' + prefix + id));
  } else if (cmd === 'measure') console.log(JSON.stringify(await measure(a, b)));
  else if (cmd === 'compare')
    console.log(
      JSON.stringify(compare(JSON.parse(await readFile(a, 'utf8')), JSON.parse(await readFile(b, 'utf8')))),
    );
  else
    throw new Error(
      'serve <private IPv4> | measure <reference URL> <internal|guest> | compare <internal.json> <guest.json>',
    );
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  main(process.argv.slice(2)).catch((e) => {
    console.error(e.message);
    process.exitCode = 1;
  });
