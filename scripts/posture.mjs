// Snapshot a single owner-selected HTTPS origin. No credentials, redirects or crawling.
import { request } from 'node:https';
const url = new URL(process.argv[2]);
if (url.protocol !== 'https:' || url.username || url.password || url.href !== url.origin + '/')
  throw new Error('Supply one HTTPS origin');
const req = request(url, { method: 'HEAD', agent: false, signal: AbortSignal.timeout(5000) }, (res) => {
  const names = ['strict-transport-security', 'content-security-policy', 'x-content-type-options'];
  console.log(
    JSON.stringify({
      origin: url.origin,
      at: new Date().toISOString(),
      status: res.statusCode,
      tls: res.socket.getProtocol(),
      headers: Object.fromEntries(names.map((n) => [n, res.headers[n] ?? null])),
    }),
  );
  res.resume();
});
req.on('error', (e) => {
  console.error('Measurement unavailable: ' + e.message);
  process.exitCode = 1;
});
req.end();
