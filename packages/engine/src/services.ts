/**
 * Service discovery — a NON-DESTRUCTIVE TCP connect scan of ONE authorized host.
 *
 * It opens a socket to each port and immediately closes it: no payload, no
 * banner-grab write, nothing sent. An accepted connection means a service
 * listens; a refusal/timeout means it does not. The caller passes only a host
 * it is authorized for (from the grant), so this never sprays across a network —
 * it maps the attack surface of a single owned host, which the web/API scan
 * then covers port by port.
 */
import { Socket } from 'node:net';

/** Common web/app/management ports. Callers may pass their own set. */
export const COMMON_PORTS = [80, 81, 443, 3000, 3001, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090];

export interface ServiceScanOptions {
  ports?: number[];
  timeoutMs?: number;
  /** Max sockets in flight (politeness). Default 20. */
  concurrency?: number;
}

export interface OpenPort { port: number; open: true }

function probe(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = new Socket();
    let done = false;
    const finish = (open: boolean) => { if (done) return; done = true; sock.destroy(); resolve(open); };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => finish(true));   // service listens
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));    // refused / unreachable
    sock.connect(port, host);
  });
}

/**
 * Return the open ports on `host`. Best-effort and bounded; a port that errors
 * or times out is treated as closed, never fatal.
 */
export async function discoverServices(host: string, opts: ServiceScanOptions = {}): Promise<OpenPort[]> {
  const ports = opts.ports ?? COMMON_PORTS;
  const timeoutMs = opts.timeoutMs ?? 1500;
  const concurrency = Math.max(1, opts.concurrency ?? 20);
  const open: OpenPort[] = [];
  const queue = [...ports];

  async function worker() {
    for (;;) {
      const port = queue.shift();
      if (port === undefined) return;
      if (await probe(host, port, timeoutMs)) open.push({ port, open: true });
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, ports.length) }, worker));
  return open.sort((a, b) => a.port - b.port);
}
