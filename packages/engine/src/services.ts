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
import { networkInterfaces } from 'node:os';

/** The agent host's own LAN as a /24 CIDR (e.g. 192.168.1.0/24), or undefined
 *  if no private IPv4 interface is found. Used by the agent to scan the network
 *  it is actually on. */
export function localSubnetCidr(): string | undefined {
  for (const addrs of Object.values(networkInterfaces())) {
    for (const a of addrs ?? []) {
      if (a.family === 'IPv4' && !a.internal && /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(a.address)) {
        const o = a.address.split('.');
        return `${o[0]}.${o[1]}.${o[2]}.0/24`;
      }
    }
  }
  return undefined;
}

/** Common web/app/management ports. Callers may pass their own set. */
export const COMMON_PORTS = [80, 81, 443, 3000, 3001, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090];

export interface ServiceScanOptions {
  ports?: number[];
  timeoutMs?: number;
  /** Max sockets in flight (politeness). Default 20. */
  concurrency?: number;
}

export interface OpenPort { port: number; open: true }
export interface HostServices { host: string; ports: number[] }

/** Expand an IPv4 CIDR (e.g. 192.168.1.0/24) to its usable host addresses.
 *  Capped so a careless /8 can't be expanded; callers pass a LAN-sized range. */
export function expandCidrV4(cidr: string, maxHosts = 1024): string[] {
  const [addr, bitsRaw] = cidr.split('/');
  const bits = Number(bitsRaw);
  const octets = addr.split('.').map(Number);
  if (octets.length !== 4 || octets.some((o) => Number.isNaN(o) || o < 0 || o > 255) || Number.isNaN(bits) || bits < 0 || bits > 32) {
    throw new Error(`invalid IPv4 CIDR: ${cidr}`);
  }
  const base = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const size = 2 ** (32 - bits);
  const count = Math.max(0, size - 2); // drop network + broadcast
  if (count > maxHosts) throw new Error(`CIDR ${cidr} expands to ${count} hosts; max ${maxHosts}`);
  const net = (base >>> (32 - bits)) << (32 - bits);
  const out: string[] = [];
  for (let i = 1; i <= count; i++) { const a = (net + i) >>> 0; out.push(`${(a >>> 24) & 255}.${(a >>> 16) & 255}.${(a >>> 8) & 255}.${a & 255}`); }
  return out;
}

/**
 * LAN discovery (on-network agent): a non-destructive connect scan across every
 * host in an authorized CIDR. Hosts with no open port are omitted. Bounded by
 * the host cap in expandCidrV4 and by `concurrency`. The agent only runs this
 * against a range the operator is authorized for.
 */
export async function discoverSubnet(cidr: string, opts: ServiceScanOptions = {}): Promise<HostServices[]> {
  const hosts = expandCidrV4(cidr);
  const out: HostServices[] = [];
  const queue = [...hosts];
  const concurrency = Math.max(1, opts.concurrency ?? 64);
  async function worker() {
    for (;;) {
      const host = queue.shift();
      if (host === undefined) return;
      const open = await discoverServices(host, { ...opts, concurrency: 8 });
      if (open.length) out.push({ host, ports: open.map((o) => o.port) });
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, hosts.length) }, worker));
  return out.sort((a, b) => a.host.localeCompare(b.host, undefined, { numeric: true }));
}

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
