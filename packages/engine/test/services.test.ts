import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { discoverServices, discoverSubnet, expandCidrV4 } from '../src';

let srv: Server; let port: number;
beforeAll(async () => {
  srv = createServer((_req, res) => res.end('ok'));
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
  port = (srv.address() as AddressInfo).port;
});
afterAll(() => srv.close());

describe('discoverServices (non-destructive connect scan)', () => {
  it('reports a listening port as open and a closed one as absent', async () => {
    const closed = port === 59999 ? 59998 : 59999;
    const open = await discoverServices('127.0.0.1', { ports: [port, closed], timeoutMs: 500 });
    expect(open.map((o) => o.port)).toContain(port);
    expect(open.map((o) => o.port)).not.toContain(closed);
  });

  it('returns nothing for an all-closed set without throwing', async () => {
    const open = await discoverServices('127.0.0.1', { ports: [59997, 59996], timeoutMs: 300 });
    expect(open).toEqual([]);
  });
});

describe('LAN subnet discovery', () => {
  it('expands an IPv4 CIDR to usable hosts and caps huge ranges', () => {
    expect(expandCidrV4('192.168.1.0/30')).toEqual(['192.168.1.1', '192.168.1.2']);
    expect(() => expandCidrV4('10.0.0.0/8')).toThrow(/max/);
    expect(() => expandCidrV4('not-a-cidr')).toThrow(/invalid/);
  });

  it('finds the listening host in a tiny loopback range, non-destructively', async () => {
    const found = await discoverSubnet('127.0.0.0/30', { ports: [port], timeoutMs: 400 });
    expect(found.some((h) => h.host === '127.0.0.1' && h.ports.includes(port))).toBe(true);
  });
});
