import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { discoverServices } from '../src';

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
