import { describe, it, expect } from 'vitest';
import { pacedSender, ScanStopped, type Sender, type RecordedResponse } from '../src';

const ok: RecordedResponse = { status: 200, headers: {}, body: 'x' };
const req = { method: 'GET', url: 'https://a/x' };
const anon = { role: 'anonymous', sessionRef: null };

function fakeClock() {
  let t = 0;
  return { now: () => t, sleep: async (ms: number) => { t += ms; }, advance: (ms: number) => { t += ms; } };
}

describe('pacedSender', () => {
  it('spaces requests to the configured rate', async () => {
    const c = fakeClock();
    const stamps: number[] = [];
    const inner: Sender = async () => { stamps.push(c.now()); return ok; };
    const send = pacedSender(inner, { requestsPerSecond: 2, now: c.now, sleep: c.sleep });
    for (let i = 0; i < 4; i++) await send(req, anon);
    expect(stamps).toEqual([0, 500, 1000, 1500]);
    expect(send.stats.requests).toBe(4);
  });

  it('throws ScanStopped(deadline) once the budget is spent, counting what was sent', async () => {
    const c = fakeClock();
    const send = pacedSender(async () => ok, { requestsPerSecond: 1000, maxDurationMs: 1000, now: c.now, sleep: c.sleep });
    await send(req, anon);
    c.advance(1500);
    await expect(send(req, anon)).rejects.toMatchObject({ name: 'ScanStopped', reason: 'deadline', requestsSent: 1 });
  });

  it('throws ScanStopped(aborted) after the signal fires and sends nothing more', async () => {
    let calls = 0;
    const ac = new AbortController();
    const send = pacedSender(async () => { calls++; return ok; }, { requestsPerSecond: 1000, signal: ac.signal });
    await send(req, anon);
    ac.abort();
    await expect(send(req, anon)).rejects.toBeInstanceOf(ScanStopped);
    expect(calls).toBe(1);
  });
});
