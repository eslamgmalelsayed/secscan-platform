/**
 * Cross-process stop (Design §8 kill switch, review gap 3).
 *
 * A running scan lives in the worker process; the API that receives
 * POST /scans/:id/stop is a different process. So "stop" is a shared flag:
 * the API sets it, the worker polls it and aborts the paced sender. The
 * in-memory implementation covers the single-process / inline path (dev, CLI,
 * tests); the Redis implementation (packages/workers) shares it across
 * processes.
 */
export interface StopSignal {
  request(scanId: string): Promise<void>;
  isRequested(scanId: string): Promise<boolean>;
  clear(scanId: string): Promise<void>;
}

export class InMemoryStopSignal implements StopSignal {
  private set = new Set<string>();
  async request(scanId: string) { this.set.add(scanId); }
  async isRequested(scanId: string) { return this.set.has(scanId); }
  async clear(scanId: string) { this.set.delete(scanId); }
}

/**
 * Bridge a StopSignal to an AbortController by polling. Returns a stop()
 * that clears the timer. The worker starts this around a running scan so the
 * paced sender (which takes the AbortSignal) halts shortly after a stop is
 * requested.
 */
export function pollStop(
  signal: StopSignal, scanId: string, controller: AbortController,
  { intervalMs = 400 }: { intervalMs?: number } = {},
): () => void {
  const timer = setInterval(async () => {
    try { if (await signal.isRequested(scanId)) controller.abort(); } catch { /* ignore */ }
  }, intervalMs);
  if (typeof timer === 'object' && 'unref' in timer) (timer as any).unref();
  return () => clearInterval(timer);
}
