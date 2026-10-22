/**
 * Pacing and the stop button (Design §8: rate limits, kill switch).
 *
 * Wraps a Sender so that every outbound request (a) waits for the configured
 * minimum spacing, (b) is refused once the overall deadline has passed, and
 * (c) is refused once the caller's AbortSignal fires (Ctrl+C, admin stop).
 * A refusal throws ScanStopped; scanners catch it, stop sending, and report
 * what was covered so far instead of pretending the scan completed.
 */
import type { Sender } from './client';

export interface PacingOptions {
  /** Upper bound on outbound requests per second. Default 5. */
  requestsPerSecond?: number;
  /** Whole-scan budget; requests after this throw ScanStopped. */
  maxDurationMs?: number;
  /** External stop (Ctrl+C / kill switch). */
  signal?: AbortSignal;
  /** Injectable clock for tests. */
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

export class ScanStopped extends Error {
  constructor(public reason: 'deadline' | 'aborted', public requestsSent: number) {
    super(`scan stopped (${reason}) after ${requestsSent} request(s)`);
    this.name = 'ScanStopped';
  }
}

export interface PacedSender extends Sender {
  readonly stats: { requests: number; startedAt: number };
}

export function pacedSender(sender: Sender, opts: PacingOptions = {}): PacedSender {
  const rps = opts.requestsPerSecond ?? 5;
  const minGap = rps > 0 ? 1000 / rps : 0;
  const now = opts.now ?? Date.now;
  const sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  const startedAt = now();
  const stats = { requests: 0, startedAt };
  let nextAllowedAt = startedAt;

  const send: Sender = async (req, ident) => {
    if (opts.signal?.aborted) throw new ScanStopped('aborted', stats.requests);
    if (opts.maxDurationMs != null && now() - startedAt >= opts.maxDurationMs) throw new ScanStopped('deadline', stats.requests);
    const wait = nextAllowedAt - now();
    if (wait > 0) await sleep(wait);
    nextAllowedAt = Math.max(now(), nextAllowedAt) + minGap;
    if (opts.signal?.aborted) throw new ScanStopped('aborted', stats.requests);
    stats.requests++;
    return sender(req, ident);
  };
  return Object.assign(send, { stats });
}
