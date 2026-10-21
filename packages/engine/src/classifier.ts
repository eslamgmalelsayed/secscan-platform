/**
 * Classify a recorded request by side-effect risk (Design §8).
 * Replaying a GET is safe; replaying POST /checkout may place a real order.
 * State-changing requests are held for staging / explicit per-scope approval.
 */
import type { RecordedRequest } from './http';

export type SideEffect = 'safe' | 'idempotent' | 'state_changing';

const SAFE = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);
const IDEMPOTENT = new Set([...SAFE, 'PUT', 'DELETE']);

const DESTRUCTIVE_PATH_HINTS = [
  'delete', 'remove', 'drop', 'purge', 'cancel', 'refund',
  'checkout', 'pay', 'transfer', 'withdraw', 'deactivate', 'reset',
];

export function classify(req: RecordedRequest): SideEffect {
  const method = req.method.toUpperCase();
  const path = req.url.toLowerCase();
  if (DESTRUCTIVE_PATH_HINTS.some((h) => path.includes(h))) return 'state_changing';
  if (SAFE.has(method)) return 'safe';
  if (IDEMPOTENT.has(method)) return 'idempotent';
  return 'state_changing';
}

/** Only genuinely safe reads replay against production by default (§8). */
export const replayableAgainstProduction = (req: RecordedRequest): boolean =>
  classify(req) === 'safe';
