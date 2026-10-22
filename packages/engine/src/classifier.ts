/**
 * Classify a recorded request by side-effect risk (Design §8).
 * Replaying a GET is safe; replaying POST /checkout may place a real order.
 * State-changing requests are held for staging / explicit per-scope approval.
 */
import type { RecordedRequest } from './http';

export type SideEffect = 'safe' | 'idempotent' | 'state_changing';

const SAFE = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);
const IDEMPOTENT = new Set([...SAFE, 'PUT', 'DELETE']);

/** Whole-word hints that a request mutates state whatever its method says
 *  (a GET /orders/42/cancel is not a read). Matched against words in path
 *  segments and against exact query-parameter VALUES (?action=delete), never
 *  as substrings of the whole URL: /presets, /players and ?remove_filter=0
 *  are reads. */
const MUTATING_WORDS = new Set([
  'delete', 'remove', 'drop', 'purge', 'cancel', 'refund', 'checkout', 'pay', 'payment',
  'transfer', 'withdraw', 'deactivate', 'activate', 'reset', 'approve', 'reject', 'confirm',
  'logout', 'signout', 'disable', 'enable', 'unsubscribe', 'publish', 'archive', 'restore', 'send',
]);

const words = (s: string): string[] => s.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);

function looksMutating(url: string): boolean {
  let u: URL;
  try { u = new URL(url); } catch { return false; }
  if (u.pathname.split('/').some((seg) => words(seg).some((w) => MUTATING_WORDS.has(w)))) return true;
  for (const [, v] of u.searchParams) if (MUTATING_WORDS.has(v.toLowerCase())) return true;
  return false;
}

export function classify(req: RecordedRequest): SideEffect {
  const method = req.method.toUpperCase();
  if (looksMutating(req.url)) return 'state_changing';
  if (SAFE.has(method)) return 'safe';
  if (IDEMPOTENT.has(method)) return 'idempotent';
  return 'state_changing';
}

/** Only genuinely safe reads replay against production by default (§8). */
export const replayableAgainstProduction = (req: RecordedRequest): boolean =>
  classify(req) === 'safe';
