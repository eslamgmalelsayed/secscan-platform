/**
 * Scan queue producer/consumer and the Redis stop signal (Design §4, review
 * gaps 1 & 3). Thin wrappers over BullMqQueue so the API can enqueue and a
 * separate worker process can consume, sharing state only through Redis.
 *
 * Job payloads are JSON in Redis: they carry identity KEYS, never secrets.
 * The worker resolves material from its own SecretStore.
 */
import { Redis } from 'ioredis';
import { BullMqQueue, connectionFromUrl } from './bullmqQueue';

const SCAN_QUEUE = 'secscan-scan';

/** Producer side (API): structurally a core `ScanQueue` ({ add(job) }). */
export interface ScanQueueProducer {
  add(job: unknown): Promise<void>;
  close(): Promise<void>;
}

export function scanQueueProducer(redisUrl: string): ScanQueueProducer {
  const q = new BullMqQueue<unknown, void>(SCAN_QUEUE, { redisUrl });
  return { add: async (job) => { await q.add(job); }, close: () => q.close() };
}

/** Consumer side (worker process): runs `handler` for every queued scan job. */
export function startScanWorker(
  redisUrl: string, handler: (job: unknown) => Promise<void>, concurrency = 1,
): BullMqQueue<unknown, void> {
  const q = new BullMqQueue<unknown, void>(SCAN_QUEUE, { redisUrl, concurrency });
  q.process(async (job) => { await handler(job.data); });
  return q; // caller keeps it to close() on shutdown
}

/**
 * Cross-process stop flag in Redis. Structurally a core `StopSignal`. A short
 * TTL keeps stale keys from lingering if a worker dies mid-scan.
 */
export class RedisStopSignal {
  private r: Redis;
  constructor(redisUrl: string, private ttlSeconds = 3600) {
    this.r = new Redis({ ...connectionFromUrl(redisUrl) } as any);
  }
  private key(scanId: string) { return `secscan:stop:${scanId}`; }
  async request(scanId: string): Promise<void> { await this.r.set(this.key(scanId), '1', 'EX', this.ttlSeconds); }
  async isRequested(scanId: string): Promise<boolean> { return (await this.r.exists(this.key(scanId))) === 1; }
  async clear(scanId: string): Promise<void> { await this.r.del(this.key(scanId)); }
  async close(): Promise<void> { await this.r.quit(); }
}
