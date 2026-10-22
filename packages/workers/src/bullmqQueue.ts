/**
 * BullMQ (Redis) implementation of the worker Queue interface (Design §4).
 *
 * Same contract as InMemoryQueue: `add` enqueues, `process` registers the
 * single handler, `drain` resolves with the results of every job added
 * through THIS instance that had not been drained yet, in add order. A job
 * whose handler throws rejects `drain` with that job's error after retries
 * are exhausted.
 *
 * Job data travels through Redis as JSON: never put secrets in it. Scan jobs
 * carry identity KEYS (sessionRef); the material stays in the API process's
 * SecretStore.
 */
import { Queue as BQueue, QueueEvents, Worker, type ConnectionOptions, type JobsOptions } from 'bullmq';
import type { Job, JobHandler, Queue } from './queue';

export interface BullMqQueueOptions {
  /** e.g. redis://127.0.0.1:6379 */
  redisUrl: string;
  /** Concurrency of this process's worker. Default 1 (scans are paced per grant). */
  concurrency?: number;
  jobOptions?: JobsOptions;
}

export function connectionFromUrl(redisUrl: string): ConnectionOptions {
  const u = new URL(redisUrl);
  return {
    host: u.hostname,
    port: u.port ? Number(u.port) : 6379,
    ...(u.username ? { username: decodeURIComponent(u.username) } : {}),
    ...(u.password ? { password: decodeURIComponent(u.password) } : {}),
    ...(u.pathname && u.pathname !== '/' ? { db: Number(u.pathname.slice(1)) } : {}),
    ...(u.protocol === 'rediss:' ? { tls: {} } : {}),
    maxRetriesPerRequest: null, // required by BullMQ workers
  };
}

export class BullMqQueue<T, R> implements Queue<T, R> {
  private queue: BQueue;
  private events: QueueEvents;
  private worker?: Worker;
  private pending: string[] = [];
  private connection: ConnectionOptions;

  constructor(readonly name: string, private opts: BullMqQueueOptions) {
    this.connection = connectionFromUrl(opts.redisUrl);
    this.queue = new BQueue(name, {
      connection: this.connection,
      defaultJobOptions: {
        attempts: 1,
        removeOnComplete: { age: 24 * 3600, count: 1000 },
        removeOnFail: { age: 7 * 24 * 3600 },
        ...opts.jobOptions,
      },
    });
    this.events = new QueueEvents(name, { connection: this.connection });
  }

  async add(data: T): Promise<Job<T>> {
    await this.events.waitUntilReady();
    const job = await this.queue.add(this.name, data as object);
    this.pending.push(job.id!);
    return { id: job.id!, data };
  }

  process(handler: JobHandler<T, R>): void {
    if (this.worker) throw new Error(`queue '${this.name}' already has a handler`);
    this.worker = new Worker(
      this.name,
      async (job) => handler({ id: job.id!, data: job.data as T }),
      { connection: this.connection, concurrency: this.opts.concurrency ?? 1 },
    );
  }

  async drain(): Promise<R[]> {
    if (!this.worker) throw new Error('no handler registered');
    const ids = this.pending.splice(0);
    const results: R[] = [];
    for (const id of ids) {
      const job = await this.queue.getJob(id);
      if (!job) throw new Error(`job ${id} disappeared from queue '${this.name}'`);
      results.push((await job.waitUntilFinished(this.events)) as R);
    }
    return results;
  }

  /** Close Redis connections. Call on shutdown and in tests. */
  async close(): Promise<void> {
    await this.worker?.close();
    await this.events.close();
    await this.queue.close();
  }

  /** Remove every job of this queue from Redis (tests only). */
  async obliterate(): Promise<void> {
    await this.queue.obliterate({ force: true });
  }
}
