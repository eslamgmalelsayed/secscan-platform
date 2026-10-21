/**
 * Minimal queue abstraction (Design §4: Redis + BullMQ).
 *
 * The production adapter is BullMQ over Redis; it is intentionally not wired
 * here because it needs a running Redis. Worker *logic* is written against
 * this interface so it is testable without infra, and a thin BullMQ adapter
 * implements the same shape in deployment.
 */
export interface Job<T> {
  id: string;
  data: T;
}

export type JobHandler<T, R> = (job: Job<T>) => Promise<R>;

export interface Queue<T, R> {
  add(data: T): Promise<Job<T>>;
  process(handler: JobHandler<T, R>): void;
  /** Resolve once the backlog present at call time has drained. */
  drain(): Promise<R[]>;
}

/** In-memory queue for tests and local dev. FIFO, single consumer. */
export class InMemoryQueue<T, R> implements Queue<T, R> {
  private backlog: Job<T>[] = [];
  private handler?: JobHandler<T, R>;
  private seq = 0;

  async add(data: T): Promise<Job<T>> {
    const job: Job<T> = { id: `job-${++this.seq}`, data };
    this.backlog.push(job);
    return job;
  }

  process(handler: JobHandler<T, R>): void {
    this.handler = handler;
  }

  async drain(): Promise<R[]> {
    if (!this.handler) throw new Error('no handler registered');
    const results: R[] = [];
    while (this.backlog.length) {
      const job = this.backlog.shift()!;
      results.push(await this.handler(job));
    }
    return results;
  }
}
