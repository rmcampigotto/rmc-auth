import type { ILoginRateLimitStore } from "../interfaces/auth.options";

interface Entry {
  count: number;
  windowEnd: number;
}

export interface InMemoryLoginRateLimitStoreOptions {
  /**
   * Max number of tracked keys. When exceeded, expired entries are purged and, if still full,
   * the oldest keys are evicted. Prevents unbounded memory growth under attack.
   * @default 10000
   */
  maxEntries?: number;
}

/**
 * In-memory store for login rate limiting. Suitable for single-instance apps.
 * For distributed apps, implement ILoginRateLimitStore with Redis or a database.
 */
export class InMemoryLoginRateLimitStore implements ILoginRateLimitStore {
  private readonly store = new Map<string, Entry>();
  private readonly maxEntries: number;

  constructor(options: InMemoryLoginRateLimitStoreOptions = {}) {
    this.maxEntries = options.maxEntries ?? 10000;
  }

  /** Number of keys currently tracked. */
  get size(): number {
    return this.store.size;
  }

  async getAttempts(key: string): Promise<number> {
    const entry = this.store.get(key);
    if (!entry) return 0;
    if (Date.now() > entry.windowEnd) {
      this.store.delete(key);
      return 0;
    }
    return entry.count;
  }

  async increment(key: string, windowMs: number): Promise<number> {
    const now = Date.now();
    const entry = this.store.get(key);
    if (!entry || now > entry.windowEnd) {
      if (!entry) this.ensureCapacity(now);
      const newEntry: Entry = { count: 1, windowEnd: now + windowMs };
      this.store.set(key, newEntry);
      return 1;
    }
    entry.count += 1;
    return entry.count;
  }

  async reset(key: string): Promise<void> {
    this.store.delete(key);
  }

  /** Removes expired entries. */
  prune(now = Date.now()): void {
    for (const [key, entry] of this.store) {
      if (now > entry.windowEnd) this.store.delete(key);
    }
  }

  /** Removes every entry. */
  clear(): void {
    this.store.clear();
  }

  private ensureCapacity(now: number): void {
    if (this.store.size < this.maxEntries) return;
    this.prune(now);
    // Map preserves insertion order: evict the oldest keys first.
    for (const key of this.store.keys()) {
      if (this.store.size < this.maxEntries) break;
      this.store.delete(key);
    }
  }
}
