import type { ILoginRateLimitStore } from "../interfaces/auth.options";

interface Entry {
  count: number;
  windowEnd: number;
}

/**
 * In-memory store for login rate limiting. Suitable for single-instance apps.
 * For distributed apps, implement ILoginRateLimitStore with Redis or a database.
 */
export class InMemoryLoginRateLimitStore implements ILoginRateLimitStore {
  private readonly store = new Map<string, Entry>();

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
}
