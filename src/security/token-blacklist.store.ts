/**
 * Store of revoked access tokens (by `jti`). Implement with Redis or a database for distributed apps.
 * Entries only need to live until the token would expire anyway (`expiresAt`, epoch ms).
 */
export interface ITokenBlacklistStore {
  add(jti: string, expiresAt: number): Promise<void>;
  has(jti: string): Promise<boolean>;
}

/**
 * In-memory blacklist of revoked access tokens. Suitable for single-instance apps.
 * Expired entries are removed automatically.
 */
export class InMemoryTokenBlacklistStore implements ITokenBlacklistStore {
  private readonly store = new Map<string, number>();
  private operations = 0;

  get size(): number {
    return this.store.size;
  }

  async add(jti: string, expiresAt: number): Promise<void> {
    if (++this.operations % 100 === 0) this.prune();
    this.store.set(jti, expiresAt);
  }

  async has(jti: string): Promise<boolean> {
    const expiresAt = this.store.get(jti);
    if (expiresAt === undefined) return false;
    if (Date.now() > expiresAt) {
      this.store.delete(jti);
      return false;
    }
    return true;
  }

  /** Removes expired entries. */
  prune(now = Date.now()): void {
    for (const [jti, expiresAt] of this.store) {
      if (now > expiresAt) this.store.delete(jti);
    }
  }

  clear(): void {
    this.store.clear();
  }
}
