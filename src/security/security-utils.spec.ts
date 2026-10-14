import { InMemoryLoginRateLimitStore } from "./login-rate-limit.store";
import { generateSecureToken, hashToken } from "./token.util";
import { timingSafeEqual } from "./timing-safe.util";

describe("security utilities", () => {
  describe("InMemoryLoginRateLimitStore", () => {
    it("counts attempts within a window and resets", async () => {
      const store = new InMemoryLoginRateLimitStore();
      expect(await store.increment("k", 60_000)).toBe(1);
      expect(await store.increment("k", 60_000)).toBe(2);
      expect(await store.getAttempts("k")).toBe(2);
      await store.reset("k");
      expect(await store.getAttempts("k")).toBe(0);
    });

    it("expires entries after the window", async () => {
      const store = new InMemoryLoginRateLimitStore();
      const now = jest.spyOn(Date, "now").mockReturnValue(1_000);
      await store.increment("k", 100);
      now.mockReturnValue(2_000);
      expect(await store.getAttempts("k")).toBe(0);
      expect(await store.increment("k", 100)).toBe(1);
      now.mockRestore();
    });

    it("never grows beyond maxEntries", async () => {
      const store = new InMemoryLoginRateLimitStore({ maxEntries: 3 });
      for (let i = 0; i < 10; i++) await store.increment(`k${i}`, 60_000);
      expect(store.size).toBe(3);
      expect(await store.getAttempts("k9")).toBe(1);
      expect(await store.getAttempts("k0")).toBe(0);
    });
  });

  describe("token utils", () => {
    it("generates unique URL-safe tokens", () => {
      const a = generateSecureToken();
      expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(generateSecureToken()).not.toBe(a);
      expect(() => generateSecureToken(8)).toThrow();
    });

    it("hashes deterministically", () => {
      expect(hashToken("abc")).toBe(hashToken("abc"));
      expect(hashToken("abc")).toHaveLength(64);
    });

    it("timingSafeEqual compares strings", () => {
      expect(timingSafeEqual("a", "a")).toBe(true);
      expect(timingSafeEqual("a", "ab")).toBe(false);
    });
  });
});

describe("InMemoryTokenBlacklistStore", () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { InMemoryTokenBlacklistStore } = require("./token-blacklist.store");

  it("tracks revoked ids until they expire", async () => {
    const store = new InMemoryTokenBlacklistStore();
    await store.add("jti-1", Date.now() + 60_000);
    await store.add("jti-2", Date.now() - 1);
    expect(await store.has("jti-1")).toBe(true);
    expect(await store.has("jti-2")).toBe(false);
    expect(await store.has("unknown")).toBe(false);
    store.prune();
    expect(store.size).toBe(1);
  });
});
