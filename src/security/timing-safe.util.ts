import { createHash, timingSafeEqual as nodeTimingSafeEqual } from "crypto";

/**
 * Timing-safe string comparison to prevent timing attacks (e.g. on refresh token or secret comparison).
 * Uses constant-time comparison of fixed-length hashes so length does not leak.
 * Use this in your IAuthUserService.isRefreshTokenValid implementation when comparing tokens.
 *
 * @param a - First string (e.g. stored token).
 * @param b - Second string (e.g. provided token).
 * @returns true only if both strings are equal.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const hash = (s: string) => createHash("sha256").update(s, "utf8").digest();
  const bufA = hash(a);
  const bufB = hash(b);
  if (bufA.length !== bufB.length) return false;
  return nodeTimingSafeEqual(bufA, bufB);
}
