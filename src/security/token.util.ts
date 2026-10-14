import { createHash, randomBytes } from "crypto";

/**
 * Generates a cryptographically secure random token (URL-safe base64).
 * Useful for password reset links, email verification, API keys, etc.
 * @param bytes - Amount of random bytes (default 32 = 256 bits).
 */
export function generateSecureToken(bytes = 32): string {
  if (!Number.isInteger(bytes) || bytes < 16) {
    throw new Error("generateSecureToken: 'bytes' must be an integer >= 16.");
  }
  return randomBytes(bytes).toString("base64url");
}

/**
 * Deterministic SHA-256 hash (hex) of a token.
 * Store this instead of the raw token so a database leak does not expose usable tokens.
 */
export function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}
