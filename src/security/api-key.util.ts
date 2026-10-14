import { randomBytes } from "crypto";
import { hashToken } from "./token.util";

export interface GeneratedApiKey {
  /** The full key. Show it to the user once; never store it. */
  key: string;
  /** SHA-256 hash of the key. Store this and look keys up by it. */
  hash: string;
  /** Non-secret prefix (e.g. `rmc_live_a1b2c3`) to help users identify the key in a UI. */
  displayPrefix: string;
}

/**
 * Generates a random API key in the format `<prefix>_<random>`.
 * @param prefix - Identifies the key type, e.g. 'sk_live'. Only letters, digits and underscores.
 */
export function generateApiKey(prefix = "rmc", bytes = 32): GeneratedApiKey {
  if (!/^[A-Za-z0-9_]{1,32}$/.test(prefix)) {
    throw new Error("generateApiKey: 'prefix' must contain only letters, digits and underscores (max 32).");
  }
  if (!Number.isInteger(bytes) || bytes < 16) throw new Error("generateApiKey: 'bytes' must be an integer >= 16.");
  const key = `${prefix}_${randomBytes(bytes).toString("base64url")}`;
  return { key, hash: hashToken(key), displayPrefix: key.slice(0, prefix.length + 7) };
}

/** Hash used to look up an API key (same as `hashToken`). */
export function hashApiKey(key: string): string {
  return hashToken(key);
}
