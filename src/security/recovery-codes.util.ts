import { randomBytes } from "crypto";
import { hashToken } from "./token.util";

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O/1/I to avoid confusion

/** Normalizes a recovery code typed by the user (case, spaces and dashes are ignored). */
export function normalizeRecoveryCode(code: string): string {
  return typeof code === "string" ? code.toUpperCase().replace(/[\s-]/g, "") : "";
}

/** SHA-256 hash of a normalized recovery code. Store only these hashes. */
export function hashRecoveryCode(code: string): string {
  return hashToken(normalizeRecoveryCode(code));
}

/**
 * Generates one-time recovery codes for two-factor authentication (format `XXXXX-XXXXX`).
 * Show `codes` to the user once and store only `hashes`.
 */
export function generateRecoveryCodes(count = 10, length = 10): { codes: string[]; hashes: string[] } {
  if (!Number.isInteger(count) || count < 1) throw new Error("generateRecoveryCodes: 'count' must be >= 1.");
  if (!Number.isInteger(length) || length < 8) throw new Error("generateRecoveryCodes: 'length' must be >= 8.");
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const bytes = randomBytes(length);
    let raw = "";
    for (const byte of bytes) raw += ALPHABET[byte % ALPHABET.length];
    const half = Math.ceil(length / 2);
    codes.push(`${raw.slice(0, half)}-${raw.slice(half)}`);
  }
  return { codes, hashes: codes.map(hashRecoveryCode) };
}
