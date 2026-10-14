import { createHmac, randomBytes } from "crypto";
import { timingSafeEqual } from "./timing-safe.util";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export interface TotpOptions {
  /** Code length. @default 6 */
  digits?: number;
  /** Time step in seconds. @default 30 */
  period?: number;
  /** Accepted steps before/after the current one (clock drift). @default 1 */
  window?: number;
  /** Current time in ms (for tests). @default Date.now() */
  timestamp?: number;
}

/** RFC 4648 base32 encoding (no padding), as used by authenticator apps. */
export function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

/** RFC 4648 base32 decoding. Ignores spaces, dashes, padding and case. */
export function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) throw new Error("Invalid base32 character");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** Generates a random base32 TOTP secret (default 20 bytes = 160 bits, as recommended by RFC 4226). */
export function generateTotpSecret(bytes = 20): string {
  if (!Number.isInteger(bytes) || bytes < 16) {
    throw new Error("generateTotpSecret: 'bytes' must be an integer >= 16.");
  }
  return base32Encode(randomBytes(bytes));
}

function hotp(key: Buffer, counter: number, digits: number): string {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", key).update(buffer).digest();
  const offset = digest[digest.length - 1] & 0xf;
  const code = (digest.readUInt32BE(offset) & 0x7fffffff) % 10 ** digits;
  return code.toString().padStart(digits, "0");
}

/** Generates the current TOTP code (RFC 6238, HMAC-SHA1). */
export function generateTotp(secret: string, options: TotpOptions = {}): string {
  const period = options.period ?? 30;
  const step = Math.floor((options.timestamp ?? Date.now()) / 1000 / period);
  return hotp(base32Decode(secret), step, options.digits ?? 6);
}

/**
 * Verifies a TOTP code. Returns the matched time step (use it for replay protection) or null.
 */
export function verifyTotp(secret: string, code: string, options: TotpOptions = {}): number | null {
  const digits = options.digits ?? 6;
  if (typeof code !== "string" || typeof secret !== "string") return null;
  const normalized = code.replace(/\s/g, "");
  if (!new RegExp(`^\\d{${digits}}$`).test(normalized)) return null;

  let key: Buffer;
  try {
    key = base32Decode(secret);
  } catch {
    return null;
  }
  if (key.length === 0) return null;

  const period = options.period ?? 30;
  const window = options.window ?? 1;
  const current = Math.floor((options.timestamp ?? Date.now()) / 1000 / period);
  let matched: number | null = null;
  // Check every step (no early return) to keep timing constant.
  for (let step = current - window; step <= current + window; step++) {
    if (step >= 0 && timingSafeEqual(hotp(key, step, digits), normalized) && matched === null) matched = step;
  }
  return matched;
}

/**
 * Builds the `otpauth://` URL that authenticator apps read from a QR code.
 * @example buildOtpAuthUrl({ secret, account: 'user@example.com', issuer: 'My App' })
 */
export function buildOtpAuthUrl(params: {
  secret: string;
  account: string;
  issuer?: string;
  digits?: number;
  period?: number;
}): string {
  const label = params.issuer
    ? `${encodeURIComponent(params.issuer)}:${encodeURIComponent(params.account)}`
    : encodeURIComponent(params.account);
  const query = new URLSearchParams({ secret: params.secret, algorithm: "SHA1" });
  if (params.issuer) query.set("issuer", params.issuer);
  query.set("digits", String(params.digits ?? 6));
  query.set("period", String(params.period ?? 30));
  return `otpauth://totp/${label}?${query.toString()}`;
}
