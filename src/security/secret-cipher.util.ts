import { createCipheriv, createDecipheriv, createHash, randomBytes } from "crypto";

const VERSION = "v1";

function deriveKey(key: string | Buffer): Buffer {
  if (Buffer.isBuffer(key)) {
    if (key.length === 32) return key;
    return createHash("sha256").update(key).digest();
  }
  if (typeof key !== "string" || key.length < 16) {
    throw new Error("Secret cipher key must be a string with at least 16 characters or a 32-byte Buffer.");
  }
  return createHash("sha256").update(key, "utf8").digest();
}

/**
 * Encrypts a value with AES-256-GCM (authenticated encryption).
 * Use it for secrets you must read back, e.g. TOTP secrets stored in the database.
 * Output format: `v1.<iv>.<authTag>.<ciphertext>` (base64url).
 */
export function encryptSecret(plaintext: string, key: string | Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", deriveKey(key), iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [VERSION, iv.toString("base64url"), tag.toString("base64url"), encrypted.toString("base64url")].join(".");
}

/**
 * Decrypts a value produced by `encryptSecret()`.
 * @throws Error if the value was tampered with or the key is wrong.
 */
export function decryptSecret(payload: string, key: string | Buffer): string {
  const parts = typeof payload === "string" ? payload.split(".") : [];
  if (parts.length !== 4 || parts[0] !== VERSION) throw new Error("Invalid encrypted secret format.");
  const [, iv, tag, data] = parts;
  const decipher = createDecipheriv("aes-256-gcm", deriveKey(key), Buffer.from(iv, "base64url"));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(data, "base64url")), decipher.final()]).toString("utf8");
}
