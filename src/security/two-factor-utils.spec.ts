import {
  base32Decode,
  base32Encode,
  buildOtpAuthUrl,
  generateTotp,
  generateTotpSecret,
  verifyTotp,
} from "./totp.util";
import { generateRecoveryCodes, hashRecoveryCode } from "./recovery-codes.util";
import { decryptSecret, encryptSecret } from "./secret-cipher.util";
import { generateApiKey, hashApiKey } from "./api-key.util";

// RFC 6238 appendix B test secret: ASCII "12345678901234567890".
const RFC_SECRET = base32Encode(Buffer.from("12345678901234567890"));

describe("TOTP", () => {
  it("encodes/decodes base32", () => {
    expect(RFC_SECRET).toBe("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    expect(base32Decode("gezd-gnbv gy3t qojq gezdgnbvgy3tqojq====").toString()).toBe("12345678901234567890");
    expect(() => base32Decode("01!")).toThrow();
  });

  it.each([
    [59, "94287082"],
    [1111111109, "07081804"],
    [1234567890, "89005924"],
    [2000000000, "69279037"],
  ])("matches RFC 6238 vectors at T=%i", (seconds, expected) => {
    expect(generateTotp(RFC_SECRET, { timestamp: seconds * 1000, digits: 8 })).toBe(expected);
  });

  it("verifies codes within the window and returns the step", () => {
    const secret = generateTotpSecret();
    const now = 1_700_000_000_000;
    const previous = generateTotp(secret, { timestamp: now - 30_000 });
    expect(verifyTotp(secret, generateTotp(secret, { timestamp: now }), { timestamp: now })).toBe(Math.floor(now / 30_000));
    expect(verifyTotp(secret, previous, { timestamp: now })).toBe(Math.floor(now / 30_000) - 1);
    expect(verifyTotp(secret, previous, { timestamp: now, window: 0 })).toBeNull();
  });

  it("rejects malformed input", () => {
    const secret = generateTotpSecret();
    expect(verifyTotp(secret, "abc")).toBeNull();
    expect(verifyTotp(secret, "1234567")).toBeNull();
    expect(verifyTotp("!!", "123456")).toBeNull();
    expect(() => generateTotpSecret(8)).toThrow();
  });

  it("builds otpauth URLs", () => {
    const url = buildOtpAuthUrl({ secret: "ABC", account: "user@example.com", issuer: "My App" });
    expect(url).toBe("otpauth://totp/My%20App:user%40example.com?secret=ABC&algorithm=SHA1&issuer=My+App&digits=6&period=30");
  });
});

describe("recovery codes", () => {
  it("generates unique codes and matching hashes", () => {
    const { codes, hashes } = generateRecoveryCodes(8);
    expect(codes).toHaveLength(8);
    expect(new Set(codes).size).toBe(8);
    expect(codes[0]).toMatch(/^[A-Z2-9]{5}-[A-Z2-9]{5}$/);
    expect(hashRecoveryCode(codes[0].toLowerCase().replace("-", " "))).toBe(hashes[0]);
    expect(() => generateRecoveryCodes(0)).toThrow();
  });
});

describe("secret cipher", () => {
  const key = "a-very-long-encryption-key-123";

  it("encrypts with a random IV and decrypts", () => {
    const a = encryptSecret("JBSWY3DPEHPK3PXP", key);
    const b = encryptSecret("JBSWY3DPEHPK3PXP", key);
    expect(a).not.toBe(b);
    expect(decryptSecret(a, key)).toBe("JBSWY3DPEHPK3PXP");
  });

  it("detects tampering and wrong keys", () => {
    const value = encryptSecret("secret", key);
    const parts = value.split(".");
    parts[3] = Buffer.from("other").toString("base64url");
    expect(() => decryptSecret(parts.join("."), key)).toThrow();
    expect(() => decryptSecret(value, "another-long-encryption-key")).toThrow();
    expect(() => decryptSecret("garbage", key)).toThrow("format");
    expect(() => encryptSecret("x", "short")).toThrow();
  });
});

describe("API keys", () => {
  it("generates prefixed keys with hashes", () => {
    const { key, hash, displayPrefix } = generateApiKey("sk_live");
    expect(key).toMatch(/^sk_live_[A-Za-z0-9_-]{43}$/);
    expect(hash).toBe(hashApiKey(key));
    expect(key.startsWith(displayPrefix)).toBe(true);
    expect(generateApiKey().key).not.toBe(key);
    expect(() => generateApiKey("bad prefix")).toThrow();
  });
});
