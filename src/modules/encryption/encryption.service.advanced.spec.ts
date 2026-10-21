import { Test } from "@nestjs/testing";
import { BadRequestException } from "@nestjs/common";
import { EncryptionService } from "./encryption.service";
import { EncryptionModule } from "./encryption.module";
import { MODULE_OPTIONS_TOKEN } from "./encryption.module-definition";
import type { EncryptionOptions } from "../../interfaces/encryption.options";

async function create(options: EncryptionOptions): Promise<EncryptionService> {
  const mod = await Test.createTestingModule({
    providers: [EncryptionService, { provide: MODULE_OPTIONS_TOKEN, useValue: options }],
  }).compile();
  return mod.get(EncryptionService);
}

const FAST_ARGON = { memoryCost: 1024, timeCost: 1, parallelism: 1 };

describe("EncryptionService (advanced)", () => {
  describe("validatePassword / passwordPolicy", () => {
    it("reports every failed rule", async () => {
      const svc = await create({
        passwordPolicy: { minLength: 10, requireUppercase: true, requireNumber: true, requireSymbol: true },
      });
      const result = svc.validatePassword("abc");
      expect(result.valid).toBe(false);
      expect(result.errors).toHaveLength(4);
    });

    it("accepts a password that satisfies the policy", async () => {
      const svc = await create({
        passwordPolicy: { minLength: 10, requireUppercase: true, requireLowercase: true, requireNumber: true, requireSymbol: true },
      });
      expect(svc.validatePassword("Str0ng!Passw")).toEqual({ valid: true, errors: [] });
    });

    it("rejects blacklisted passwords (case-insensitive)", async () => {
      const svc = await create({ passwordPolicy: { blacklist: ["Password123"] } });
      expect(svc.validatePassword("password123").valid).toBe(false);
    });

    it("hash() throws BadRequestException with the policy errors", async () => {
      const svc = await create({ saltRounds: 4, passwordPolicy: { requireSymbol: true } });
      await expect(svc.hash("NoSymbols1")).rejects.toThrow(BadRequestException);
    });

    it("uses the OWASP policy when enabled", async () => {
      const svc = await create({ useOwaspPolicy: true });
      expect(svc.validatePassword("weak").valid).toBe(false);
      expect(svc.validatePassword("C0rrect-Horse-Battery!").valid).toBe(true);
    });

    it("rejects breached passwords", async () => {
      const svc = await create({ saltRounds: 4, checkPasswordBreach: async (p) => p === "breached1" });
      await expect(svc.hash("breached1")).rejects.toThrow("data breach");
    });
  });

  describe("compare", () => {
    it("returns false for malformed hashes instead of throwing", async () => {
      const svc = await create({ saltRounds: 4 });
      await expect(svc.compare("x", "not-a-hash")).resolves.toBe(false);
      await expect(svc.compare("x", "")).resolves.toBe(false);
    });

    it("verifies bcrypt hashes when configured with argon2 (migration)", async () => {
      const bcryptSvc = await create({ saltRounds: 4, pepper: "pep" });
      const argonSvc = await create({ algorithm: "argon2", argon2Options: FAST_ARGON, pepper: "pep" });
      const legacy = await bcryptSvc.hash("Password1");
      await expect(argonSvc.compare("Password1", legacy)).resolves.toBe(true);
    });

    it("supports argon2 with custom options", async () => {
      const svc = await create({ algorithm: "argon2", argon2Options: { ...FAST_ARGON, type: "argon2id" } });
      const hash = await svc.hash("Password1");
      expect(hash.startsWith("$argon2id$")).toBe(true);
      await expect(svc.compare("Password1", hash)).resolves.toBe(true);
      await expect(svc.compare("Password2", hash)).resolves.toBe(false);
    });

    it("rejects bcrypt passwords over 72 bytes (they would collide after truncation)", async () => {
      const svc = await create({ saltRounds: 4 });
      expect(svc.validatePassword("a".repeat(72)).valid).toBe(true);
      expect(svc.validatePassword("é".repeat(37))).toEqual({ valid: false, errors: ["Maximum 72 bytes allowed."] });
      await expect(svc.hash("a".repeat(73))).rejects.toThrow(BadRequestException);

      const argon = await create({ algorithm: "argon2", argon2Options: FAST_ARGON });
      expect(argon.validatePassword("a".repeat(100)).valid).toBe(true);
    });

    it("hmac pepper strategy keeps the pepper effective beyond bcrypt's 72-byte limit", async () => {
      const long = "a".repeat(80);
      const append = await create({ saltRounds: 4, pepper: "pepper-A" });
      // With 'append', the pepper would be truncated away, so such passwords are rejected.
      await expect(append.hash(long)).rejects.toThrow(BadRequestException);

      const hmacA = await create({ saltRounds: 4, pepper: "pepper-A", pepperStrategy: "hmac" });
      const hmacB = await create({ saltRounds: 4, pepper: "pepper-B", pepperStrategy: "hmac" });
      const hash = await hmacA.hash(long);
      await expect(hmacA.compare(long, hash)).resolves.toBe(true);
      await expect(hmacB.compare(long, hash)).resolves.toBe(false);
    });
  });

  describe("needsRehash", () => {
    it("detects algorithm changes and weaker bcrypt cost", async () => {
      const weak = await create({ saltRounds: 4 });
      const hash = await weak.hash("Password1");
      expect(weak.needsRehash(hash)).toBe(false);
      expect((await create({ saltRounds: 5 })).needsRehash(hash)).toBe(true);
      expect((await create({ algorithm: "argon2", argon2Options: FAST_ARGON })).needsRehash(hash)).toBe(true);
    });

    it("detects changed argon2 parameters", async () => {
      const svc = await create({ algorithm: "argon2", argon2Options: FAST_ARGON });
      const hash = await svc.hash("Password1");
      expect(svc.needsRehash(hash)).toBe(false);
      const stronger = await create({ algorithm: "argon2", argon2Options: { ...FAST_ARGON, timeCost: 2 } });
      expect(stronger.needsRehash(hash)).toBe(true);
    });

    it("returns false for unknown formats", async () => {
      const svc = await create({});
      expect(svc.needsRehash("plain")).toBe(false);
    });
  });

  it("compareDummy always resolves to false", async () => {
    const svc = await create({ saltRounds: 4 });
    await expect(svc.compareDummy("rmc-auth-dummy-password")).resolves.toBe(false);
  });

  describe("module validation", () => {
    const init = (options: EncryptionOptions) =>
      Test.createTestingModule({ imports: [EncryptionModule.register(options)] })
        .compile()
        .then((m) => m.init());

    it("rejects invalid argon2 options", async () => {
      await expect(init({ algorithm: "argon2", argon2Options: { memoryCost: 10 } })).rejects.toThrow("memoryCost");
    });

    it("rejects an invalid password policy", async () => {
      await expect(init({ passwordPolicy: { minLength: 20, maxLength: 10 } })).rejects.toThrow("passwordPolicy");
    });

    it("rejects an invalid pepper strategy", async () => {
      await expect(init({ pepper: "x", pepperStrategy: "xor" as never })).rejects.toThrow("pepperStrategy");
    });
  });
});
