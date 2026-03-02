import { Test, TestingModule } from "@nestjs/testing";
import { BadRequestException } from "@nestjs/common";
import { EncryptionService } from "./encryption.service";
import { MODULE_OPTIONS_TOKEN } from "./encryption.module-definition";
import type { EncryptionOptions } from "../../interfaces/encryption.options";

describe("EncryptionService", () => {
  let service: EncryptionService;

  const defaultOptions: EncryptionOptions = {
    saltRounds: 10,
    algorithm: "bcrypt",
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EncryptionService,
        {
          provide: MODULE_OPTIONS_TOKEN,
          useValue: defaultOptions,
        },
      ],
    }).compile();

    service = module.get<EncryptionService>(EncryptionService);
  });

  it("should be defined", () => {
    expect(service).toBeDefined();
  });

  describe("hash", () => {
    it("should hash a password with bcrypt", async () => {
      const hash = await service.hash("myPassword123");
      expect(hash).toBeDefined();
      expect(hash).not.toBe("myPassword123");
      expect(hash.startsWith("$2")).toBe(true);
    });

    it("should throw when password is empty", async () => {
      await expect(service.hash("")).rejects.toThrow("Password is required");
    });

    it("should throw BadRequestException when strongPasswordValidation fails (too short)", async () => {
      const module = await Test.createTestingModule({
        providers: [
          EncryptionService,
          {
            provide: MODULE_OPTIONS_TOKEN,
            useValue: { ...defaultOptions, strongPasswordValidation: true },
          },
        ],
      }).compile();
      const svc = module.get<EncryptionService>(EncryptionService);

      await expect(svc.hash("short")).rejects.toThrow(BadRequestException);
    });

    it("should throw BadRequestException when password is only numbers", async () => {
      const module = await Test.createTestingModule({
        providers: [
          EncryptionService,
          {
            provide: MODULE_OPTIONS_TOKEN,
            useValue: { ...defaultOptions, strongPasswordValidation: true },
          },
        ],
      }).compile();
      const svc = module.get<EncryptionService>(EncryptionService);

      await expect(svc.hash("12345678")).rejects.toThrow(BadRequestException);
    });

    it("should accept valid password with strongPasswordValidation", async () => {
      const module = await Test.createTestingModule({
        providers: [
          EncryptionService,
          {
            provide: MODULE_OPTIONS_TOKEN,
            useValue: { ...defaultOptions, strongPasswordValidation: true },
          },
        ],
      }).compile();
      const svc = module.get<EncryptionService>(EncryptionService);

      const hash = await svc.hash("ValidPass1");
      expect(hash).toBeDefined();
    });
  });

  describe("compare", () => {
    it("should return true for matching password and hash", async () => {
      const password = "testPassword";
      const hash = await service.hash(password);
      const result = await service.compare(password, hash);
      expect(result).toBe(true);
    });

    it("should return false for wrong password", async () => {
      const hash = await service.hash("correct");
      const result = await service.compare("wrong", hash);
      expect(result).toBe(false);
    });
  });
});
