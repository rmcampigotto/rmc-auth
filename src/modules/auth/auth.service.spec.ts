import { Test, TestingModule } from "@nestjs/testing";
import { JwtService } from "@nestjs/jwt";
import { UnauthorizedException, BadRequestException } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { MODULE_OPTIONS_TOKEN } from "./auth.module-definition";
import type { AuthOptions } from "../../interfaces/auth.options";
import type { IAuthUserService } from "../../interfaces/user-service.interface";
import type { IEncryptionService } from "../../interfaces/encryption-service.interface";

describe("AuthService", () => {
  const mockUser = {
    id: "user-1",
    email: "user@example.com",
    password: "hashed",
    roles: ["user"],
  };

  const mockAuthOptions: AuthOptions = {
    jwtSecret: "test-secret",
    expiresIn: "15m",
    identifierField: "email",
    passwordField: "password",
    rolesField: "roles",
    userService: {} as IAuthUserService,
    encryptionService: {} as IEncryptionService,
  };

  let service: AuthService;
  let jwtService: JwtService;
  let userService: IAuthUserService;
  let encryptionService: IEncryptionService;

  beforeEach(async () => {
    userService = {
      findOneByField: jest.fn().mockResolvedValue(mockUser),
      saveRefreshToken: jest.fn().mockResolvedValue(undefined),
      isRefreshTokenValid: jest.fn().mockResolvedValue(true),
    };

    encryptionService = {
      compare: jest.fn().mockResolvedValue(true),
      hash: jest.fn().mockResolvedValue("hashed"),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: MODULE_OPTIONS_TOKEN,
          useValue: { ...mockAuthOptions, userService, encryptionService },
        },
        {
          provide: JwtService,
          useValue: {
            signAsync: jest.fn().mockResolvedValue("mock-token"),
            verifyAsync: jest.fn().mockResolvedValue({ sub: mockUser.id }),
          },
        },
        {
          provide: "ENCRYPTION_SERVICE",
          useValue: encryptionService,
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    jwtService = module.get<JwtService>(JwtService);
  });

  it("should be defined", () => {
    expect(service).toBeDefined();
  });

  describe("login", () => {
    it("should return access and refresh tokens on valid credentials", async () => {
      const credentials = { email: "user@example.com", password: "plain" };
      const result = await service.login(credentials);

      expect(result).toHaveProperty("accessToken", "mock-token");
      expect(result).toHaveProperty("refreshToken");
      expect(userService.findOneByField).toHaveBeenCalledWith("email", "user@example.com");
      expect(encryptionService.compare).toHaveBeenCalledWith("plain", "hashed");
    });

    it("should throw UnauthorizedException when user not found", async () => {
      (userService.findOneByField as jest.Mock).mockResolvedValue(null);

      await expect(
        service.login({ email: "unknown@example.com", password: "any" })
      ).rejects.toThrow(UnauthorizedException);
    });

    it("should throw UnauthorizedException when password is invalid", async () => {
      (encryptionService.compare as jest.Mock).mockResolvedValue(false);

      await expect(
        service.login({ email: "user@example.com", password: "wrong" })
      ).rejects.toThrow(UnauthorizedException);
    });

    it("should throw BadRequestException when identifier exceeds max length", async () => {
      const longEmail = "a".repeat(300);
      await expect(
        service.login({ email: longEmail, password: "any" })
      ).rejects.toThrow(BadRequestException);
    });

    it("should throw BadRequestException when credentials are missing", async () => {
      await expect(service.login({})).rejects.toThrow(BadRequestException);
    });
  });

  describe("generateTokens", () => {
    it("should return only accessToken when useRefreshTokens is false", async () => {
      const options = { ...mockAuthOptions, useRefreshTokens: false, userService, encryptionService };
      const module2 = await Test.createTestingModule({
        providers: [
          AuthService,
          { provide: MODULE_OPTIONS_TOKEN, useValue: options },
          {
            provide: JwtService,
            useValue: { signAsync: jest.fn().mockResolvedValue("access-only") },
          },
          { provide: "ENCRYPTION_SERVICE", useValue: encryptionService },
        ],
      }).compile();
      const svc = module2.get<AuthService>(AuthService);

      const result = await svc.generateTokens(mockUser);
      expect(result.accessToken).toBe("access-only");
      expect(result.refreshToken).toBeNull();
    });

    it("should call saveRefreshToken when useRefreshTokens is true", async () => {
      const optionsWithRefresh = {
        ...mockAuthOptions,
        useRefreshTokens: true,
        userService,
        encryptionService,
      };
      const mod = await Test.createTestingModule({
        providers: [
          AuthService,
          { provide: MODULE_OPTIONS_TOKEN, useValue: optionsWithRefresh },
          {
            provide: JwtService,
            useValue: { signAsync: jest.fn().mockResolvedValue("token") },
          },
          { provide: "ENCRYPTION_SERVICE", useValue: encryptionService },
        ],
      }).compile();
      const svc = mod.get<AuthService>(AuthService);
      await svc.generateTokens(mockUser);
      expect(userService.saveRefreshToken).toHaveBeenCalledWith("user-1", "token");
    });
  });

  describe("refresh", () => {
    it("should return new tokens for valid refresh token", async () => {
      (userService.findOneByField as jest.Mock).mockResolvedValue(mockUser);
      const options = {
        ...mockAuthOptions,
        useRefreshTokens: true,
        refreshSecret: "refresh-secret",
        userService,
        encryptionService,
      };
      const module2 = await Test.createTestingModule({
        providers: [
          AuthService,
          { provide: MODULE_OPTIONS_TOKEN, useValue: options },
          {
            provide: JwtService,
            useValue: {
              signAsync: jest.fn().mockResolvedValue("new-token"),
              verifyAsync: jest.fn().mockResolvedValue({ sub: mockUser.id }),
            },
          },
          { provide: "ENCRYPTION_SERVICE", useValue: encryptionService },
        ],
      }).compile();
      const svc = module2.get<AuthService>(AuthService);

      const result = await svc.refresh("valid-refresh-token");
      expect(result).toHaveProperty("accessToken");
      expect(result).toHaveProperty("refreshToken");
    });

    it("should throw UnauthorizedException for invalid refresh token", async () => {
      (jwtService.verifyAsync as jest.Mock).mockRejectedValue(new Error("invalid"));

      await expect(service.refresh("invalid-token")).rejects.toThrow(UnauthorizedException);
    });
  });
});
