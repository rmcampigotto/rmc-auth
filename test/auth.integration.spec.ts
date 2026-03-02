import { Test, TestingModule } from "@nestjs/testing";
import { AuthService } from "../src/modules/auth/auth.service";
import { EncryptionModule, EncryptionService } from "../src";
import { JwtModule } from "@nestjs/jwt";
import { MODULE_OPTIONS_TOKEN } from "../src/modules/auth/auth.module-definition";
import type { IAuthUserService } from "../src/interfaces/user-service.interface";

/**
 * Integration test: real EncryptionService (hash/compare) + AuthService.
 * Exercises the full login flow with real bcrypt hashing.
 */
describe("Auth + Encryption integration", () => {
  const testUser = {
    id: "int-user-1",
    email: "integration@example.com",
    roles: ["user"] as string[],
  };

  let authService: AuthService;
  let encryptionService: EncryptionService;
  let userService: IAuthUserService;
  let storedHash: string;

  beforeAll(async () => {
    userService = {
      findOneByField: jest.fn(),
      saveRefreshToken: jest.fn().mockResolvedValue(undefined),
      isRefreshTokenValid: jest.fn().mockResolvedValue(true),
      revokeAllTokens: jest.fn().mockResolvedValue(undefined),
    };

    storedHash = await (async () => {
      const encMod = await Test.createTestingModule({
        imports: [
          EncryptionModule.register({
            saltRounds: 10,
            algorithm: "bcrypt",
            strongPasswordValidation: true,
          }),
        ],
      }).compile();
      const enc = encMod.get<EncryptionService>(EncryptionService);
      return await enc.hash("Password123!");
    })();
  });

  beforeEach(async () => {
    (userService.findOneByField as jest.Mock).mockImplementation(async (field: string, value: string) => {
      if (field === "email" && value === "integration@example.com") {
        return { ...testUser, password: storedHash };
      }
      if (field === "id" && value === testUser.id) {
        return { ...testUser, password: storedHash };
      }
      return null;
    });

    const app = await Test.createTestingModule({
      imports: [
        EncryptionModule.register({
          saltRounds: 10,
          algorithm: "bcrypt",
          strongPasswordValidation: true,
        }),
        JwtModule.register({
          secret: "integration-test-secret",
          signOptions: { expiresIn: "15m", issuer: "rmc-auth-test", audience: "rmc-auth-test" },
        }),
      ],
      providers: [
        AuthService,
        {
          provide: MODULE_OPTIONS_TOKEN,
          useFactory: (enc: EncryptionService) => ({
            jwtSecret: "integration-test-secret",
            expiresIn: "15m",
            jwtIssuer: "rmc-auth-test",
            jwtAudience: "rmc-auth-test",
            identifierField: "email",
            passwordField: "password",
            rolesField: "roles",
            userService,
            encryptionService: enc,
            useRefreshTokens: false,
          }),
          inject: [EncryptionService],
        },
        {
          provide: "ENCRYPTION_SERVICE",
          useFactory: (enc: EncryptionService) => enc,
          inject: [EncryptionService],
        },
      ],
    }).compile();

    authService = app.get<AuthService>(AuthService);
    encryptionService = app.get<EncryptionService>(EncryptionService);
  });

  it("should resolve AuthService and EncryptionService", () => {
    expect(authService).toBeDefined();
    expect(encryptionService).toBeDefined();
  });

  it("should login and return access token with real password hash", async () => {
    const result = await authService.login({
      email: "integration@example.com",
      password: "Password123!",
    });

    expect(result).toHaveProperty("accessToken");
    expect(typeof result.accessToken).toBe("string");
    expect(result.accessToken.length).toBeGreaterThan(0);
  });

  it("should reject invalid credentials", async () => {
    await expect(
      authService.login({ email: "integration@example.com", password: "WrongPassword" })
    ).rejects.toThrow();
  });
});
