import { Test } from "@nestjs/testing";
import { JwtModule, JwtService } from "@nestjs/jwt";
import { BadRequestException, HttpException, UnauthorizedException } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { MODULE_OPTIONS_TOKEN } from "./auth.module-definition";
import type { AuthOptions } from "../../interfaces/auth.options";
import type { IAuthUserService } from "../../interfaces/user-service.interface";
import type { IEncryptionService } from "../../interfaces/encryption-service.interface";
import { InMemoryTokenBlacklistStore } from "../../security/token-blacklist.store";
import { InMemoryLoginRateLimitStore } from "../../security/login-rate-limit.store";

const flush = () => new Promise((resolve) => setImmediate(resolve));

describe("AuthService (accounts: permissions, revocation, passwords, action tokens)", () => {
  let user: Record<string, unknown>;
  let userService: jest.Mocked<Required<IAuthUserService>>;
  let encryptionService: IEncryptionService;

  async function createService(overrides: Partial<AuthOptions> = {}) {
    const options: AuthOptions = {
      jwtSecret: "access-secret-access-secret-access",
      refreshSecret: "refresh-secret-refresh-secret-refresh",
      expiresIn: "15m",
      identifierField: "email",
      passwordField: "password",
      useRefreshTokens: true,
      userService,
      encryptionService,
      ...overrides,
    };
    const mod = await Test.createTestingModule({
      imports: [JwtModule.register({})],
      providers: [
        AuthService,
        { provide: MODULE_OPTIONS_TOKEN, useValue: options },
        { provide: "ENCRYPTION_SERVICE", useValue: encryptionService },
      ],
    }).compile();
    return { service: mod.get(AuthService), jwt: mod.get(JwtService) };
  }

  beforeEach(() => {
    user = { id: "u-1", email: "user@example.com", password: "hash:Old-Password1", roles: ["user"], permissions: ["posts:*"] };
    userService = {
      findOneByField: jest.fn(async (field: string, value: unknown) => (user[field] === value ? { ...user } : null)),
      saveRefreshToken: jest.fn().mockResolvedValue(undefined),
      isRefreshTokenValid: jest.fn().mockResolvedValue(true),
      revokeAllTokens: jest.fn().mockResolvedValue(undefined),
      clearFailedLogin: jest.fn().mockResolvedValue(undefined),
      updatePasswordHash: jest.fn(async (_id: string, hash: string) => {
        user.password = hash;
      }),
    } as unknown as jest.Mocked<Required<IAuthUserService>>;
    encryptionService = {
      hash: jest.fn(async (p: string) => {
        if (p.length < 8) throw new BadRequestException("Insecure password");
        return `hash:${p}`;
      }),
      compare: jest.fn(async (p: string, h: string) => h === `hash:${p}`),
    };
  });

  describe("permissions", () => {
    it("adds permissions to the access token when permissionsField is set", async () => {
      const { service, jwt } = await createService({ permissionsField: "permissions" });
      const { accessToken } = await service.generateTokens(user);
      expect(jwt.decode(accessToken).permissions).toEqual(["posts:*"]);
    });

    it("omits permissions by default", async () => {
      const { service, jwt } = await createService();
      const { accessToken } = await service.generateTokens(user);
      expect(jwt.decode(accessToken).permissions).toBeUndefined();
    });
  });

  describe("access token revocation", () => {
    it("revokeAccessToken blacklists the token until it expires", async () => {
      const tokenBlacklist = new InMemoryTokenBlacklistStore();
      const { service } = await createService({ tokenBlacklist });
      const { accessToken } = await service.generateTokens(user);
      await expect(service.verifyAccessToken(accessToken)).resolves.toBeDefined();
      await expect(service.revokeAccessToken(accessToken)).resolves.toBe(true);
      await expect(service.verifyAccessToken(accessToken)).rejects.toThrow(UnauthorizedException);
    });

    it("logout revokes the given access token", async () => {
      const tokenBlacklist = new InMemoryTokenBlacklistStore();
      const { service } = await createService({ tokenBlacklist });
      const { accessToken } = await service.generateTokens(user);
      await service.logout("u-1", undefined, accessToken);
      expect(userService.revokeAllTokens).toHaveBeenCalledWith("u-1");
      await expect(service.verifyAccessToken(accessToken)).rejects.toThrow(UnauthorizedException);
    });

    it("logoutCurrentSession revokes only the session, or every session when the token has none", async () => {
      userService.revokeSession = jest.fn().mockResolvedValue(undefined);
      const { service } = await createService();
      await service.logoutCurrentSession({ id: "u-1", username: "x", sessionId: "s-1" });
      expect(userService.revokeSession).toHaveBeenCalledWith("u-1", "s-1");
      expect(userService.revokeAllTokens).not.toHaveBeenCalled();

      await service.logoutCurrentSession({ id: "u-1", username: "x" });
      expect(userService.revokeAllTokens).toHaveBeenCalledWith("u-1");
    });

    it("revokeAccessToken requires a blacklist", async () => {
      const { service } = await createService();
      const { accessToken } = await service.generateTokens(user);
      await expect(service.revokeAccessToken(accessToken)).rejects.toThrow("tokenBlacklist");
    });
  });

  describe("changePassword", () => {
    it("updates the hash and revokes sessions", async () => {
      const onPasswordChanged = jest.fn();
      const { service } = await createService({ onPasswordChanged });
      await service.changePassword("u-1", "Old-Password1", "New-Password1", { ip: "1.1.1.1" });
      expect(userService.updatePasswordHash).toHaveBeenCalledWith("u-1", "hash:New-Password1");
      expect(userService.revokeAllTokens).toHaveBeenCalledWith("u-1");
      await flush();
      expect(onPasswordChanged).toHaveBeenCalledWith("u-1", "change", { ip: "1.1.1.1" });
    });

    it("rejects a wrong current password", async () => {
      const { service } = await createService();
      await expect(service.changePassword("u-1", "wrong", "New-Password1")).rejects.toThrow(UnauthorizedException);
      expect(userService.updatePasswordHash).not.toHaveBeenCalled();
    });

    it("rejects reusing the same password and weak passwords", async () => {
      const { service } = await createService();
      await expect(service.changePassword("u-1", "Old-Password1", "Old-Password1")).rejects.toThrow(BadRequestException);
      await expect(service.changePassword("u-1", "Old-Password1", "short")).rejects.toThrow(BadRequestException);
    });

    it("rate limits attempts per user", async () => {
      const { service } = await createService({ rateLimitStore: new InMemoryLoginRateLimitStore(), rateLimitMaxAttempts: 2 });
      await expect(service.changePassword("u-1", "wrong", "New-Password1")).rejects.toThrow(UnauthorizedException);
      await expect(service.changePassword("u-1", "wrong", "New-Password1")).rejects.toThrow(UnauthorizedException);
      await expect(service.changePassword("u-1", "Old-Password1", "New-Password1")).rejects.toThrow(HttpException);
      expect(userService.updatePasswordHash).not.toHaveBeenCalled();
    });

    it("requires updatePasswordHash", async () => {
      delete (userService as Partial<IAuthUserService>).updatePasswordHash;
      const { service } = await createService();
      await expect(service.changePassword("u-1", "Old-Password1", "New-Password1")).rejects.toThrow("updatePasswordHash");
    });
  });

  describe("password reset", () => {
    it("creates a token and resets the password once", async () => {
      const onPasswordChanged = jest.fn();
      const { service } = await createService({ onPasswordChanged, passwordResetExpiresIn: "10m" });
      const reset = await service.createPasswordResetToken("user@example.com");
      expect(reset).toMatchObject({ userId: "u-1", expiresIn: 600 });
      expect(reset!.user).toMatchObject({ email: "user@example.com" });

      await service.resetPassword(reset!.token, "Brand-New-Password1");
      expect(user.password).toBe("hash:Brand-New-Password1");
      expect(userService.revokeAllTokens).toHaveBeenCalledWith("u-1");
      expect(userService.clearFailedLogin).toHaveBeenCalledWith("user@example.com");
      await flush();
      expect(onPasswordChanged).toHaveBeenCalledWith("u-1", "reset", undefined);

      // Single use: the password changed, so the same token is now invalid.
      await expect(service.resetPassword(reset!.token, "Another-Password1")).rejects.toThrow(UnauthorizedException);
    });

    it("returns null for unknown users", async () => {
      const { service } = await createService();
      await expect(service.createPasswordResetToken("nobody@example.com")).resolves.toBeNull();
      await expect(service.createPasswordResetToken("")).resolves.toBeNull();
    });

    it("rejects tampered or foreign tokens", async () => {
      const { service } = await createService();
      const { accessToken } = await service.generateTokens(user);
      await expect(service.resetPassword(accessToken, "New-Password1")).rejects.toThrow(UnauthorizedException);
      await expect(service.resetPassword("garbage", "New-Password1")).rejects.toThrow(UnauthorizedException);
    });
  });

  describe("action tokens", () => {
    it("round-trips data for the same purpose", async () => {
      const { service } = await createService();
      const token = await service.createActionToken("u-1", "email_verification", "1d", { email: "user@example.com" });
      await expect(service.verifyActionToken(token, "email_verification")).resolves.toMatchObject({
        sub: "u-1",
        purpose: "email_verification",
        email: "user@example.com",
      });
    });

    it("rejects another purpose and never works as an access or refresh token", async () => {
      const { service } = await createService({ refreshSecret: undefined });
      const token = await service.createActionToken("u-1", "email_verification");
      await expect(service.verifyActionToken(token, "password_reset")).rejects.toThrow(UnauthorizedException);
      await expect(service.verifyAccessToken(token)).rejects.toThrow(UnauthorizedException);
      await expect(service.refresh(token)).rejects.toThrow(UnauthorizedException);
    });

    it("cannot override reserved claims", async () => {
      const { service } = await createService();
      const token = await service.createActionToken("u-1", "invite", "1h", { sub: "admin", type: "access" });
      await expect(service.verifyActionToken(token, "invite")).resolves.toMatchObject({ sub: "u-1", type: "action" });
    });
  });
});
