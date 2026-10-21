import { Test } from "@nestjs/testing";
import { JwtModule, JwtService } from "@nestjs/jwt";
import { HttpException, UnauthorizedException, BadRequestException } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { MODULE_OPTIONS_TOKEN } from "./auth.module-definition";
import type { AuthOptions } from "../../interfaces/auth.options";
import type { IAuthUserService } from "../../interfaces/user-service.interface";
import type { IEncryptionService } from "../../interfaces/encryption-service.interface";
import { InMemoryLoginRateLimitStore } from "../../security/login-rate-limit.store";
import { hashToken } from "../../security/token.util";

const flush = () => new Promise((resolve) => setImmediate(resolve));

describe("AuthService (security features, real JWT)", () => {
  const user = { id: "u-1", email: "user@example.com", password: "hash", roles: ["user"], tenantId: "t-1" };

  let userService: jest.Mocked<Required<IAuthUserService>>;
  let encryptionService: jest.Mocked<Required<IEncryptionService>>;

  const baseOptions = (): AuthOptions => ({
    jwtSecret: "access-secret-access-secret-access",
    refreshSecret: "refresh-secret-refresh-secret-refresh",
    expiresIn: "15m",
    refreshExpiresIn: "7d",
    jwtIssuer: "iss",
    jwtAudience: "aud",
    identifierField: "email",
    passwordField: "password",
    useRefreshTokens: true,
    userService,
    encryptionService,
  });

  async function createService(overrides: Partial<AuthOptions> = {}) {
    const options = { ...baseOptions(), ...overrides };
    const mod = await Test.createTestingModule({
      imports: [JwtModule.register({})],
      providers: [
        AuthService,
        { provide: MODULE_OPTIONS_TOKEN, useValue: options },
        { provide: "ENCRYPTION_SERVICE", useValue: options.encryptionService },
      ],
    }).compile();
    return { service: mod.get(AuthService), jwt: mod.get(JwtService), options };
  }

  beforeEach(() => {
    let storedRefresh: string | null = null;
    userService = {
      findOneByField: jest.fn(async (field: string, value: unknown) =>
        (field === "email" && value === user.email) || (field === "id" && value === user.id) ? { ...user } : null
      ),
      saveRefreshToken: jest.fn(async (_id: string, token: string) => {
        storedRefresh = token;
      }),
      isRefreshTokenValid: jest.fn(async (_id: string, token: string) => storedRefresh === token),
      revokeAllTokens: jest.fn(async () => {
        storedRefresh = null;
      }),
      getLockoutUntil: jest.fn().mockResolvedValue(null),
      recordFailedLogin: jest.fn().mockResolvedValue(undefined),
      clearFailedLogin: jest.fn().mockResolvedValue(undefined),
      updatePasswordHash: jest.fn().mockResolvedValue(undefined),
    } as unknown as jest.Mocked<Required<IAuthUserService>>;
    encryptionService = {
      compare: jest.fn(async (pwd: string) => pwd === "correct"),
      hash: jest.fn().mockResolvedValue("new-hash"),
      needsRehash: jest.fn().mockReturnValue(false),
      compareDummy: jest.fn().mockResolvedValue(false),
    } as unknown as jest.Mocked<Required<IEncryptionService>>;
  });

  describe("tokens", () => {
    it("returns token metadata and typed claims", async () => {
      const { service, jwt } = await createService();
      const tokens = await service.login({ email: user.email, password: "correct" });

      expect(tokens.tokenType).toBe("Bearer");
      expect(tokens.expiresIn).toBe(900);
      expect(tokens.refreshExpiresIn).toBe(7 * 86400);
      expect(jwt.decode(tokens.accessToken)).toMatchObject({ sub: "u-1", type: "access", roles: ["user"] });
      expect(jwt.decode(tokens.refreshToken!)).toMatchObject({ sub: "u-1", type: "refresh" });
      expect(jwt.decode(tokens.refreshToken!).jti).toEqual(expect.any(String));
    });

    it("issues a unique refresh token on every call", async () => {
      const { service } = await createService();
      const a = await service.generateTokens(user);
      const b = await service.generateTokens(user);
      expect(a.refreshToken).not.toBe(b.refreshToken);
    });

    it("adds custom claims via buildPayload without overriding reserved claims", async () => {
      const { service, jwt } = await createService({
        buildPayload: (u) => ({ tenantId: u.tenantId, sub: "hijack", type: "refresh" }),
      });
      const { accessToken } = await service.generateTokens(user);
      expect(jwt.decode(accessToken)).toMatchObject({ sub: "u-1", type: "access", tenantId: "t-1" });
    });

    it("supports a custom idField", async () => {
      userService.findOneByField.mockResolvedValue({ uuid: "abc", email: user.email, password: "hash" });
      const { service, jwt } = await createService({ idField: "uuid" });
      const tokens = await service.login({ email: user.email, password: "correct" });
      expect(jwt.decode(tokens.accessToken).sub).toBe("abc");
      expect(userService.saveRefreshToken).toHaveBeenCalledWith("abc", tokens.refreshToken, expect.any(Object));
    });

    it("stores only the SHA-256 hash when hashRefreshTokens is enabled", async () => {
      const { service } = await createService({ hashRefreshTokens: true });
      const tokens = await service.login({ email: user.email, password: "correct" });
      expect(userService.saveRefreshToken).toHaveBeenCalledWith("u-1", hashToken(tokens.refreshToken!), expect.any(Object));
      await expect(service.refresh(tokens.refreshToken!)).resolves.toHaveProperty("accessToken");
    });
  });

  describe("refresh", () => {
    it("rotates tokens and detects reuse of an old refresh token", async () => {
      const onRefreshFailure = jest.fn();
      const { service } = await createService({ onRefreshFailure });
      const first = await service.login({ email: user.email, password: "correct" });
      const second = await service.refresh(first.refreshToken!);
      expect(second.refreshToken).not.toBe(first.refreshToken);

      await expect(service.refresh(first.refreshToken!)).rejects.toThrow("Refresh Token compromised.");
      expect(userService.revokeAllTokens).toHaveBeenCalledWith("u-1");
      await flush();
      expect(onRefreshFailure).toHaveBeenCalledWith("token_compromised", undefined);
    });

    it("rejects an access token used as refresh token, even with a shared secret", async () => {
      const onRefreshFailure = jest.fn();
      const { service } = await createService({ refreshSecret: undefined, onRefreshFailure });
      const { accessToken } = await service.login({ email: user.email, password: "correct" });
      await expect(service.refresh(accessToken)).rejects.toThrow(UnauthorizedException);
      await flush();
      expect(onRefreshFailure).toHaveBeenCalledWith("wrong_token_type", undefined);
    });

    it("rejects a signed refresh token without subject", async () => {
      const { service, jwt, options } = await createService();
      const token = await jwt.signAsync(
        { type: "refresh", jti: "x" },
        { secret: options.refreshSecret, issuer: "iss", audience: "aud", expiresIn: 60 }
      );
      await expect(service.refresh(token)).rejects.toThrow(UnauthorizedException);
      expect(userService.findOneByField).not.toHaveBeenCalled();
    });

    it("rejects refresh for inactive users", async () => {
      const { service } = await createService();
      const { refreshToken } = await service.login({ email: user.email, password: "correct" });
      const { service: blocked } = await createService({ isUserActive: () => false });
      await expect(blocked.refresh(refreshToken!)).rejects.toThrow(UnauthorizedException);
    });
  });

  describe("login hardening", () => {
    it("runs a dummy comparison when the user does not exist (timing attack)", async () => {
      const { service } = await createService();
      await expect(service.login({ email: "nobody@example.com", password: "x" })).rejects.toThrow(UnauthorizedException);
      expect(encryptionService.compareDummy).toHaveBeenCalledWith("x");
    });

    it("rejects non-string passwords and object identifiers", async () => {
      const { service } = await createService();
      await expect(service.login({ email: user.email, password: 123 })).rejects.toThrow(BadRequestException);
      await expect(service.login({ email: { $ne: null }, password: "x" })).rejects.toThrow(BadRequestException);
    });

    it("normalizes the identifier", async () => {
      const { service } = await createService({ normalizeIdentifier: (v) => v.trim().toLowerCase() });
      await expect(service.login({ email: "  USER@example.com ", password: "correct" })).resolves.toBeDefined();
    });

    it("returns 401 for inactive users", async () => {
      const onLoginFailure = jest.fn();
      const { service } = await createService({ isUserActive: (u) => u.email !== user.email, onLoginFailure });
      await expect(service.login({ email: user.email, password: "correct" })).rejects.toThrow("Invalid Credentials");
      await flush();
      expect(onLoginFailure).toHaveBeenCalledWith(user.email, "user_inactive", undefined);
    });

    it("forwards the lockout policy to recordFailedLogin", async () => {
      const { service } = await createService({ lockoutMaxAttempts: 5, lockoutDurationMinutes: 30 });
      await expect(service.login({ email: user.email, password: "wrong" })).rejects.toThrow(UnauthorizedException);
      expect(userService.recordFailedLogin).toHaveBeenCalledWith(user.email, { maxAttempts: 5, durationMinutes: 30 });
    });

    it("blocks locked accounts", async () => {
      userService.getLockoutUntil.mockResolvedValue(new Date(Date.now() + 60_000));
      const { service } = await createService({ lockoutMaxAttempts: 5 });
      await expect(service.login({ email: user.email, password: "correct" })).rejects.toThrow(UnauthorizedException);
      expect(encryptionService.compare).not.toHaveBeenCalled();
    });

    it("rate limits per IP + identifier and returns 429", async () => {
      const store = new InMemoryLoginRateLimitStore();
      const { service } = await createService({ rateLimitStore: store, rateLimitMaxAttempts: 2 });
      const ctx = { ip: "1.1.1.1" };
      await expect(service.login({ email: user.email, password: "wrong" }, ctx)).rejects.toThrow(UnauthorizedException);
      await expect(service.login({ email: user.email, password: "wrong" }, ctx)).rejects.toThrow(UnauthorizedException);
      await expect(service.login({ email: user.email, password: "wrong" }, ctx)).rejects.toThrow(HttpException);
      // Another IP is not affected.
      await expect(service.login({ email: user.email, password: "correct" }, { ip: "2.2.2.2" })).resolves.toBeDefined();
    });

    it("transparently rehashes outdated password hashes", async () => {
      encryptionService.needsRehash.mockReturnValue(true);
      const { service } = await createService();
      await service.login({ email: user.email, password: "correct" });
      await flush();
      expect(encryptionService.hash).toHaveBeenCalledWith("correct");
      expect(userService.updatePasswordHash).toHaveBeenCalledWith("u-1", "new-hash");
    });

    it("never breaks login when an audit hook throws synchronously", async () => {
      const { service } = await createService({
        onLoginSuccess: () => {
          throw new Error("hook failure");
        },
      });
      await expect(service.login({ email: user.email, password: "correct" })).resolves.toBeDefined();
    });

    it("passes the request context to audit hooks", async () => {
      const onLoginSuccess = jest.fn();
      const { service } = await createService({ onLoginSuccess });
      await service.login({ email: user.email, password: "correct" }, { ip: "1.2.3.4" });
      await flush();
      expect(onLoginSuccess).toHaveBeenCalledWith("u-1", user.email, { ip: "1.2.3.4" });
    });
  });

  describe("validateUser / logout / verifyAccessToken / decodeToken", () => {
    it("validateUser returns the user without issuing tokens", async () => {
      const { service } = await createService();
      await expect(service.validateUser({ email: user.email, password: "correct" })).resolves.toMatchObject({ id: "u-1" });
      expect(userService.saveRefreshToken).not.toHaveBeenCalled();
    });

    it("logout revokes refresh tokens and fires onLogout", async () => {
      const onLogout = jest.fn();
      const { service } = await createService({ onLogout });
      const { refreshToken } = await service.login({ email: user.email, password: "correct" });
      await service.logout("u-1");
      await flush();
      expect(onLogout).toHaveBeenCalledWith("u-1", undefined);
      await expect(service.refresh(refreshToken!)).rejects.toThrow(UnauthorizedException);
    });

    it("verifyAccessToken accepts access tokens and rejects refresh tokens", async () => {
      const { service } = await createService({ refreshSecret: undefined });
      const tokens = await service.login({ email: user.email, password: "correct" });
      await expect(service.verifyAccessToken(tokens.accessToken)).resolves.toMatchObject({ sub: "u-1" });
      await expect(service.verifyAccessToken(tokens.refreshToken!)).rejects.toThrow(UnauthorizedException);
      await expect(service.verifyAccessToken("garbage")).rejects.toThrow(UnauthorizedException);
    });

    it("rejects tokens signed with a different algorithm", async () => {
      const { service, jwt } = await createService();
      const forged = await jwt.signAsync(
        { sub: "u-1", type: "access" },
        { secret: baseOptions().jwtSecret, algorithm: "HS512", issuer: "iss", audience: "aud" }
      );
      await expect(service.verifyAccessToken(forged)).rejects.toThrow(UnauthorizedException);
    });

    it("decodeToken returns null for invalid input", async () => {
      const { service } = await createService();
      expect(service.decodeToken("not-a-jwt")).toBeNull();
    });
  });
});
