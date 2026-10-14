import { Test } from "@nestjs/testing";
import { JwtModule, JwtService } from "@nestjs/jwt";
import { HttpException, UnauthorizedException } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { MODULE_OPTIONS_TOKEN } from "./auth.module-definition";
import type { AuthOptions } from "../../interfaces/auth.options";
import type { IAuthUserService } from "../../interfaces/user-service.interface";
import type { IEncryptionService } from "../../interfaces/encryption-service.interface";
import { TwoFactorRequiredException } from "../../exceptions/two-factor-required.exception";
import { generateTotp } from "../../security/totp.util";
import { InMemoryLoginRateLimitStore } from "../../security/login-rate-limit.store";

const flush = () => new Promise((resolve) => setImmediate(resolve));

describe("AuthService (two-factor and sessions)", () => {
  let user: Record<string, unknown>;
  let secret: string | null;
  let recoveryHashes: Set<string>;
  let lastStep: number;
  let userService: jest.Mocked<Required<IAuthUserService>>;
  const encryptionService: IEncryptionService = {
    hash: async (p) => `hash:${p}`,
    compare: async (p, h) => h === `hash:${p}`,
  };

  async function createService(overrides: Partial<AuthOptions> = {}) {
    const options: AuthOptions = {
      jwtSecret: "access-secret-access-secret-access",
      refreshSecret: "refresh-secret-refresh-secret-refresh",
      expiresIn: "15m",
      identifierField: "email",
      passwordField: "password",
      useRefreshTokens: true,
      twoFactor: { issuer: "Test" },
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

  const credentials = { email: "user@example.com", password: "Password1" };

  beforeEach(async () => {
    user = { id: "u-1", email: "user@example.com", password: "hash:Password1" };
    secret = null;
    recoveryHashes = new Set();
    lastStep = -1;
    userService = {
      findOneByField: jest.fn(async (field: string, value: unknown) => (user[field] === value ? { ...user } : null)),
      saveRefreshToken: jest.fn().mockResolvedValue(undefined),
      isRefreshTokenValid: jest.fn().mockResolvedValue(true),
      revokeAllTokens: jest.fn().mockResolvedValue(undefined),
      revokeSession: jest.fn().mockResolvedValue(undefined),
      getTwoFactorSecret: jest.fn(async () => secret),
      consumeTotpStep: jest.fn(async (_id: string, step: number) => {
        if (step <= lastStep) return false;
        lastStep = step;
        return true;
      }),
      consumeRecoveryCode: jest.fn(async (_id: string, hash: string) => recoveryHashes.delete(hash)),
    } as unknown as jest.Mocked<Required<IAuthUserService>>;
  });

  async function enroll(service: AuthService) {
    const setup = await service.setupTwoFactor("user@example.com");
    expect(service.confirmTwoFactorSetup(setup.secret, generateTotp(setup.secret))).toBe(true);
    secret = setup.secret;
    recoveryHashes = new Set(setup.recoveryCodeHashes);
    return setup;
  }

  it("setupTwoFactor returns a secret, otpauth URL and recovery codes", async () => {
    const { service } = await createService();
    const setup = await service.setupTwoFactor("user@example.com");
    expect(setup.secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(setup.otpauthUrl).toContain("otpauth://totp/Test:user%40example.com");
    expect(setup.recoveryCodes).toHaveLength(10);
    expect(setup.recoveryCodeHashes).toHaveLength(10);
  });

  it("login works normally for users without 2FA", async () => {
    const { service } = await createService();
    await expect(service.authenticate(credentials)).resolves.toMatchObject({ status: "success" });
  });

  it("requires a second step for users with 2FA and issues tokens after a valid code", async () => {
    const onLoginSuccess = jest.fn();
    const { service } = await createService({ onLoginSuccess });
    await enroll(service);

    const result = await service.authenticate(credentials);
    expect(result).toMatchObject({ status: "two_factor_required", expiresIn: 300 });
    await flush();
    expect(onLoginSuccess).not.toHaveBeenCalled();

    const error = await service.login(credentials).catch((e) => e);
    expect(error).toBeInstanceOf(TwoFactorRequiredException);
    expect(error.getStatus()).toBe(401);
    expect(error.getResponse()).toMatchObject({ mfaRequired: true, mfaToken: expect.any(String) });

    const mfaToken = (result as { mfaToken: string }).mfaToken;
    const tokens = await service.verifyTwoFactorLogin(mfaToken, generateTotp(secret!));
    expect(tokens.accessToken).toEqual(expect.any(String));
    await flush();
    expect(onLoginSuccess).toHaveBeenCalledWith("u-1", "user@example.com", undefined);
  });

  it("rejects wrong codes, replayed codes and foreign tokens", async () => {
    const onLoginFailure = jest.fn();
    const { service } = await createService({ onLoginFailure });
    await enroll(service);
    const { mfaToken } = (await service.authenticate(credentials)) as { mfaToken: string };

    await expect(service.verifyTwoFactorLogin(mfaToken, "000000")).rejects.toThrow(UnauthorizedException);
    await flush();
    expect(onLoginFailure).toHaveBeenCalledWith("user@example.com", "invalid_two_factor_code", undefined);

    const code = generateTotp(secret!);
    await service.verifyTwoFactorLogin(mfaToken, code);
    await expect(service.verifyTwoFactorLogin(mfaToken, code)).rejects.toThrow(UnauthorizedException); // replay

    const { accessToken } = await service.generateTokens(user);
    await expect(service.verifyTwoFactorLogin(accessToken, code)).rejects.toThrow(UnauthorizedException);
  });

  it("accepts each recovery code once", async () => {
    const { service } = await createService();
    const setup = await enroll(service);
    const { mfaToken } = (await service.authenticate(credentials)) as { mfaToken: string };
    const code = setup.recoveryCodes[0].toLowerCase();
    await expect(service.verifyTwoFactorLogin(mfaToken, code)).resolves.toHaveProperty("accessToken");
    await expect(service.verifyTwoFactorLogin(mfaToken, code)).rejects.toThrow(UnauthorizedException);
  });

  it("rate limits second-step attempts", async () => {
    const { service } = await createService({ rateLimitStore: new InMemoryLoginRateLimitStore(), rateLimitMaxAttempts: 2 });
    await enroll(service);
    const { mfaToken } = (await service.authenticate(credentials)) as { mfaToken: string };
    await expect(service.verifyTwoFactorLogin(mfaToken, "000000")).rejects.toThrow(UnauthorizedException);
    await expect(service.verifyTwoFactorLogin(mfaToken, "000000")).rejects.toThrow(UnauthorizedException);
    await expect(service.verifyTwoFactorLogin(mfaToken, generateTotp(secret!))).rejects.toThrow(HttpException);
  });

  describe("sessions", () => {
    it("keeps the session id across refresh rotations and passes session info", async () => {
      const { service, jwt } = await createService({ twoFactor: undefined });
      const first = await service.login(credentials, { ip: "1.1.1.1" });
      expect(first.sessionId).toEqual(expect.any(String));
      expect(jwt.decode(first.accessToken).sid).toBe(first.sessionId);
      expect(userService.saveRefreshToken).toHaveBeenCalledWith(
        "u-1",
        first.refreshToken,
        expect.objectContaining({ sessionId: first.sessionId, jti: expect.any(String), expiresAt: expect.any(Date), context: { ip: "1.1.1.1" } })
      );

      const second = await service.refresh(first.refreshToken!);
      expect(second.sessionId).toBe(first.sessionId);
      expect(userService.isRefreshTokenValid).toHaveBeenCalledWith(
        "u-1",
        first.refreshToken,
        expect.objectContaining({ sessionId: first.sessionId })
      );

      const other = await service.login(credentials);
      expect(other.sessionId).not.toBe(first.sessionId);
    });

    it("revokeSession revokes a single session", async () => {
      const { service } = await createService({ twoFactor: undefined });
      await service.revokeSession("u-1", "session-1");
      expect(userService.revokeSession).toHaveBeenCalledWith("u-1", "session-1");
    });
  });

  it("rate limits password reset requests", async () => {
    const { service } = await createService({ rateLimitStore: new InMemoryLoginRateLimitStore(), rateLimitMaxAttempts: 1 });
    await expect(service.createPasswordResetToken("user@example.com")).resolves.not.toBeNull();
    await expect(service.createPasswordResetToken("user@example.com")).rejects.toThrow(HttpException);
  });
});
