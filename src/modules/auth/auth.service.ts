import { Inject, Injectable, UnauthorizedException, BadRequestException, HttpException, HttpStatus } from "@nestjs/common";
import { randomUUID } from "crypto";
import { MODULE_OPTIONS_TOKEN } from "./auth.module-definition";
import type { AuthOptions } from "../../interfaces/auth.options";
import { JwtService } from "@nestjs/jwt";
import type { IEncryptionService } from "../../interfaces/encryption-service.interface";
import type {
  AuthContext,
  AuthResult,
  AuthTokens,
  JwtPayload,
  PasswordResetToken,
  RefreshSessionInfo,
  RequestUser,
  TwoFactorSetup,
} from "../../types/auth.types";
import { TwoFactorRequiredException } from "../../exceptions/two-factor-required.exception";
import { buildOtpAuthUrl, generateTotpSecret, verifyTotp } from "../../security/totp.util";
import { generateRecoveryCodes, hashRecoveryCode, normalizeRecoveryCode } from "../../security/recovery-codes.util";
import { SECURITY_CONSTANTS } from "../../security/constants";
import { hashToken } from "../../security/token.util";
import { timingSafeEqual } from "../../security/timing-safe.util";
import { parseDurationToSeconds } from "../../utils/duration.util";
import { clearResponseCookie, CookieSettings, setResponseCookie } from "../../utils/cookie.util";

type UserRecord = Record<string, unknown>;
type SignOptions = Parameters<JwtService["signAsync"]>[1];
type VerifyOptions = Parameters<JwtService["verifyAsync"]>[1];

const RESERVED_CLAIMS = ["sub", "username", "roles", "permissions", "type", "purpose", "sid", "jti", "iat", "exp", "nbf", "iss", "aud"];
const MFA_PURPOSE = "mfa_login";
const PASSWORD_RESET_PURPOSE = "password_reset";

/** Removes undefined keys: jsonwebtoken rejects e.g. `issuer: undefined`. */
function compact<T extends Record<string, unknown>>(options: T): T {
  return Object.fromEntries(Object.entries(options).filter(([, v]) => v !== undefined)) as T;
}

function safeFire(fn: (() => unknown) | undefined): void {
  if (!fn) return;
  try {
    Promise.resolve(fn()).catch(() => {});
  } catch {
    // Audit hooks must never break the auth flow.
  }
}

@Injectable()
export class AuthService {
  constructor(
    @Inject(MODULE_OPTIONS_TOKEN) private authOptions: AuthOptions,
    private readonly jwtService: JwtService,
    @Inject("ENCRYPTION_SERVICE") private readonly encryptionService: IEncryptionService
  ) {}

  private get maxIdentifierLength(): number {
    return this.authOptions.maxIdentifierLength ?? SECURITY_CONSTANTS.MAX_IDENTIFIER_LENGTH;
  }

  private get maxPasswordLength(): number {
    return this.authOptions.maxPasswordLength ?? SECURITY_CONSTANTS.MAX_PASSWORD_LENGTH;
  }

  private get idField(): string {
    return this.authOptions.idField ?? "id";
  }

  private get algorithm(): string {
    return this.authOptions.jwtAlgorithm ?? "HS256";
  }

  private get refreshSecret(): string {
    return this.authOptions.refreshSecret ?? this.authOptions.jwtSecret;
  }

  private get actionSecret(): string {
    return this.authOptions.actionTokenSecret ?? this.authOptions.jwtSecret;
  }

  private get refreshExpiresIn(): string | number {
    return this.authOptions.refreshExpiresIn ?? "7d";
  }

  private getUserId(user: UserRecord): string {
    return String(user[this.idField] ?? "");
  }

  private storedRefreshToken(token: string): string {
    return this.authOptions.hashRefreshTokens ? hashToken(token) : token;
  }

  private async isActive(user: UserRecord): Promise<boolean> {
    if (!this.authOptions.isUserActive) return true;
    try {
      return (await this.authOptions.isUserActive(user)) === true;
    } catch {
      return false;
    }
  }

  private validateLoginInput(credentials: Record<string, unknown>): { identifier: string; password: string } {
    if (!credentials || typeof credentials !== "object") {
      throw new BadRequestException("Invalid request");
    }
    const identifier = credentials[this.authOptions.identifierField];
    const password = credentials[this.authOptions.passwordField];
    if (identifier == null || password == null) {
      throw new BadRequestException("Invalid request");
    }
    if (typeof identifier === "object" || typeof password !== "string") {
      throw new BadRequestException("Invalid request");
    }
    let idStr = String(identifier);
    if (idStr.length > this.maxIdentifierLength || password.length > this.maxPasswordLength) {
      throw new BadRequestException("Invalid request");
    }
    if (this.authOptions.normalizeIdentifier) {
      idStr = this.authOptions.normalizeIdentifier(idStr);
    }
    if (!idStr.trim() || !password) throw new BadRequestException("Invalid request");
    return { identifier: idStr, password };
  }

  private passwordFingerprint(storedHash: unknown): string {
    return hashToken(typeof storedHash === "string" ? storedHash : "").slice(0, 32);
  }

  private async findUserById(userId: string): Promise<UserRecord | null> {
    return (await this.authOptions.userService.findOneByField(this.idField, userId)) as UserRecord | null;
  }

  private async storeNewPassword(user: UserRecord, newPassword: string): Promise<void> {
    const us = this.authOptions.userService;
    if (!us.updatePasswordHash) {
      throw new Error("userService must implement updatePasswordHash to change or reset passwords");
    }
    if (typeof newPassword !== "string" || !newPassword || newPassword.length > this.maxPasswordLength) {
      throw new BadRequestException("Invalid request");
    }
    const userId = this.getUserId(user);
    await us.updatePasswordHash(userId, await this.encryptionService.hash(newPassword));
    if (us.revokeAllTokens) await us.revokeAllTokens(userId);
  }

  private async buildPayload(user: UserRecord): Promise<Record<string, unknown> & { sub: string; username: string; roles: string[] }> {
    const rolesField = this.authOptions.rolesField ?? "roles";
    const rawRoles = user[rolesField];
    const roles = Array.isArray(rawRoles) ? rawRoles.map(String) : [];
    const custom: Record<string, unknown> = {};
    if (this.authOptions.buildPayload) {
      const extra = await this.authOptions.buildPayload(user);
      for (const [key, value] of Object.entries(extra ?? {})) {
        if (!RESERVED_CLAIMS.includes(key)) custom[key] = value;
      }
    }
    if (this.authOptions.permissionsField) {
      const rawPermissions = user[this.authOptions.permissionsField];
      custom.permissions = Array.isArray(rawPermissions) ? rawPermissions.map(String) : [];
    }
    return {
      ...custom,
      sub: this.getUserId(user),
      username: String(user[this.authOptions.identifierField] ?? ""),
      roles,
    };
  }

  /**
   * Signs an access token (and a refresh token when enabled) for the given user record.
   * Use it for custom flows (e.g. after sign-up, OAuth or magic link).
   * @param options.sessionId - Keeps an existing session id (used internally on refresh). A new one is created otherwise.
   * @param options.context - Request context forwarded to `saveRefreshToken`.
   */
  async generateTokens(user: UserRecord, options: { sessionId?: string; context?: AuthContext } = {}): Promise<AuthTokens> {
    const payload = await this.buildPayload(user);
    const sessionId = this.authOptions.useRefreshTokens ? options.sessionId ?? randomUUID() : undefined;
    const accessToken = await this.jwtService.signAsync(compact({ ...payload, type: "access", sid: sessionId, jti: randomUUID() }), compact({
      secret: this.authOptions.jwtSecret,
      expiresIn: this.authOptions.expiresIn as string | number,
      issuer: this.authOptions.jwtIssuer,
      audience: this.authOptions.jwtAudience,
      algorithm: this.algorithm,
    }) as SignOptions);

    const tokens: AuthTokens = {
      accessToken,
      refreshToken: null,
      tokenType: "Bearer",
      expiresIn: parseDurationToSeconds(this.authOptions.expiresIn),
    };

    if (this.authOptions.useRefreshTokens) {
      if (!this.authOptions.userService.saveRefreshToken) {
        throw new Error("userService must implement saveRefreshToken to use Refresh Tokens");
      }
      const jti = randomUUID();
      const refreshToken = await this.jwtService.signAsync(
        { sub: payload.sub, username: payload.username, roles: payload.roles, type: "refresh", sid: sessionId, jti },
        compact({
          secret: this.refreshSecret,
          expiresIn: this.refreshExpiresIn,
          issuer: this.authOptions.refreshIssuer ?? this.authOptions.jwtIssuer,
          audience: this.authOptions.refreshAudience ?? this.authOptions.jwtAudience,
          algorithm: this.algorithm,
        }) as SignOptions
      );
      const refreshSeconds = parseDurationToSeconds(this.refreshExpiresIn);
      const session: RefreshSessionInfo = {
        sessionId: sessionId!,
        jti,
        expiresAt: new Date(Date.now() + refreshSeconds * 1000),
        context: options.context,
      };
      await this.authOptions.userService.saveRefreshToken(payload.sub, this.storedRefreshToken(refreshToken), session);
      tokens.refreshToken = refreshToken;
      tokens.refreshExpiresIn = refreshSeconds;
      tokens.sessionId = sessionId;
    }

    return tokens;
  }

  /**
   * Exchanges a valid refresh token for a new token pair (rotation).
   * If the token was already used/revoked (`isRefreshTokenValid` returns false), every session of the user
   * is revoked (`revokeAllTokens`) because this indicates token theft.
   */
  async refresh(rt: string, context?: AuthContext): Promise<AuthTokens> {
    const fail = (reason: Parameters<NonNullable<AuthOptions["onRefreshFailure"]>>[0], message = "Invalid Refresh Token") => {
      safeFire(() => this.authOptions.onRefreshFailure?.(reason, context));
      return new UnauthorizedException(message);
    };

    if (typeof rt !== "string" || !rt.trim() || rt.length > SECURITY_CONSTANTS.MAX_REFRESH_TOKEN_LENGTH) {
      throw fail("invalid_input");
    }

    let payload: JwtPayload;
    try {
      payload = await this.jwtService.verifyAsync<JwtPayload>(rt, compact({
        secret: this.refreshSecret,
        issuer: this.authOptions.refreshIssuer ?? this.authOptions.jwtIssuer,
        audience: this.authOptions.refreshAudience ?? this.authOptions.jwtAudience,
        algorithms: [this.algorithm],
        clockTolerance: this.authOptions.clockToleranceSeconds,
      }) as VerifyOptions);
    } catch {
      throw fail("verification_failed");
    }

    if (payload.type !== "refresh") throw fail("wrong_token_type");
    if (typeof payload.sub !== "string" || !payload.sub) throw fail("verification_failed");

    const user = (await this.authOptions.userService.findOneByField(this.idField, payload.sub)) as UserRecord | null;
    if (!user) throw fail("user_not_found");
    if (!(await this.isActive(user))) throw fail("user_inactive");

    const userId = this.getUserId(user);
    const sessionId = typeof payload.sid === "string" ? payload.sid : randomUUID();
    if (this.authOptions.userService.isRefreshTokenValid) {
      const session: RefreshSessionInfo = {
        sessionId,
        jti: String(payload.jti ?? ""),
        expiresAt: new Date((payload.exp ?? 0) * 1000),
        context,
      };
      const isValid = await this.authOptions.userService.isRefreshTokenValid(userId, this.storedRefreshToken(rt), session);
      if (!isValid) {
        if (this.authOptions.userService.revokeAllTokens) {
          await this.authOptions.userService.revokeAllTokens(userId);
        }
        throw fail("token_compromised", "Refresh Token compromised.");
      }
    }

    safeFire(() => this.authOptions.onRefreshSuccess?.(userId, context));
    return this.generateTokens(user, { sessionId, context });
  }

  /**
   * Validates credentials and returns the user record, without issuing tokens.
   * Applies input validation, rate limiting, lockout, timing-attack protection and audit hooks.
   * @throws BadRequestException if input is invalid (length/type).
   * @throws HttpException (429) if rate limit exceeded.
   * @throws UnauthorizedException if credentials invalid, account locked or user inactive.
   */
  async validateUser(credentials: Record<string, unknown>, context?: AuthContext): Promise<UserRecord> {
    const { user, identifier } = await this.checkCredentials(credentials, context);
    safeFire(() => this.authOptions.onLoginSuccess?.(this.getUserId(user), identifier, context));
    return user;
  }

  private async checkCredentials(
    credentials: Record<string, unknown>,
    context?: AuthContext
  ): Promise<{ user: UserRecord; identifier: string }> {
    let input: { identifier: string; password: string };
    try {
      input = this.validateLoginInput(credentials);
    } catch (e) {
      safeFire(() => this.authOptions.onLoginFailure?.("", "invalid_input", context));
      throw e;
    }
    const { identifier, password } = input;

    const rateLimitKey = context?.ip ? `login:${context.ip}:${identifier}` : `login:${identifier}`;
    const store = this.authOptions.rateLimitStore;
    const maxAttempts = this.authOptions.rateLimitMaxAttempts ?? 10;
    const windowMs = this.authOptions.rateLimitWindowMs ?? 15 * 60 * 1000;

    if (store) {
      const attempts = await store.increment(rateLimitKey, windowMs);
      if (attempts > maxAttempts) {
        safeFire(() => this.authOptions.onLoginFailure?.(identifier, "rate_limit_exceeded", context));
        throw new HttpException("Too many attempts. Try again later.", HttpStatus.TOO_MANY_REQUESTS);
      }
    }

    const us = this.authOptions.userService;
    if (us.getLockoutUntil && this.authOptions.lockoutMaxAttempts != null) {
      const lockUntil = await us.getLockoutUntil(identifier);
      if (lockUntil && lockUntil > new Date()) {
        safeFire(() => this.authOptions.onLoginFailure?.(identifier, "account_locked", context));
        throw new UnauthorizedException("Invalid Credentials");
      }
    }

    const lockoutPolicy =
      this.authOptions.lockoutMaxAttempts != null
        ? {
            maxAttempts: this.authOptions.lockoutMaxAttempts,
            durationMinutes: this.authOptions.lockoutDurationMinutes ?? 15,
          }
        : undefined;

    const user = (await us.findOneByField(this.authOptions.identifierField, identifier)) as UserRecord | null;

    if (!user) {
      // Spend the same time as a real comparison so response time does not reveal valid identifiers.
      if (this.encryptionService.compareDummy) await this.encryptionService.compareDummy(password);
      if (us.recordFailedLogin) await us.recordFailedLogin(identifier, lockoutPolicy);
      safeFire(() => this.authOptions.onLoginFailure?.(identifier, "user_not_found", context));
      throw new UnauthorizedException("Invalid Credentials");
    }

    const storedHash = user[this.authOptions.passwordField];
    const isPasswordValid = await this.encryptionService.compare(
      password,
      typeof storedHash === "string" ? storedHash : ""
    );

    if (!isPasswordValid) {
      if (us.recordFailedLogin) await us.recordFailedLogin(identifier, lockoutPolicy);
      safeFire(() => this.authOptions.onLoginFailure?.(identifier, "invalid_password", context));
      throw new UnauthorizedException("Invalid Credentials");
    }

    if (!(await this.isActive(user))) {
      safeFire(() => this.authOptions.onLoginFailure?.(identifier, "user_inactive", context));
      throw new UnauthorizedException("Invalid Credentials");
    }

    if (us.clearFailedLogin) await us.clearFailedLogin(identifier);
    if (store) await store.reset(rateLimitKey);

    const userId = this.getUserId(user);
    if (
      us.updatePasswordHash &&
      typeof storedHash === "string" &&
      this.encryptionService.needsRehash?.(storedHash)
    ) {
      safeFire(async () => us.updatePasswordHash!(userId, await this.encryptionService.hash(password)));
    }

    return { user, identifier };
  }

  /**
   * Performs full user authentication with input validation, optional lockout, rate limiting, and audit hooks.
   * @param context - Optional request metadata (ip, userAgent). When `ip` is given, rate limiting is per IP + identifier.
   * @throws BadRequestException if input is invalid (length/type).
   * @throws HttpException (429) if rate limit exceeded.
   * @throws UnauthorizedException if credentials invalid or account locked.
   */
  async login(credentials: Record<string, unknown>, context?: AuthContext): Promise<AuthTokens> {
    const result = await this.authenticate(credentials, context);
    if (result.status === "two_factor_required") {
      throw new TwoFactorRequiredException(result.mfaToken, result.expiresIn);
    }
    return result.tokens;
  }

  /**
   * Same as `login()`, but returns a result object instead of throwing when two-factor authentication is required.
   * @returns `{ status: 'success', tokens }` or `{ status: 'two_factor_required', mfaToken, expiresIn }`.
   */
  async authenticate(credentials: Record<string, unknown>, context?: AuthContext): Promise<AuthResult> {
    const { user, identifier } = await this.checkCredentials(credentials, context);
    const userId = this.getUserId(user);

    if (this.authOptions.twoFactor && this.authOptions.userService.getTwoFactorSecret) {
      const secret = await this.authOptions.userService.getTwoFactorSecret(userId);
      if (secret) {
        const expiresIn = this.authOptions.twoFactor.mfaTokenExpiresIn ?? "5m";
        const mfaToken = await this.createActionToken(userId, MFA_PURPOSE, expiresIn, { identifier });
        return { status: "two_factor_required", mfaToken, expiresIn: parseDurationToSeconds(expiresIn) };
      }
    }

    safeFire(() => this.authOptions.onLoginSuccess?.(userId, identifier, context));
    return { status: "success", tokens: await this.generateTokens(user, { context }) };
  }

  /**
   * Second step of a two-factor login: exchanges the `mfaToken` and a TOTP (or recovery) code for tokens.
   * Attempts are rate limited per user when `rateLimitStore` is configured.
   * The mfaToken is single-use when `tokenBlacklist` is configured.
   * @throws UnauthorizedException if the mfaToken or the code is invalid.
   */
  async verifyTwoFactorLogin(mfaToken: string, code: string, context?: AuthContext): Promise<AuthTokens> {
    const payload = await this.verifyActionToken(mfaToken, MFA_PURPOSE);
    const blacklist = this.authOptions.tokenBlacklist;
    if (blacklist && payload.jti && (await blacklist.has(payload.jti))) {
      throw new UnauthorizedException("Invalid token");
    }
    const identifier = typeof payload.identifier === "string" ? payload.identifier : "";
    const store = this.authOptions.rateLimitStore;
    const rateKey = `mfa:${payload.sub}`;
    if (store) {
      const attempts = await store.increment(rateKey, this.authOptions.rateLimitWindowMs ?? 15 * 60 * 1000);
      if (attempts > (this.authOptions.rateLimitMaxAttempts ?? 10)) {
        safeFire(() => this.authOptions.onLoginFailure?.(identifier, "rate_limit_exceeded", context));
        throw new HttpException("Too many attempts. Try again later.", HttpStatus.TOO_MANY_REQUESTS);
      }
    }

    const user = await this.findUserById(payload.sub);
    if (!user || !(await this.isActive(user))) throw new UnauthorizedException("Invalid token");

    if (!(await this.verifyTwoFactorCode(payload.sub, code))) {
      safeFire(() => this.authOptions.onLoginFailure?.(identifier, "invalid_two_factor_code", context));
      throw new UnauthorizedException("Invalid two-factor code");
    }

    if (store) await store.reset(rateKey);
    if (blacklist && payload.jti) {
      const expiresAt = typeof payload.exp === "number" ? payload.exp * 1000 : Date.now() + 3600 * 1000;
      await blacklist.add(payload.jti, expiresAt);
    }
    safeFire(() => this.authOptions.onLoginSuccess?.(payload.sub, identifier, context));
    return this.generateTokens(user, { context });
  }

  /**
   * Checks a TOTP code (with replay protection when `consumeTotpStep` is implemented) or a recovery code
   * (when `consumeRecoveryCode` is implemented) for a user with two-factor enabled.
   * Use it to protect sensitive actions (e.g. disabling 2FA, changing e-mail).
   */
  async verifyTwoFactorCode(userId: string, code: string): Promise<boolean> {
    const us = this.authOptions.userService;
    if (typeof code !== "string" || !code || code.length > 64 || !us.getTwoFactorSecret) return false;
    const secret = await us.getTwoFactorSecret(userId);
    if (!secret) return false;

    const step = verifyTotp(secret, code, { window: this.authOptions.twoFactor?.window ?? 1 });
    if (step !== null) {
      return us.consumeTotpStep ? us.consumeTotpStep(userId, step) : true;
    }
    if (us.consumeRecoveryCode && normalizeRecoveryCode(code).length >= 8) {
      return us.consumeRecoveryCode(userId, hashRecoveryCode(code));
    }
    return false;
  }

  /**
   * Starts two-factor enrollment: generates a TOTP secret, the `otpauth://` URL (render it as a QR code)
   * and recovery codes. Nothing is stored: confirm with `confirmTwoFactorSetup()` and then persist
   * the secret (ideally with `encryptSecret()`) and `recoveryCodeHashes`.
   */
  async setupTwoFactor(account: string): Promise<TwoFactorSetup> {
    if (typeof account !== "string" || !account) throw new BadRequestException("Invalid request");
    const secret = generateTotpSecret();
    const { codes, hashes } = generateRecoveryCodes();
    return {
      secret,
      otpauthUrl: buildOtpAuthUrl({ secret, account, issuer: this.authOptions.twoFactor?.issuer }),
      recoveryCodes: codes,
      recoveryCodeHashes: hashes,
    };
  }

  /** Verifies the first code typed by the user during enrollment, proving the authenticator app is set up. */
  confirmTwoFactorSetup(secret: string, code: string): boolean {
    return verifyTotp(secret, code, { window: this.authOptions.twoFactor?.window ?? 1 }) !== null;
  }

  /**
   * Revokes a single session (device). Requires `userService.revokeSession`.
   * Get the current session id with `@CurrentUser('sessionId')`.
   */
  async revokeSession(userId: string, sessionId: string, context?: AuthContext): Promise<void> {
    if (!userId || !sessionId) throw new BadRequestException("Invalid request");
    if (!this.authOptions.userService.revokeSession) {
      throw new Error("userService must implement revokeSession to revoke individual sessions");
    }
    await this.authOptions.userService.revokeSession(userId, sessionId);
    safeFire(() => this.authOptions.onLogout?.(userId, context));
  }

  /**
   * Authenticates an API key (same logic as `@ApiKeyAuth()`). Requires `apiKeyService`.
   * @returns the user/client the key belongs to, or null.
   */
  async validateApiKey(key: string, context?: AuthContext): Promise<RequestUser | null> {
    const service = this.authOptions.apiKeyService;
    if (!service) throw new Error("AuthModule: 'apiKeyService' is required to validate API keys");
    if (typeof key !== "string" || !key || key.length > 512) return null;
    const user = await service.validateApiKey(hashToken(key), context);
    return user ? { ...user, authMethod: "api_key" } : null;
  }

  /**
   * Revokes every refresh token of the user (requires `userService.revokeAllTokens`).
   * Pass the current access token (see `@AccessToken()`) to also revoke it immediately when `tokenBlacklist`
   * is configured; otherwise access tokens remain valid until they expire, so keep `expiresIn` short.
   */
  async logout(userId: string, context?: AuthContext, accessToken?: string): Promise<void> {
    if (!userId) throw new BadRequestException("Invalid request");
    if (this.authOptions.userService.revokeAllTokens) {
      await this.authOptions.userService.revokeAllTokens(userId);
    }
    if (accessToken && this.authOptions.tokenBlacklist) {
      await this.revokeAccessToken(accessToken).catch(() => false);
    }
    safeFire(() => this.authOptions.onLogout?.(userId, context));
  }

  /**
   * Logs out only the current device: revokes the session of the user's token (`userService.revokeSession`,
   * falling back to `revokeAllTokens` when the token has no session or revokeSession is not implemented)
   * and the access token itself when `tokenBlacklist` is configured.
   * @param user - `@CurrentUser()`.
   * @param accessToken - `@AccessToken()`.
   */
  async logoutCurrentSession(user: RequestUser, accessToken?: string, context?: AuthContext): Promise<void> {
    if (!user?.id) throw new BadRequestException("Invalid request");
    const us = this.authOptions.userService;
    if (user.sessionId && us.revokeSession) {
      await us.revokeSession(user.id, user.sessionId);
    } else if (us.revokeAllTokens) {
      await us.revokeAllTokens(user.id);
    }
    if (accessToken && this.authOptions.tokenBlacklist) {
      await this.revokeAccessToken(accessToken).catch(() => false);
    }
    safeFire(() => this.authOptions.onLogout?.(user.id, context));
  }

  private cookieSettings(kind: "access" | "refresh"): CookieSettings {
    const o = this.authOptions.cookieOptions ?? {};
    const path = o.path ?? "/";
    return {
      httpOnly: true,
      secure: o.secure ?? true,
      sameSite: o.sameSite ?? "strict",
      domain: o.domain,
      path: kind === "refresh" ? o.refreshTokenPath ?? path : path,
    };
  }

  /**
   * Stores the tokens in httpOnly cookies named `accessTokenCookieName` / `refreshTokenCookieName`.
   * Works with Express (`res.cookie`) and Fastify (`@fastify/cookie`). Get the response with `@Res({ passthrough: true })`.
   */
  setAuthCookies(response: unknown, tokens: AuthTokens): void {
    const { accessTokenCookieName, refreshTokenCookieName } = this.authOptions;
    if (!accessTokenCookieName && !refreshTokenCookieName) {
      throw new Error("AuthModule: set 'accessTokenCookieName' and/or 'refreshTokenCookieName' to use cookies");
    }
    if (accessTokenCookieName) {
      setResponseCookie(response, accessTokenCookieName, tokens.accessToken, {
        ...this.cookieSettings("access"),
        maxAgeSeconds: tokens.expiresIn,
      });
    }
    if (refreshTokenCookieName && tokens.refreshToken) {
      setResponseCookie(response, refreshTokenCookieName, tokens.refreshToken, {
        ...this.cookieSettings("refresh"),
        maxAgeSeconds: tokens.refreshExpiresIn,
      });
    }
  }

  /** Clears the cookies set by `setAuthCookies()` (e.g. on logout). */
  clearAuthCookies(response: unknown): void {
    const { accessTokenCookieName, refreshTokenCookieName } = this.authOptions;
    if (accessTokenCookieName) clearResponseCookie(response, accessTokenCookieName, this.cookieSettings("access"));
    if (refreshTokenCookieName) clearResponseCookie(response, refreshTokenCookieName, this.cookieSettings("refresh"));
  }

  /**
   * Revokes an access token before it expires (requires `tokenBlacklist`).
   * @returns true if the token was revoked, false if it has no `jti` (issued by an older version).
   * @throws UnauthorizedException if the token is invalid.
   */
  async revokeAccessToken(token: string): Promise<boolean> {
    const blacklist = this.authOptions.tokenBlacklist;
    if (!blacklist) throw new Error("AuthModule: 'tokenBlacklist' is required to revoke access tokens");
    const payload = await this.verifyAccessToken(token);
    if (!payload.jti) return false;
    const expiresAt = typeof payload.exp === "number" ? payload.exp * 1000 : Date.now() + 24 * 3600 * 1000;
    await blacklist.add(payload.jti, expiresAt);
    return true;
  }

  /**
   * Changes the password of an authenticated user after checking the current one.
   * Revokes every refresh token (other sessions must log in again). Requires `userService.updatePasswordHash`.
   * Attempts are rate limited per user when `rateLimitStore` is configured.
   * @throws HttpException (429) if rate limit exceeded.
   * @throws UnauthorizedException if the current password is wrong.
   * @throws BadRequestException if the new password violates the policy or equals the current one.
   */
  async changePassword(userId: string, currentPassword: string, newPassword: string, context?: AuthContext): Promise<void> {
    if (typeof currentPassword !== "string" || currentPassword.length > this.maxPasswordLength) {
      throw new BadRequestException("Invalid request");
    }
    const user = userId ? await this.findUserById(userId) : null;
    if (!user) throw new UnauthorizedException("Invalid Credentials");
    // Stops brute-forcing the current password with a stolen access token.
    const store = this.authOptions.rateLimitStore;
    const rateKey = `change-password:${this.getUserId(user)}`;
    if (store) {
      const attempts = await store.increment(rateKey, this.authOptions.rateLimitWindowMs ?? 15 * 60 * 1000);
      if (attempts > (this.authOptions.rateLimitMaxAttempts ?? 10)) {
        throw new HttpException("Too many attempts. Try again later.", HttpStatus.TOO_MANY_REQUESTS);
      }
    }
    const storedHash = user[this.authOptions.passwordField];
    const valid = await this.encryptionService.compare(currentPassword, typeof storedHash === "string" ? storedHash : "");
    if (!valid) throw new UnauthorizedException("Invalid Credentials");
    if (store) await store.reset(rateKey);
    if (currentPassword === newPassword) {
      throw new BadRequestException("New password must be different from the current one.");
    }
    await this.storeNewPassword(user, newPassword);
    safeFire(() => this.authOptions.onPasswordChanged?.(this.getUserId(user), "change", context));
  }

  /**
   * Creates a single-use password reset token for the identifier (e.g. e-mail).
   * The token becomes invalid as soon as the password changes, so it cannot be reused. No storage required.
   * Requests are rate limited per identifier (and IP, when given) if `rateLimitStore` is configured.
   * @returns null when the user does not exist. Always answer the client with the same generic message.
   */
  async createPasswordResetToken(identifier: string, context?: AuthContext): Promise<PasswordResetToken | null> {
    if (typeof identifier !== "string" || !identifier.trim() || identifier.length > this.maxIdentifierLength) {
      return null;
    }
    const normalized = this.authOptions.normalizeIdentifier ? this.authOptions.normalizeIdentifier(identifier) : identifier;
    const store = this.authOptions.rateLimitStore;
    if (store) {
      const key = context?.ip ? `reset:${context.ip}:${normalized}` : `reset:${normalized}`;
      const attempts = await store.increment(key, this.authOptions.rateLimitWindowMs ?? 15 * 60 * 1000);
      if (attempts > (this.authOptions.rateLimitMaxAttempts ?? 10)) {
        throw new HttpException("Too many attempts. Try again later.", HttpStatus.TOO_MANY_REQUESTS);
      }
    }
    const user = (await this.authOptions.userService.findOneByField(this.authOptions.identifierField, normalized)) as UserRecord | null;
    if (!user || !(await this.isActive(user))) return null;

    const expiresIn = this.authOptions.passwordResetExpiresIn ?? "15m";
    const userId = this.getUserId(user);
    const token = await this.createActionToken(userId, PASSWORD_RESET_PURPOSE, expiresIn, {
      fp: this.passwordFingerprint(user[this.authOptions.passwordField]),
    });
    return { token, userId, expiresIn: parseDurationToSeconds(expiresIn), user };
  }

  /**
   * Sets a new password using a token from `createPasswordResetToken()`.
   * Revokes every refresh token and clears failed login attempts. Requires `userService.updatePasswordHash`.
   * @throws UnauthorizedException if the token is invalid, expired or already used.
   * @throws BadRequestException if the new password violates the policy.
   */
  async resetPassword(token: string, newPassword: string, context?: AuthContext): Promise<void> {
    const payload = await this.verifyActionToken(token, PASSWORD_RESET_PURPOSE);
    const user = await this.findUserById(payload.sub);
    if (!user || !(await this.isActive(user))) throw new UnauthorizedException("Invalid token");
    const fingerprint = this.passwordFingerprint(user[this.authOptions.passwordField]);
    if (typeof payload.fp !== "string" || !timingSafeEqual(payload.fp, fingerprint)) {
      throw new UnauthorizedException("Invalid token");
    }
    await this.storeNewPassword(user, newPassword);
    const us = this.authOptions.userService;
    const identifier = user[this.authOptions.identifierField];
    if (us.clearFailedLogin && identifier != null) await us.clearFailedLogin(String(identifier));
    safeFire(() => this.authOptions.onPasswordChanged?.(this.getUserId(user), "reset", context));
  }

  /**
   * Creates a signed, short-lived token for a specific purpose (e-mail verification, magic link, invite...).
   * Action tokens never authenticate requests and are only accepted by `verifyActionToken()` with the same purpose.
   * @param data - Extra claims to embed (do not put secrets here: JWTs are only signed, not encrypted).
   */
  async createActionToken(
    userId: string,
    purpose: string,
    expiresIn: string | number = "1h",
    data: Record<string, unknown> = {}
  ): Promise<string> {
    if (!userId || !purpose) throw new Error("createActionToken: 'userId' and 'purpose' are required");
    const custom: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data)) {
      if (!RESERVED_CLAIMS.includes(key)) custom[key] = value;
    }
    return this.jwtService.signAsync(
      { ...custom, sub: userId, type: "action", purpose, jti: randomUUID() },
      compact({
        secret: this.actionSecret,
        expiresIn: parseDurationToSeconds(expiresIn),
        issuer: this.authOptions.jwtIssuer,
        audience: this.authOptions.jwtAudience,
        algorithm: this.algorithm,
      }) as SignOptions
    );
  }

  /**
   * Verifies a token created by `createActionToken()` for the given purpose.
   * @throws UnauthorizedException if the token is invalid, expired or for another purpose.
   */
  async verifyActionToken(token: string, purpose: string): Promise<JwtPayload> {
    if (typeof token !== "string" || !token.trim() || token.length > SECURITY_CONSTANTS.MAX_REFRESH_TOKEN_LENGTH) {
      throw new UnauthorizedException("Invalid token");
    }
    let payload: JwtPayload;
    try {
      payload = await this.jwtService.verifyAsync<JwtPayload>(token, compact({
        secret: this.actionSecret,
        issuer: this.authOptions.jwtIssuer,
        audience: this.authOptions.jwtAudience,
        algorithms: [this.algorithm],
        clockTolerance: this.authOptions.clockToleranceSeconds,
      }) as VerifyOptions);
    } catch {
      throw new UnauthorizedException("Invalid token");
    }
    if (payload.type !== "action" || payload.purpose !== purpose || !payload.sub) {
      throw new UnauthorizedException("Invalid token");
    }
    return payload;
  }

  /**
   * Verifies an access token (signature, expiration, issuer, audience, algorithm and token type).
   * Useful outside HTTP guards (WebSockets, GraphQL subscriptions, microservices).
   * @throws UnauthorizedException if the token is invalid.
   */
  async verifyAccessToken(token: string): Promise<JwtPayload> {
    if (typeof token !== "string" || !token.trim() || token.length > SECURITY_CONSTANTS.MAX_REFRESH_TOKEN_LENGTH) {
      throw new UnauthorizedException("Invalid token");
    }
    let payload: JwtPayload;
    try {
      payload = await this.jwtService.verifyAsync<JwtPayload>(token, compact({
        secret: this.authOptions.jwtSecret,
        issuer: this.authOptions.jwtIssuer,
        audience: this.authOptions.jwtAudience,
        algorithms: [this.algorithm],
        clockTolerance: this.authOptions.clockToleranceSeconds,
      }) as VerifyOptions);
    } catch {
      throw new UnauthorizedException("Invalid token");
    }
    if (payload.type !== undefined && payload.type !== "access") throw new UnauthorizedException("Invalid token");
    if (this.authOptions.tokenBlacklist && payload.jti && (await this.authOptions.tokenBlacklist.has(payload.jti))) {
      throw new UnauthorizedException("Invalid token");
    }
    return payload;
  }

  /**
   * Decodes a token WITHOUT verifying its signature. Never trust the result for authorization.
   */
  decodeToken(token: string): JwtPayload | null {
    try {
      const decoded = this.jwtService.decode(token);
      return decoded && typeof decoded === "object" ? (decoded as JwtPayload) : null;
    } catch {
      return null;
    }
  }
}
