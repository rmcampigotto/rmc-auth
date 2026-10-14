import { Inject, Injectable, UnauthorizedException, BadRequestException, HttpException, HttpStatus } from "@nestjs/common";
import { randomUUID } from "crypto";
import { MODULE_OPTIONS_TOKEN } from "./auth.module-definition";
import type { AuthOptions } from "../../interfaces/auth.options";
import { JwtService } from "@nestjs/jwt";
import type { IEncryptionService } from "../../interfaces/encryption-service.interface";
import type { AuthContext, AuthTokens, JwtPayload, PasswordResetToken } from "../../types/auth.types";
import { SECURITY_CONSTANTS } from "../../security/constants";
import { hashToken } from "../../security/token.util";
import { timingSafeEqual } from "../../security/timing-safe.util";
import { parseDurationToSeconds } from "../../utils/duration.util";

type UserRecord = Record<string, unknown>;
type SignOptions = Parameters<JwtService["signAsync"]>[1];
type VerifyOptions = Parameters<JwtService["verifyAsync"]>[1];

const RESERVED_CLAIMS = ["sub", "username", "roles", "permissions", "type", "purpose", "jti", "iat", "exp", "nbf", "iss", "aud"];
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
   */
  async generateTokens(user: UserRecord): Promise<AuthTokens> {
    const payload = await this.buildPayload(user);
    const accessToken = await this.jwtService.signAsync({ ...payload, type: "access", jti: randomUUID() }, compact({
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
      const refreshToken = await this.jwtService.signAsync(
        { sub: payload.sub, username: payload.username, roles: payload.roles, type: "refresh", jti: randomUUID() },
        compact({
          secret: this.refreshSecret,
          expiresIn: this.refreshExpiresIn,
          issuer: this.authOptions.refreshIssuer ?? this.authOptions.jwtIssuer,
          audience: this.authOptions.refreshAudience ?? this.authOptions.jwtAudience,
          algorithm: this.algorithm,
        }) as SignOptions
      );
      await this.authOptions.userService.saveRefreshToken(payload.sub, this.storedRefreshToken(refreshToken));
      tokens.refreshToken = refreshToken;
      tokens.refreshExpiresIn = parseDurationToSeconds(this.refreshExpiresIn);
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

    const user = (await this.authOptions.userService.findOneByField(this.idField, payload.sub)) as UserRecord | null;
    if (!user) throw fail("user_not_found");
    if (!(await this.isActive(user))) throw fail("user_inactive");

    const userId = this.getUserId(user);
    if (this.authOptions.userService.isRefreshTokenValid) {
      const isValid = await this.authOptions.userService.isRefreshTokenValid(userId, this.storedRefreshToken(rt));
      if (!isValid) {
        if (this.authOptions.userService.revokeAllTokens) {
          await this.authOptions.userService.revokeAllTokens(userId);
        }
        throw fail("token_compromised", "Refresh Token compromised.");
      }
    }

    safeFire(() => this.authOptions.onRefreshSuccess?.(userId, context));
    return this.generateTokens(user);
  }

  /**
   * Validates credentials and returns the user record, without issuing tokens.
   * Applies input validation, rate limiting, lockout, timing-attack protection and audit hooks.
   * @throws BadRequestException if input is invalid (length/type).
   * @throws HttpException (429) if rate limit exceeded.
   * @throws UnauthorizedException if credentials invalid, account locked or user inactive.
   */
  async validateUser(credentials: Record<string, unknown>, context?: AuthContext): Promise<UserRecord> {
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

    safeFire(() => this.authOptions.onLoginSuccess?.(userId, identifier, context));
    return user;
  }

  /**
   * Performs full user authentication with input validation, optional lockout, rate limiting, and audit hooks.
   * @param context - Optional request metadata (ip, userAgent). When `ip` is given, rate limiting is per IP + identifier.
   * @throws BadRequestException if input is invalid (length/type).
   * @throws HttpException (429) if rate limit exceeded.
   * @throws UnauthorizedException if credentials invalid or account locked.
   */
  async login(credentials: Record<string, unknown>, context?: AuthContext): Promise<AuthTokens> {
    const user = await this.validateUser(credentials, context);
    return this.generateTokens(user);
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
   * @throws UnauthorizedException if the current password is wrong.
   * @throws BadRequestException if the new password violates the policy or equals the current one.
   */
  async changePassword(userId: string, currentPassword: string, newPassword: string, context?: AuthContext): Promise<void> {
    if (typeof currentPassword !== "string" || currentPassword.length > this.maxPasswordLength) {
      throw new BadRequestException("Invalid request");
    }
    const user = userId ? await this.findUserById(userId) : null;
    if (!user) throw new UnauthorizedException("Invalid Credentials");
    const storedHash = user[this.authOptions.passwordField];
    const valid = await this.encryptionService.compare(currentPassword, typeof storedHash === "string" ? storedHash : "");
    if (!valid) throw new UnauthorizedException("Invalid Credentials");
    if (currentPassword === newPassword) {
      throw new BadRequestException("New password must be different from the current one.");
    }
    await this.storeNewPassword(user, newPassword);
    safeFire(() => this.authOptions.onPasswordChanged?.(this.getUserId(user), "change", context));
  }

  /**
   * Creates a single-use password reset token for the identifier (e.g. e-mail).
   * The token becomes invalid as soon as the password changes, so it cannot be reused. No storage required.
   * @returns null when the user does not exist. Always answer the client with the same generic message.
   */
  async createPasswordResetToken(identifier: string): Promise<PasswordResetToken | null> {
    if (typeof identifier !== "string" || !identifier.trim() || identifier.length > this.maxIdentifierLength) {
      return null;
    }
    const normalized = this.authOptions.normalizeIdentifier ? this.authOptions.normalizeIdentifier(identifier) : identifier;
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
