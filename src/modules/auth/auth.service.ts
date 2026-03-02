import { Inject, Injectable, UnauthorizedException, BadRequestException, HttpException, HttpStatus } from "@nestjs/common";
import { MODULE_OPTIONS_TOKEN } from "./auth.module-definition";
import type { AuthOptions } from "../../interfaces/auth.options";
import { JwtService } from "@nestjs/jwt";
import type { IEncryptionService } from "../../interfaces/encryption-service.interface";
import type { AuthTokens } from "../../types/auth.types";
import { SECURITY_CONSTANTS } from "../../security/constants";

type UserRecord = Record<string, unknown> & { id: string };

function safeFire<T>(fn: (() => T | Promise<T>) | undefined): void {
  if (!fn) return;
  Promise.resolve(fn()).catch(() => {});
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

  private validateLoginInput(credentials: Record<string, unknown>): { identifier: string; password: string } {
    const identifier = credentials[this.authOptions.identifierField];
    const password = credentials[this.authOptions.passwordField];
    if (identifier == null || password == null) {
      throw new BadRequestException("Invalid request");
    }
    const idStr = typeof identifier === "string" ? identifier : String(identifier);
    const pwdStr = typeof password === "string" ? password : "";
    if (idStr.length > this.maxIdentifierLength || pwdStr.length > this.maxPasswordLength) {
      throw new BadRequestException("Invalid request");
    }
    if (!idStr.trim()) throw new BadRequestException("Invalid request");
    return { identifier: idStr, password: pwdStr };
  }

  async generateTokens(user: UserRecord): Promise<AuthTokens> {
    const rolesField = this.authOptions.rolesField ?? "roles";
    const payload = {
      sub: user.id,
      username: String(user[this.authOptions.identifierField] ?? ""),
      roles: (user[rolesField] as string[] | undefined) ?? [],
    };
    const accessToken = await this.jwtService.signAsync(payload, {
      secret: this.authOptions.jwtSecret,
      expiresIn: this.authOptions.expiresIn as string | number,
      issuer: this.authOptions.jwtIssuer,
      audience: this.authOptions.jwtAudience,
    } as Parameters<JwtService["signAsync"]>[1]);

    let refreshToken: string | null = null;

    if (this.authOptions.useRefreshTokens) {
      if (!this.authOptions.userService.saveRefreshToken) {
        throw new Error("userService must implement saveRefreshToken to use Refresh Tokens");
      }
      refreshToken = await this.jwtService.signAsync(payload, {
        secret: this.authOptions.refreshSecret ?? this.authOptions.jwtSecret,
        expiresIn: (this.authOptions.refreshExpiresIn ?? "7d") as string | number,
        issuer: this.authOptions.refreshIssuer ?? this.authOptions.jwtIssuer,
        audience: this.authOptions.refreshAudience ?? this.authOptions.jwtAudience,
      } as Parameters<JwtService["signAsync"]>[1]);
      await this.authOptions.userService.saveRefreshToken(user.id, refreshToken);
    }

    return { accessToken, refreshToken };
  }

  async refresh(rt: string): Promise<AuthTokens> {
    if (typeof rt !== "string" || !rt.trim() || rt.length > SECURITY_CONSTANTS.MAX_REFRESH_TOKEN_LENGTH) {
      safeFire(() => this.authOptions.onRefreshFailure?.("invalid_input"));
      throw new UnauthorizedException("Invalid Refresh Token");
    }
    try {
      const payload = await this.jwtService.verifyAsync<{ sub: string }>(rt, {
        secret: this.authOptions.refreshSecret ?? this.authOptions.jwtSecret,
        issuer: this.authOptions.refreshIssuer ?? this.authOptions.jwtIssuer,
        audience: this.authOptions.refreshAudience ?? this.authOptions.jwtAudience,
      });
      const user = (await this.authOptions.userService.findOneByField("id", payload.sub)) as UserRecord | null;
      if (!user) {
        safeFire(() => this.authOptions.onRefreshFailure?.("user_not_found"));
        throw new UnauthorizedException("Invalid Refresh Token");
      }

      if (this.authOptions.userService.isRefreshTokenValid) {
        const isValid = await this.authOptions.userService.isRefreshTokenValid(user.id, rt);
        if (!isValid) {
          if (this.authOptions.userService.revokeAllTokens) {
            await this.authOptions.userService.revokeAllTokens(user.id);
          }
          safeFire(() => this.authOptions.onRefreshFailure?.("token_compromised"));
          throw new UnauthorizedException("Refresh Token compromised.");
        }
      }

      safeFire(() => this.authOptions.onRefreshSuccess?.(user.id));
      return this.generateTokens(user);
    } catch (e) {
      if (e instanceof UnauthorizedException) throw e;
      safeFire(() => this.authOptions.onRefreshFailure?.("verification_failed"));
      throw new UnauthorizedException("Invalid Refresh Token");
    }
  }

  /**
   * Performs full user authentication with input validation, optional lockout, rate limiting, and audit hooks.
   * @throws BadRequestException if input is invalid (length/type).
   * @throws TooManyRequestsException if rate limit exceeded.
   * @throws UnauthorizedException if credentials invalid or account locked.
   */
  async login(credentials: Record<string, unknown>): Promise<AuthTokens> {
    const { identifier, password } = this.validateLoginInput(credentials);

    const rateLimitKey = `login:${identifier}`;
    const store = this.authOptions.rateLimitStore;
    const maxAttempts = this.authOptions.rateLimitMaxAttempts ?? 10;
    const windowMs = this.authOptions.rateLimitWindowMs ?? 15 * 60 * 1000;

    if (store) {
      const attempts = await store.increment(rateLimitKey, windowMs);
      if (attempts > maxAttempts) {
        safeFire(() => this.authOptions.onLoginFailure?.(identifier, "rate_limit_exceeded"));
        throw new HttpException("Too many attempts. Try again later.", HttpStatus.TOO_MANY_REQUESTS);
      }
    }

    const us = this.authOptions.userService;
    if (us.getLockoutUntil && this.authOptions.lockoutMaxAttempts != null) {
      const lockUntil = await us.getLockoutUntil(identifier);
      if (lockUntil && lockUntil > new Date()) {
        safeFire(() => this.authOptions.onLoginFailure?.(identifier, "account_locked"));
        throw new UnauthorizedException("Invalid Credentials");
      }
    }

    const user = (await us.findOneByField(this.authOptions.identifierField, identifier)) as UserRecord | null;

    if (!user) {
      if (us.recordFailedLogin) await us.recordFailedLogin(identifier);
      safeFire(() => this.authOptions.onLoginFailure?.(identifier, "user_not_found"));
      throw new UnauthorizedException("Invalid Credentials");
    }

    const storedHash = user[this.authOptions.passwordField];
    const isPasswordValid = await this.encryptionService.compare(
      password,
      typeof storedHash === "string" ? storedHash : ""
    );

    if (!isPasswordValid) {
      if (us.recordFailedLogin) await us.recordFailedLogin(identifier);
      safeFire(() => this.authOptions.onLoginFailure?.(identifier, "invalid_password"));
      throw new UnauthorizedException("Invalid Credentials");
    }

    if (us.clearFailedLogin) await us.clearFailedLogin(identifier);
    if (store) await store.reset(rateLimitKey);
    safeFire(() => this.authOptions.onLoginSuccess?.(user.id, identifier));

    return this.generateTokens(user);
  }
}