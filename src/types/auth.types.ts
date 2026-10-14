/**
 * Kind of token carried in the `type` claim.
 * Prevents an access token from being used as a refresh token (and vice versa).
 */
export type TokenType = "access" | "refresh";

/**
 * JWT payload shape (claims) after verification.
 * Use this to type `request.user` or decode results.
 */
export interface JwtPayload {
  sub: string;
  username: string;
  roles?: string[];
  /** Token kind. Refresh tokens are rejected by the access-token strategy. */
  type?: TokenType;
  /** Unique token id (always present on refresh tokens). */
  jti?: string;
  iat?: number;
  exp?: number;
  iss?: string;
  aud?: string | string[];
  /** Custom claims added through `AuthOptions.buildPayload`. */
  [claim: string]: unknown;
}

/**
 * User object attached to the request after JWT validation.
 * Populated by JwtStrategy and available as `request.user`.
 */
export interface RequestUser {
  id: string;
  username: string;
  roles?: string[];
  /** Custom claims added through `AuthOptions.buildPayload`, if any. */
  claims?: Record<string, unknown>;
}

/**
 * Return type of login() and refresh().
 */
export interface AuthTokens {
  accessToken: string;
  refreshToken: string | null;
  /** Always `'Bearer'`. */
  tokenType?: "Bearer";
  /** Access token lifetime in seconds. */
  expiresIn?: number;
  /** Refresh token lifetime in seconds (only when refresh tokens are enabled). */
  refreshExpiresIn?: number;
}

/**
 * Request metadata optionally passed to login()/refresh().
 * Used to scope rate limiting (per IP + identifier) and forwarded to audit hooks.
 */
export interface AuthContext {
  ip?: string;
  userAgent?: string;
  [key: string]: unknown;
}

/** Reasons reported to `onLoginFailure`. */
export type LoginFailureReason =
  | "invalid_input"
  | "rate_limit_exceeded"
  | "account_locked"
  | "user_not_found"
  | "invalid_password"
  | "user_inactive";

/** Reasons reported to `onRefreshFailure`. */
export type RefreshFailureReason =
  | "invalid_input"
  | "verification_failed"
  | "wrong_token_type"
  | "user_not_found"
  | "user_inactive"
  | "token_compromised";

/** Lockout settings passed to `IAuthUserService.recordFailedLogin`. */
export interface LockoutPolicy {
  maxAttempts: number;
  durationMinutes: number;
}

/** Result of `EncryptionService.validatePassword()`. */
export interface PasswordValidationResult {
  valid: boolean;
  errors: string[];
}
