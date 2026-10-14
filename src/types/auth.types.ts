/**
 * Kind of token carried in the `type` claim.
 * Prevents an access token from being used as a refresh token (and vice versa).
 */
export type TokenType = "access" | "refresh" | "action";

/**
 * JWT payload shape (claims) after verification.
 * Use this to type `request.user` or decode results.
 */
export interface JwtPayload {
  sub: string;
  username: string;
  roles?: string[];
  /** Fine-grained permissions (when `permissionsField` is configured). */
  permissions?: string[];
  /** Token kind. Only access tokens authenticate requests. */
  type?: TokenType;
  /** Session id: stable across refresh rotations, identifies a device/login. */
  sid?: string;
  /** Purpose of an action token (e.g. 'password_reset', 'email_verification'). */
  purpose?: string;
  /** Unique token id (used for rotation and revocation). */
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
  /** Fine-grained permissions (when `permissionsField` is configured). */
  permissions?: string[];
  /** Session id of the token (when refresh tokens are enabled). */
  sessionId?: string;
  /** How the request was authenticated. */
  authMethod?: "jwt" | "api_key";
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
  /** Session id (only when refresh tokens are enabled). */
  sessionId?: string;
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
  | "invalid_two_factor_code"
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

/** Metadata passed to `saveRefreshToken` / `isRefreshTokenValid` (multi-device sessions). */
export interface RefreshSessionInfo {
  /** Stable id of the session (device). Kept across refresh rotations. */
  sessionId: string;
  /** Unique id of this refresh token. */
  jti: string;
  /** When this refresh token expires. Use it to clean up stored sessions. */
  expiresAt: Date;
  /** Request context of the login/refresh (ip, userAgent), when provided. */
  context?: AuthContext;
}

/** Result of `AuthService.authenticate()`. */
export type AuthResult =
  | { status: "success"; tokens: AuthTokens }
  | { status: "two_factor_required"; mfaToken: string; expiresIn: number };

/** Result of `AuthService.setupTwoFactor()`. Persist `secret` (encrypted) and `recoveryCodeHashes` after confirmation. */
export interface TwoFactorSetup {
  secret: string;
  otpauthUrl: string;
  recoveryCodes: string[];
  recoveryCodeHashes: string[];
}

/** Result of `AuthService.createPasswordResetToken()`. */
export interface PasswordResetToken {
  token: string;
  userId: string;
  /** Lifetime in seconds. */
  expiresIn: number;
  /** The user record, e.g. to read the e-mail address the link will be sent to. */
  user: Record<string, unknown>;
}

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
