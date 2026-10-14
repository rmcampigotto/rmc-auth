import { IEncryptionService } from "./encryption-service.interface";
import { IAuthUserService } from "./user-service.interface";
import type {
  AuthContext,
  JwtPayload,
  LoginFailureReason,
  RefreshFailureReason,
  RequestUser,
} from "../types/auth.types";

/** HMAC algorithms supported for signing tokens. */
export type JwtAlgorithm = "HS256" | "HS384" | "HS512";

export interface AuthOptions {
  /**
   * Secret key to sign the JWT.
   * @example 'my-ultra-secret-key'
   */
  jwtSecret: string;
  /**
   * Access Token lifetime.
   * Can be a number (seconds) or a string (e.g. '15m', '1h').
   */
  expiresIn: string | number;
  /** Name of the login field (e.g. 'email', 'username'). */
  identifierField: string;
  /** Name of the password field (e.g. 'password'). */
  passwordField: string;
  /** Name of the field that contains roles in the user object (e.g. 'roles', 'permissions'). */
  rolesField?: string;
  /**
   * Name of the field that contains the user id.
   * @default 'id'
   */
  idField?: string;
  /** Instance of the service that implements user lookup in the database. */
  userService: IAuthUserService;
  /** Instance of the encryption service (EncryptionService). */
  encryptionService: IEncryptionService;
  /** Enable Refresh Token and security rotation. */
  useRefreshTokens?: boolean;
  /** Separate secret for the Refresh Token (recommended for security). */
  refreshSecret?: string;
  /** Refresh Token expiration. Example: 3000. Value in seconds or string (e.g. '7d'). */
  refreshExpiresIn?: string | number;
  /**
   * If true, refresh tokens are stored as SHA-256 hashes: `saveRefreshToken` and `isRefreshTokenValid`
   * receive the hash instead of the raw token. Recommended: a database leak won't expose usable tokens.
   * @default false
   */
  hashRefreshTokens?: boolean;
  /**
   * If true, JwtAuthGuard is applied automatically to all application routes,
   * and RolesGuard enforces `@Roles()` globally.
   */
  globalLock?: boolean;
  /**
   * Default issuer for the Access Token.
   * Recommended to always set.
   */
  jwtIssuer?: string;

  /**
   * Default audience for the Access Token.
   * Recommended to always set.
   */
  jwtAudience?: string;

  /**
   * Issuer for the Refresh Token.
   * If not set, jwtIssuer is used.
   */
  refreshIssuer?: string;

  /**
   * Audience for the Refresh Token.
   * If not set, jwtAudience is used.
   */
  refreshAudience?: string;

  /**
   * Signing algorithm. Verification only accepts this algorithm (prevents algorithm confusion).
   * @default 'HS256'
   */
  jwtAlgorithm?: JwtAlgorithm;

  /**
   * Clock skew tolerance in seconds when verifying `exp`/`nbf`.
   * @default 0
   */
  clockToleranceSeconds?: number;

  // --- Token extraction & payload ---

  /**
   * Name of a cookie that may carry the access token (requires `cookie-parser`).
   * The `Authorization: Bearer` header is always checked first.
   */
  accessTokenCookieName?: string;

  /**
   * Adds custom claims to the token payload (e.g. tenantId, permissions).
   * Reserved claims (sub, username, roles, type, jti, iat, exp, iss, aud) cannot be overridden.
   * Custom claims are exposed as `request.user.claims`.
   */
  buildPayload?: (user: Record<string, unknown>) => Record<string, unknown> | Promise<Record<string, unknown>>;

  /**
   * Extra validation executed on every authenticated request after the JWT is verified
   * (e.g. check the user still exists/is active, or a token blacklist).
   * Return the user to attach to the request, or null/false to reject with 401.
   */
  validateJwtPayload?: (
    payload: JwtPayload,
    user: RequestUser
  ) => RequestUser | null | false | Promise<RequestUser | null | false>;

  /**
   * Checks whether the user may authenticate (e.g. email verified, not banned).
   * Called on login and refresh. Returning false responds with the same generic 401.
   */
  isUserActive?: (user: Record<string, unknown>) => boolean | Promise<boolean>;

  /**
   * Normalizes the identifier before lookup, rate limit and lockout (e.g. `(v) => v.trim().toLowerCase()`).
   */
  normalizeIdentifier?: (identifier: string) => string;

  // --- Cybersecurity options ---

  /**
   * When true, enforces: jwtIssuer and jwtAudience required, access token expiresIn <= 1 hour,
   * JWT secret length >= 32, and a distinct refreshSecret when refresh tokens are enabled. Use in production.
   */
  strictMode?: boolean;

  /**
   * Max length for identifier (login field). Prevents DoS.
   * @default 256
   */
  maxIdentifierLength?: number;

  /**
   * Max length for password input. Prevents DoS (bcrypt has 72-byte limit).
   * @default 1024
   */
  maxPasswordLength?: number;

  /** Account lockout: max failed attempts before locking. Requires userService lockout methods. */
  lockoutMaxAttempts?: number;
  /**
   * Account lockout: duration in minutes. Forwarded to `recordFailedLogin`.
   * @default 15
   */
  lockoutDurationMinutes?: number;

  /** Security audit: called after successful login. Do not throw. */
  onLoginSuccess?: (userId: string, identifier: string, context?: AuthContext) => void | Promise<void>;
  /** Security audit: called after failed login (invalid credentials or locked). Do not throw. */
  onLoginFailure?: (identifier: string, reason: LoginFailureReason, context?: AuthContext) => void | Promise<void>;
  /** Security audit: called after successful refresh. Do not throw. */
  onRefreshSuccess?: (userId: string, context?: AuthContext) => void | Promise<void>;
  /** Security audit: called after failed refresh. Do not throw. */
  onRefreshFailure?: (reason: RefreshFailureReason, context?: AuthContext) => void | Promise<void>;
  /** Security audit: called after logout. Do not throw. */
  onLogout?: (userId: string, context?: AuthContext) => void | Promise<void>;

  /** Rate limit: max login attempts per key (identifier, or IP + identifier when context.ip is given) per window. */
  rateLimitMaxAttempts?: number;
  /** Rate limit: window in milliseconds. */
  rateLimitWindowMs?: number;
  /** Rate limit store. If not provided, rate limiting is skipped. */
  rateLimitStore?: ILoginRateLimitStore;
}

/**
 * Store for login rate limiting (e.g. by IP or IP+identifier).
 * Implement with in-memory, Redis, or DB for distributed apps.
 */
export interface ILoginRateLimitStore {
  getAttempts(key: string): Promise<number>;
  increment(key: string, windowMs: number): Promise<number>;
  reset(key: string): Promise<void>;
}
