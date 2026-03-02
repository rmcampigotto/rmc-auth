import { IEncryptionService } from "./encryption-service.interface";
import { IAuthUserService } from "./user-service.interface";

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
  /** If true, JwtAuthGuard is applied automatically to all application routes. */
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

  // --- Cybersecurity options ---

  /**
   * When true, enforces: jwtIssuer and jwtAudience required, access token expiresIn <= 1 hour,
   * and JWT secret length >= 32. Use in production.
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
  /** Account lockout: duration in minutes. */
  lockoutDurationMinutes?: number;

  /** Security audit: called after successful login. Do not throw. */
  onLoginSuccess?: (userId: string, identifier: string) => void | Promise<void>;
  /** Security audit: called after failed login (invalid credentials or locked). Do not throw. */
  onLoginFailure?: (identifier: string, reason: string) => void | Promise<void>;
  /** Security audit: called after successful refresh. Do not throw. */
  onRefreshSuccess?: (userId: string) => void | Promise<void>;
  /** Security audit: called after failed refresh. Do not throw. */
  onRefreshFailure?: (reason: string) => void | Promise<void>;

  /** Rate limit: max login attempts per key (e.g. IP + identifier) per window. */
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