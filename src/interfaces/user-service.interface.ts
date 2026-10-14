import type { LockoutPolicy } from "../types/auth.types";

export interface IAuthUserService {
  /** Find the user by the given field (email, username, etc). */
  findOneByField(field: string, value: unknown): Promise<unknown>;
  /**
   * Required for Refresh Token rotation.
   * When `hashRefreshTokens` is enabled, `token` is the SHA-256 hash of the refresh token.
   */
  saveRefreshToken?(userId: string, token: string): Promise<void>;
  /**
   * Required for Refresh Token rotation (reuse detection).
   * When `hashRefreshTokens` is enabled, `token` is the SHA-256 hash of the refresh token.
   */
  isRefreshTokenValid?(userId: string, token: string): Promise<boolean>;
  /** Revokes every refresh token of the user. Used on logout and when token reuse is detected. */
  revokeAllTokens?(userId: string): Promise<void>;

  /** Account lockout: return lockout end date if the identifier is locked, else null. */
  getLockoutUntil?(identifier: string): Promise<Date | null>;
  /**
   * Account lockout: record a failed login attempt for the identifier.
   * `policy` carries `lockoutMaxAttempts` / `lockoutDurationMinutes` so the implementation can set the lock date.
   */
  recordFailedLogin?(identifier: string, policy?: LockoutPolicy): Promise<void>;
  /** Account lockout: clear failed attempts after successful login. */
  clearFailedLogin?(identifier: string): Promise<void>;

  /**
   * Optional: persist a new password hash. Called after a successful login when the stored hash
   * uses outdated parameters (e.g. bcrypt -> argon2 migration, higher cost). Enables transparent rehashing.
   */
  updatePasswordHash?(userId: string, newHash: string): Promise<void>;
}
