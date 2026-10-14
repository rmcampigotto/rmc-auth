import type { LockoutPolicy, RefreshSessionInfo } from "../types/auth.types";

export interface IAuthUserService {
  /** Find the user by the given field (email, username, etc). */
  findOneByField(field: string, value: unknown): Promise<unknown>;
  /**
   * Required for Refresh Token rotation.
   * When `hashRefreshTokens` is enabled, `token` is the SHA-256 hash of the refresh token.
   */
  saveRefreshToken?(userId: string, token: string, session?: RefreshSessionInfo): Promise<void>;
  /**
   * Required for Refresh Token rotation (reuse detection).
   * When `hashRefreshTokens` is enabled, `token` is the SHA-256 hash of the refresh token.
   */
  isRefreshTokenValid?(userId: string, token: string, session?: RefreshSessionInfo): Promise<boolean>;
  /**
   * Optional (multi-device sessions): revoke a single session. Store refresh tokens keyed by
   * `session.sessionId` (from `saveRefreshToken`) to support one session per device.
   */
  revokeSession?(userId: string, sessionId: string): Promise<void>;
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
   * Required by `changePassword()` and `resetPassword()`.
   */
  updatePasswordHash?(userId: string, newHash: string): Promise<void>;

  /**
   * Two-factor: return the user's TOTP secret (base32), or null when 2FA is disabled for the user.
   * Decrypt it here if you store it with `encryptSecret()`.
   */
  getTwoFactorSecret?(userId: string): Promise<string | null>;
  /**
   * Two-factor (replay protection): atomically record that the TOTP time step was used.
   * Return false if `step` is not greater than the last used step.
   */
  consumeTotpStep?(userId: string, step: number): Promise<boolean>;
  /**
   * Two-factor: consume a recovery code by its hash (see `generateRecoveryCodes`).
   * Return true if the hash existed and was removed.
   */
  consumeRecoveryCode?(userId: string, codeHash: string): Promise<boolean>;
}
