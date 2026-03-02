export interface IAuthUserService {
  /** Find the user by the given field (email, username, etc). */
  findOneByField(field: string, value: unknown): Promise<unknown>;
  /** Required for Refresh Token rotation. */
  saveRefreshToken?(userId: string, token: string): Promise<void>;
  /** Required for Refresh Token rotation. */
  isRefreshTokenValid?(userId: string, token: string): Promise<boolean>;
  /** Required for Refresh Token rotation. */
  revokeAllTokens?(userId: string): Promise<void>;

  /** Account lockout: return lockout end date if the identifier is locked, else null. */
  getLockoutUntil?(identifier: string): Promise<Date | null>;
  /** Account lockout: record a failed login attempt for the identifier. */
  recordFailedLogin?(identifier: string): Promise<void>;
  /** Account lockout: clear failed attempts after successful login. */
  clearFailedLogin?(identifier: string): Promise<void>;
}