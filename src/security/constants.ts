/**
 * Security-related limits to prevent DoS, injection, and abuse.
 * These values follow OWASP and common hardening guidelines.
 */
export const SECURITY_CONSTANTS = {
  /** Max length for login identifier (email, username) to prevent DoS. */
  MAX_IDENTIFIER_LENGTH: 256,
  /** Max length for password input (bcrypt has 72-byte limit; cap earlier for safety). */
  MAX_PASSWORD_LENGTH: 1024,
  /** Max length for refresh token string before verification. */
  MAX_REFRESH_TOKEN_LENGTH: 4096,
  /** Minimum recommended length for JWT secret (strict mode). */
  MIN_JWT_SECRET_LENGTH: 32,
  /** Default max access token TTL in seconds when strictMode is enabled (1 hour). */
  STRICT_MODE_MAX_EXPIRES_IN_SECONDS: 3600,
} as const;
