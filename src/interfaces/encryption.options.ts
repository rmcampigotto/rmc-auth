export interface Argon2Options {
  /** Argon2 variant. @default 'argon2id' */
  type?: "argon2d" | "argon2i" | "argon2id";
  /** Memory cost in KiB. @default 65536 (64 MiB) */
  memoryCost?: number;
  /** Number of iterations. @default 3 */
  timeCost?: number;
  /** Degree of parallelism. @default 4 */
  parallelism?: number;
}

export interface PasswordPolicy {
  /** @default 8 */
  minLength?: number;
  /** @default 128 */
  maxLength?: number;
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireNumber?: boolean;
  requireSymbol?: boolean;
  /** Rejects passwords made only of digits. @default true */
  disallowOnlyNumbers?: boolean;
  /** Rejects passwords present in this list (case-insensitive). */
  blacklist?: string[];
}

export interface EncryptionOptions {
  /**
   * Number of rounds for Bcrypt processing.
   * Recommended: 10 or more.
   * @default 10
   */
  saltRounds?: number;

  /**
   * Optional string to append to the password before hashing.
   * Improves security against Rainbow Table attacks.
   */
  pepper?: string;

  /**
   * How the pepper is combined with the password.
   * - `'append'` (default, backward compatible): `password + pepper`. With bcrypt, input over 72 bytes is truncated,
   *   so long passwords may lose the pepper.
   * - `'hmac'`: `HMAC-SHA256(pepper, password)` (base64). Fixed length, never truncated. Recommended for new projects.
   * Changing this invalidates existing hashes.
   * @default 'append'
   */
  pepperStrategy?: "append" | "hmac";

  /**
   * If true, the library throws if the password is "weak"
   * (e.g. fewer than 8 characters or numbers only).
   */
  strongPasswordValidation?: boolean;

  /**
   * Custom password policy. Takes precedence over `strongPasswordValidation`.
   */
  passwordPolicy?: PasswordPolicy;

  /**
   * Hashing algorithm to use.
   * @default 'bcrypt'
   */
  algorithm?: "bcrypt" | "argon2";

  /** Argon2 parameters (only for `algorithm: 'argon2'`). */
  argon2Options?: Argon2Options;

  /**
   * If true, uses OWASP-based password validation (owasp-password-strength-test)
   * instead of simple length/numeric validation.
   */
  useOwaspPolicy?: boolean;

  /**
   * Optional breach check: if returns true, the password is considered compromised (e.g. HIBP).
   * Called before hashing in hash(). Throw or return true to reject the password.
   */
  checkPasswordBreach?: (password: string) => Promise<boolean>;
}
