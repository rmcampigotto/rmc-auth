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
   * If true, the library throws if the password is "weak"
   * (e.g. fewer than 8 characters or numbers only).
   */
  strongPasswordValidation?: boolean;

  /**
   * Hashing algorithm to use.
   * @default 'bcrypt'
   */
  algorithm?: "bcrypt" | "argon2";

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