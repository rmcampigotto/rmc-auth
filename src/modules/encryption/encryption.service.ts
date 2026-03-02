import { Injectable, Inject, BadRequestException } from "@nestjs/common";
import type { EncryptionOptions } from "../../interfaces/encryption.options";
import { MODULE_OPTIONS_TOKEN } from "./encryption.module-definition";
import * as bcrypt from "bcrypt";
import * as argon2 from "argon2";
import owasp from "owasp-password-strength-test";

@Injectable()
export class EncryptionService {
  constructor(
    @Inject(MODULE_OPTIONS_TOKEN) private options: EncryptionOptions
  ) {}

  /**
   * Configurable hash function (bcrypt by default, optionally Argon2).
   * Uses pepper if configured in setup.
   * @param password - Plain password. StrongPasswordValidation or OWASP policy applied if configured.
   * @returns Hashed password.
   */
  async hash(password: string): Promise<string> {
    if (!password) throw new Error("Password is required");

    if (this.options.checkPasswordBreach) {
      const breached = await this.options.checkPasswordBreach(password);
      if (breached) {
        throw new BadRequestException("This password has been found in a data breach. Choose a different password.");
      }
    }

    const algorithm = this.options.algorithm || "bcrypt";

    if (this.options.useOwaspPolicy) {
      const result = owasp.test(password);
      if (!result.strong) {
        throw new BadRequestException(
          `Insecure password: ${result.errors.join(" ")}`
        );
      }
    } else if (this.options.strongPasswordValidation) {
      if (password.length < 8) {
        throw new BadRequestException(
          "Insecure password: Minimum 8 characters required."
        );
      }
      if (/^\d+$/.test(password)) {
        throw new BadRequestException("Password cannot be only numbers.");
      }
    }

    const passwordWithPepper = this.options.pepper
      ? password + this.options.pepper
      : password;

    if (algorithm === "argon2") {
      return await argon2.hash(passwordWithPepper);
    }

    return await bcrypt.hash(passwordWithPepper, this.options.saltRounds || 10);
  }

  /**
   * Compare plain password with stored hash. Uses pepper if configured.
   * @param password - Plain password for authentication.
   * @param hash - Stored hash (e.g. from database).
   * @returns True if the password matches, false otherwise.
   */
  async compare(password: string, hash: string): Promise<boolean> {
    const algorithm = this.options.algorithm || "bcrypt";

    const passwordWithPepper = this.options.pepper
      ? password + this.options.pepper
      : password;

    if (algorithm === "argon2") {
      return await argon2.verify(hash, passwordWithPepper);
    }

    return await bcrypt.compare(passwordWithPepper, hash);
  }
}

