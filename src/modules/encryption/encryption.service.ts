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
   * Hash function configurável (bcrypt por padrão, opcionalmente Argon2).
   * Pepper option utilization if informed in setup.
   * @param {string} password - Password value. StrongPasswordValidation or OWASP policy if informed in setup.
   * @returns {Promise<string>} - Crypt version of the password (Promise).
   */
  async hash(password: string): Promise<string> {
    if (!password) throw new Error("Password is required");

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
   * Compare function. Pepper option utilization if informed in the setup.
   * @param {string} password - Password value for authentication.
   * @param {string} hash - Crypted password stored in the login system (db for example).
   * @returns {Promise<boolean>} - True if the password matches, false if not (Promise).
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

