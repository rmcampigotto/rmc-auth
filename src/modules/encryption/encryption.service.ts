import { Injectable, Inject, BadRequestException } from "@nestjs/common";
import { createHmac } from "crypto";
import type { EncryptionOptions } from "../../interfaces/encryption.options";
import type { IEncryptionService } from "../../interfaces/encryption-service.interface";
import type { PasswordValidationResult } from "../../types/auth.types";
import { MODULE_OPTIONS_TOKEN } from "./encryption.module-definition";
import * as bcrypt from "bcrypt";
import * as argon2 from "argon2";
import owasp from "owasp-password-strength-test";

/** bcrypt ignores every byte after the 72nd. */
const BCRYPT_MAX_BYTES = 72;

const ARGON2_TYPES = { argon2d: argon2.argon2d, argon2i: argon2.argon2i, argon2id: argon2.argon2id } as const;

type HashAlgorithm = "bcrypt" | "argon2";

function detectAlgorithm(hash: string): HashAlgorithm | null {
  if (/^\$2[abxy]?\$/.test(hash)) return "bcrypt";
  if (hash.startsWith("$argon2")) return "argon2";
  return null;
}

@Injectable()
export class EncryptionService implements IEncryptionService {
  private dummyHash: Promise<string> | null = null;

  constructor(
    @Inject(MODULE_OPTIONS_TOKEN) private options: EncryptionOptions
  ) {}

  private get algorithm(): HashAlgorithm {
    return this.options.algorithm || "bcrypt";
  }

  private get saltRounds(): number {
    return this.options.saltRounds || 10;
  }

  private get argon2HashOptions(): argon2.Options {
    const o = this.options.argon2Options ?? {};
    return {
      type: ARGON2_TYPES[o.type ?? "argon2id"],
      memoryCost: o.memoryCost ?? 65536,
      timeCost: o.timeCost ?? 3,
      parallelism: o.parallelism ?? 4,
    };
  }

  private applyPepper(password: string): string {
    const { pepper, pepperStrategy } = this.options;
    if (!pepper) return password;
    if (pepperStrategy === "hmac") {
      return createHmac("sha256", pepper).update(password, "utf8").digest("base64");
    }
    return password + pepper;
  }

  private async hashRaw(password: string): Promise<string> {
    const input = this.applyPepper(password);
    if (this.algorithm === "argon2") {
      return await argon2.hash(input, this.argon2HashOptions);
    }
    return await bcrypt.hash(input, this.saltRounds);
  }

  /**
   * Validates a password against the configured policy (OWASP, `passwordPolicy` or `strongPasswordValidation`)
   * without hashing it. Useful to give feedback in sign-up forms.
   */
  validatePassword(password: string): PasswordValidationResult {
    if (typeof password !== "string" || !password) {
      return { valid: false, errors: ["Password is required."] };
    }

    const errors: string[] = [];
    // Passwords that only differ after byte 72 would produce the same bcrypt hash. HMAC pepper has a fixed length.
    if (
      this.algorithm === "bcrypt" &&
      !(this.options.pepper && this.options.pepperStrategy === "hmac") &&
      Buffer.byteLength(password, "utf8") > BCRYPT_MAX_BYTES
    ) {
      errors.push(`Maximum ${BCRYPT_MAX_BYTES} bytes allowed.`);
    }

    if (this.options.useOwaspPolicy) {
      const result = owasp.test(password);
      errors.push(...(result.strong ? [] : result.errors));
      return { valid: errors.length === 0, errors };
    }

    const policy = this.options.passwordPolicy;

    if (policy) {
      const minLength = policy.minLength ?? 8;
      const maxLength = policy.maxLength ?? 128;
      if (password.length < minLength) errors.push(`Minimum ${minLength} characters required.`);
      if (password.length > maxLength) errors.push(`Maximum ${maxLength} characters allowed.`);
      if (policy.requireUppercase && !/[A-Z]/.test(password)) errors.push("At least one uppercase letter required.");
      if (policy.requireLowercase && !/[a-z]/.test(password)) errors.push("At least one lowercase letter required.");
      if (policy.requireNumber && !/\d/.test(password)) errors.push("At least one number required.");
      if (policy.requireSymbol && !/[^A-Za-z0-9]/.test(password)) errors.push("At least one symbol required.");
      if ((policy.disallowOnlyNumbers ?? true) && /^\d+$/.test(password)) {
        errors.push("Password cannot be only numbers.");
      }
      if (policy.blacklist?.some((b) => b.toLowerCase() === password.toLowerCase())) {
        errors.push("Password is too common.");
      }
    } else if (this.options.strongPasswordValidation) {
      if (password.length < 8) errors.push("Minimum 8 characters required.");
      if (/^\d+$/.test(password)) errors.push("Password cannot be only numbers.");
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Configurable hash function (bcrypt by default, optionally Argon2).
   * Uses pepper if configured in setup.
   * @param password - Plain password. Password policy and breach check applied if configured.
   * @returns Hashed password.
   */
  async hash(password: string): Promise<string> {
    if (!password) throw new Error("Password is required");

    const validation = this.validatePassword(password);
    if (!validation.valid) {
      throw new BadRequestException(`Insecure password: ${validation.errors.join(" ")}`);
    }

    if (this.options.checkPasswordBreach) {
      const breached = await this.options.checkPasswordBreach(password);
      if (breached) {
        throw new BadRequestException("This password has been found in a data breach. Choose a different password.");
      }
    }

    return this.hashRaw(password);
  }

  /**
   * Compare plain password with stored hash. Uses pepper if configured.
   * The algorithm is detected from the hash itself, so bcrypt and argon2 hashes can coexist during a migration.
   * Never throws for malformed hashes: returns false instead.
   * @param password - Plain password for authentication.
   * @param hash - Stored hash (e.g. from database).
   * @returns True if the password matches, false otherwise.
   */
  async compare(password: string, hash: string): Promise<boolean> {
    if (typeof password !== "string" || typeof hash !== "string" || !hash) return false;
    const algorithm = detectAlgorithm(hash) ?? this.algorithm;
    const input = this.applyPepper(password);

    try {
      if (algorithm === "argon2") {
        return await argon2.verify(hash, input);
      }
      return await bcrypt.compare(input, hash);
    } catch {
      return false;
    }
  }

  /**
   * Returns true when the hash was generated with a different algorithm or weaker parameters than the
   * current configuration. Re-hash the password after a successful login when this returns true.
   */
  needsRehash(hash: string): boolean {
    if (typeof hash !== "string") return false;
    const detected = detectAlgorithm(hash);
    if (!detected) return false;
    if (detected !== this.algorithm) return true;

    try {
      if (detected === "bcrypt") {
        return bcrypt.getRounds(hash) < this.saltRounds;
      }
      const { memoryCost, timeCost, parallelism } = this.argon2HashOptions;
      return argon2.needsRehash(hash, { memoryCost, timeCost, parallelism });
    } catch {
      return false;
    }
  }

  /**
   * Runs a comparison against a dummy hash with the configured cost and always resolves to false.
   * Equalizes response time between "user not found" and "wrong password" (prevents user enumeration).
   */
  async compareDummy(password: string): Promise<false> {
    if (!this.dummyHash) {
      this.dummyHash = this.hashRaw("rmc-auth-dummy-password");
    }
    await this.compare(typeof password === "string" ? password : "", await this.dummyHash);
    return false;
  }
}
