import { Inject, Injectable, Logger, OnModuleInit } from "@nestjs/common";
import { MODULE_OPTIONS_TOKEN } from "./encryption.module-definition";
import type { EncryptionOptions } from "../../interfaces/encryption.options";

function isPositiveInt(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value > 0;
}

@Injectable()
export class EncryptionOptionsValidator implements OnModuleInit {
  private readonly logger = new Logger("EncryptionModule");

  constructor(@Inject(MODULE_OPTIONS_TOKEN) private readonly options: EncryptionOptions) {}

  onModuleInit(): void {
    const algorithm = this.options.algorithm ?? "bcrypt";
    if (algorithm !== "bcrypt" && algorithm !== "argon2") {
      throw new Error("EncryptionModule: 'algorithm' must be 'bcrypt' or 'argon2'.");
    }
    if (algorithm === "bcrypt") {
      const rounds = this.options.saltRounds ?? 10;
      if (typeof rounds !== "number" || rounds < 1 || rounds > 31) {
        throw new Error(
          "EncryptionModule: 'saltRounds' must be a number between 1 and 31 when using bcrypt."
        );
      }
    }
    const argon = this.options.argon2Options;
    if (argon) {
      if (argon.memoryCost != null && (!isPositiveInt(argon.memoryCost) || argon.memoryCost < 1024)) {
        throw new Error("EncryptionModule: 'argon2Options.memoryCost' must be an integer >= 1024 (KiB).");
      }
      if (argon.timeCost != null && !isPositiveInt(argon.timeCost)) {
        throw new Error("EncryptionModule: 'argon2Options.timeCost' must be a positive integer.");
      }
      if (argon.parallelism != null && !isPositiveInt(argon.parallelism)) {
        throw new Error("EncryptionModule: 'argon2Options.parallelism' must be a positive integer.");
      }
    }
    if (this.options.pepper != null && typeof this.options.pepper !== "string") {
      throw new Error("EncryptionModule: 'pepper' must be a string.");
    }
    if (this.options.pepperStrategy && !["append", "hmac"].includes(this.options.pepperStrategy)) {
      throw new Error("EncryptionModule: 'pepperStrategy' must be 'append' or 'hmac'.");
    }
    if (algorithm === "bcrypt" && this.options.pepper && (this.options.pepperStrategy ?? "append") === "append") {
      this.logger.warn(
        "'pepper' with pepperStrategy 'append' and bcrypt: input over 72 bytes is truncated, so long passwords lose the pepper. Use pepperStrategy: 'hmac' for new projects."
      );
    }
    const policy = this.options.passwordPolicy;
    if (policy) {
      const min = policy.minLength ?? 8;
      const max = policy.maxLength ?? 128;
      if (!isPositiveInt(min) || !isPositiveInt(max) || min > max) {
        throw new Error("EncryptionModule: 'passwordPolicy' minLength/maxLength must be positive integers with minLength <= maxLength.");
      }
    }
  }
}
