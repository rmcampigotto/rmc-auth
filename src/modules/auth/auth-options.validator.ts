import { Inject, Injectable, OnModuleInit } from "@nestjs/common";
import { MODULE_OPTIONS_TOKEN } from "./auth.module-definition";
import type { AuthOptions } from "../../interfaces/auth.options";
import { SECURITY_CONSTANTS } from "../../security/constants";

const REQUIRED_STRING_MSG = "AuthModule: missing required option";

function parseExpiresInToSeconds(expiresIn: string | number): number {
  if (typeof expiresIn === "number") return expiresIn;
  const match = expiresIn.match(/^(\d+)(s|m|h|d)$/);
  if (!match) return 3600;
  const n = parseInt(match[1], 10);
  const unit = match[2];
  if (unit === "s") return n;
  if (unit === "m") return n * 60;
  if (unit === "h") return n * 3600;
  if (unit === "d") return n * 86400;
  return 3600;
}

@Injectable()
export class AuthOptionsValidator implements OnModuleInit {
  constructor(@Inject(MODULE_OPTIONS_TOKEN) private readonly options: AuthOptions) {}

  onModuleInit(): void {
    if (!this.options.jwtSecret || typeof this.options.jwtSecret !== "string") {
      throw new Error(`${REQUIRED_STRING_MSG} 'jwtSecret'.`);
    }
    if (this.options.strictMode && this.options.jwtSecret.length < SECURITY_CONSTANTS.MIN_JWT_SECRET_LENGTH) {
      throw new Error(
        `AuthModule (strictMode): 'jwtSecret' must be at least ${SECURITY_CONSTANTS.MIN_JWT_SECRET_LENGTH} characters.`
      );
    }
    if (this.options.expiresIn === undefined || this.options.expiresIn === null) {
      throw new Error("AuthModule: missing required option 'expiresIn'.");
    }
    if (this.options.strictMode) {
      const seconds = parseExpiresInToSeconds(this.options.expiresIn);
      if (seconds > SECURITY_CONSTANTS.STRICT_MODE_MAX_EXPIRES_IN_SECONDS) {
        throw new Error(
          `AuthModule (strictMode): 'expiresIn' must not exceed ${SECURITY_CONSTANTS.STRICT_MODE_MAX_EXPIRES_IN_SECONDS} seconds (1 hour).`
        );
      }
      if (!this.options.jwtIssuer || !this.options.jwtAudience) {
        throw new Error("AuthModule (strictMode): 'jwtIssuer' and 'jwtAudience' are required.");
      }
    }
    if (!this.options.identifierField || typeof this.options.identifierField !== "string") {
      throw new Error(`${REQUIRED_STRING_MSG} 'identifierField'.`);
    }
    if (!this.options.passwordField || typeof this.options.passwordField !== "string") {
      throw new Error(`${REQUIRED_STRING_MSG} 'passwordField'.`);
    }
    if (!this.options.userService || typeof this.options.userService.findOneByField !== "function") {
      throw new Error("AuthModule: missing or invalid 'userService' (must implement findOneByField).");
    }
    if (!this.options.encryptionService || typeof this.options.encryptionService.compare !== "function") {
      throw new Error("AuthModule: missing or invalid 'encryptionService' (must implement compare).");
    }
    if (this.options.useRefreshTokens) {
      if (!this.options.userService.saveRefreshToken) {
        throw new Error(
          "AuthModule: 'useRefreshTokens' is true but userService does not implement 'saveRefreshToken'."
        );
      }
    }
    if (
      this.options.lockoutMaxAttempts != null &&
      (this.options.userService.getLockoutUntil == null ||
        this.options.userService.recordFailedLogin == null ||
        this.options.userService.clearFailedLogin == null)
    ) {
      throw new Error(
        "AuthModule: 'lockoutMaxAttempts' requires userService to implement getLockoutUntil, recordFailedLogin, and clearFailedLogin."
      );
    }
  }
}
