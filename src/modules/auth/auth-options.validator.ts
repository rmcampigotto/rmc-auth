import { Inject, Injectable, OnModuleInit } from "@nestjs/common";
import { MODULE_OPTIONS_TOKEN } from "./auth.module-definition";
import type { AuthOptions } from "../../interfaces/auth.options";
import { SECURITY_CONSTANTS } from "../../security/constants";
import { parseDurationToSeconds } from "../../utils/duration.util";

const REQUIRED_STRING_MSG = "AuthModule: missing required option";
const ALGORITHMS = ["HS256", "HS384", "HS512"];

function parseDurationOption(name: string, value: string | number): number {
  try {
    return parseDurationToSeconds(value);
  } catch {
    throw new Error(`AuthModule: invalid '${name}' (${String(value)}). Use seconds or a string like '15m', '1h', '7d'.`);
  }
}

function assertPositiveInt(name: string, value: number | undefined): void {
  if (value != null && (!Number.isInteger(value) || value <= 0)) {
    throw new Error(`AuthModule: '${name}' must be a positive integer.`);
  }
}

@Injectable()
export class AuthOptionsValidator implements OnModuleInit {
  constructor(@Inject(MODULE_OPTIONS_TOKEN) private readonly options: AuthOptions) {}

  onModuleInit(): void {
    const o = this.options;
    if (!o.jwtSecret || typeof o.jwtSecret !== "string") {
      throw new Error(`${REQUIRED_STRING_MSG} 'jwtSecret'.`);
    }
    if (o.strictMode && o.jwtSecret.length < SECURITY_CONSTANTS.MIN_JWT_SECRET_LENGTH) {
      throw new Error(
        `AuthModule (strictMode): 'jwtSecret' must be at least ${SECURITY_CONSTANTS.MIN_JWT_SECRET_LENGTH} characters.`
      );
    }
    if (o.expiresIn === undefined || o.expiresIn === null) {
      throw new Error("AuthModule: missing required option 'expiresIn'.");
    }
    const accessSeconds = parseDurationOption("expiresIn", o.expiresIn);
    if (o.refreshExpiresIn != null) {
      parseDurationOption("refreshExpiresIn", o.refreshExpiresIn);
    }
    if (o.jwtAlgorithm && !ALGORITHMS.includes(o.jwtAlgorithm)) {
      throw new Error(`AuthModule: 'jwtAlgorithm' must be one of ${ALGORITHMS.join(", ")}.`);
    }
    if (o.strictMode) {
      if (accessSeconds > SECURITY_CONSTANTS.STRICT_MODE_MAX_EXPIRES_IN_SECONDS) {
        throw new Error(
          `AuthModule (strictMode): 'expiresIn' must not exceed ${SECURITY_CONSTANTS.STRICT_MODE_MAX_EXPIRES_IN_SECONDS} seconds (1 hour).`
        );
      }
      if (!o.jwtIssuer || !o.jwtAudience) {
        throw new Error("AuthModule (strictMode): 'jwtIssuer' and 'jwtAudience' are required.");
      }
      if (o.useRefreshTokens) {
        if (!o.refreshSecret || o.refreshSecret === o.jwtSecret) {
          throw new Error("AuthModule (strictMode): 'refreshSecret' is required and must differ from 'jwtSecret'.");
        }
        if (o.refreshSecret.length < SECURITY_CONSTANTS.MIN_JWT_SECRET_LENGTH) {
          throw new Error(
            `AuthModule (strictMode): 'refreshSecret' must be at least ${SECURITY_CONSTANTS.MIN_JWT_SECRET_LENGTH} characters.`
          );
        }
      }
    }
    if (!o.identifierField || typeof o.identifierField !== "string") {
      throw new Error(`${REQUIRED_STRING_MSG} 'identifierField'.`);
    }
    if (!o.passwordField || typeof o.passwordField !== "string") {
      throw new Error(`${REQUIRED_STRING_MSG} 'passwordField'.`);
    }
    if (!o.userService || typeof o.userService.findOneByField !== "function") {
      throw new Error("AuthModule: missing or invalid 'userService' (must implement findOneByField).");
    }
    if (!o.encryptionService || typeof o.encryptionService.compare !== "function") {
      throw new Error("AuthModule: missing or invalid 'encryptionService' (must implement compare).");
    }
    if (o.useRefreshTokens) {
      if (!o.userService.saveRefreshToken) {
        throw new Error(
          "AuthModule: 'useRefreshTokens' is true but userService does not implement 'saveRefreshToken'."
        );
      }
    }
    assertPositiveInt("lockoutMaxAttempts", o.lockoutMaxAttempts);
    assertPositiveInt("lockoutDurationMinutes", o.lockoutDurationMinutes);
    assertPositiveInt("rateLimitMaxAttempts", o.rateLimitMaxAttempts);
    assertPositiveInt("rateLimitWindowMs", o.rateLimitWindowMs);
    assertPositiveInt("maxIdentifierLength", o.maxIdentifierLength);
    assertPositiveInt("maxPasswordLength", o.maxPasswordLength);
    if (o.clockToleranceSeconds != null && (typeof o.clockToleranceSeconds !== "number" || o.clockToleranceSeconds < 0)) {
      throw new Error("AuthModule: 'clockToleranceSeconds' must be a number >= 0.");
    }
    if (
      o.lockoutMaxAttempts != null &&
      (o.userService.getLockoutUntil == null ||
        o.userService.recordFailedLogin == null ||
        o.userService.clearFailedLogin == null)
    ) {
      throw new Error(
        "AuthModule: 'lockoutMaxAttempts' requires userService to implement getLockoutUntil, recordFailedLogin, and clearFailedLogin."
      );
    }
  }
}
