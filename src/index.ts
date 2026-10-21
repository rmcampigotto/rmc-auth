// 1. Interfaces and contracts
export * from "./interfaces/auth.options";
export * from "./interfaces/encryption.options";
export * from "./interfaces/user-service.interface";
export * from "./interfaces/encryption-service.interface";

// 1.1 Types (JWT, request user, tokens)
export type {
  JwtPayload,
  RequestUser,
  AuthTokens,
  AuthContext,
  TokenType,
  LoginFailureReason,
  RefreshFailureReason,
  LockoutPolicy,
  PasswordValidationResult,
  PasswordResetToken,
  RefreshSessionInfo,
  AuthResult,
  TwoFactorSetup,
} from "./types/auth.types";

// 1.2 Exceptions
export { TwoFactorRequiredException } from "./exceptions/two-factor-required.exception";

// 2. Main modules
export * from './modules/encryption/encryption.module';
export * from './modules/auth/auth.module';

// 3. Services (for manual injection if needed)
export * from './modules/encryption/encryption.service';
export * from './modules/auth/auth.service';

// 4. Guards (for manual use via @UseGuards)
export * from './guards/jwt-auth.guard';
export * from './guards/roles.guard';
export * from './guards/permissions.guard';
export * from './guards/api-key.guard';

// 5. Decorators (ease of use)
export * from './decorators/public.decorator';
export * from './decorators/roles.decorator';
export * from './decorators/auth.decorator';
export * from './decorators/current-user.decorator';
export * from './decorators/permissions.decorator';
export * from './decorators/api-key.decorator';
export { AuthCtx, getAuthContext } from './decorators/auth-context.decorator';

// 5.1 Ready-made controller
export { createAuthController } from './controllers/auth.controller';
export type { AuthControllerOptions, AuthControllerRoute } from './controllers/auth.controller';

// 6. Constants (for referencing injection tokens)
export { MODULE_OPTIONS_TOKEN as AUTH_OPTIONS_TOKEN } from './modules/auth/auth.module-definition';
export { MODULE_OPTIONS_TOKEN as ENCRYPTION_OPTIONS_TOKEN } from './modules/encryption/encryption.module-definition';

// 7. Security (cybersecurity utilities and defaults)
export { SECURITY_CONSTANTS } from './security/constants';
export { timingSafeEqual } from './security/timing-safe.util';
export { generateSecureToken, hashToken } from './security/token.util';
export { InMemoryLoginRateLimitStore } from './security/login-rate-limit.store';
export type { InMemoryLoginRateLimitStoreOptions } from './security/login-rate-limit.store';
export { InMemoryTokenBlacklistStore } from './security/token-blacklist.store';
export type { ITokenBlacklistStore } from './security/token-blacklist.store';
export {
  generateTotpSecret,
  generateTotp,
  verifyTotp,
  buildOtpAuthUrl,
  base32Encode,
  base32Decode,
} from './security/totp.util';
export type { TotpOptions } from './security/totp.util';
export { generateRecoveryCodes, hashRecoveryCode, normalizeRecoveryCode } from './security/recovery-codes.util';
export { encryptSecret, decryptSecret } from './security/secret-cipher.util';
export { generateApiKey, hashApiKey } from './security/api-key.util';
export type { GeneratedApiKey } from './security/api-key.util';

// 8. Utilities
export { parseDurationToSeconds } from './utils/duration.util';
export { expandRoles, permissionMatches, hasPermission } from './utils/authorization.util';
export { getRequestFromContext } from './utils/request.util';
