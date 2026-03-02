// 1. Interfaces and contracts
export * from "./interfaces/auth.options";
export * from "./interfaces/encryption.options";
export * from "./interfaces/user-service.interface";
export * from "./interfaces/encryption-service.interface";

// 1.1 Types (JWT, request user, tokens)
export type { JwtPayload, RequestUser, AuthTokens } from "./types/auth.types";

// 2. Main modules
export * from './modules/encryption/encryption.module';
export * from './modules/auth/auth.module';

// 3. Services (for manual injection if needed)
export * from './modules/encryption/encryption.service';
export * from './modules/auth/auth.service';

// 4. Guards (for manual use via @UseGuards)
export * from './guards/jwt-auth.guard';
export * from './guards/roles.guard';

// 5. Decorators (ease of use)
export * from './decorators/public.decorator';
export * from './decorators/roles.decorator';
export * from './decorators/auth.decorator';

// 6. Constants (for referencing injection tokens)
export { MODULE_OPTIONS_TOKEN as AUTH_OPTIONS_TOKEN } from './modules/auth/auth.module-definition';
export { MODULE_OPTIONS_TOKEN as ENCRYPTION_OPTIONS_TOKEN } from './modules/encryption/encryption.module-definition';

// 7. Security (cybersecurity utilities and defaults)
export { SECURITY_CONSTANTS } from './security/constants';
export { timingSafeEqual } from './security/timing-safe.util';
export { InMemoryLoginRateLimitStore } from './security/login-rate-limit.store';