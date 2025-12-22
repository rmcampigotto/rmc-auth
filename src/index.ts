// 1. Interfaces e Contratos
export * from './interfaces/auth.options';
export * from './interfaces/encryption.options';
export * from './interfaces/user-service.interface';
export * from './interfaces/encryption-service.interface';

// 2. Módulos Principais
export * from './modules/encryption/encryption.module';
export * from './modules/auth/auth.module';

// 3. Serviços (Caso o usuário queira injetá-los manualmente)
export * from './modules/encryption/encryption.service';
export * from './modules/auth/auth.service';

// 4. Guards (Para uso manual via @UseGuards)
export * from './guards/jwt-auth.guard';
export * from './guards/roles.guard';

// 5. Decorators (O coração da facilidade de uso)
export * from './decorators/public.decorator';
export * from './decorators/roles.decorator';
export * from './decorators/auth.decorator';

// 6. Constantes (Caso o usuário precise referenciar tokens de injeção)
export { MODULE_OPTIONS_TOKEN as AUTH_OPTIONS_TOKEN } from './modules/auth/auth.module-definition';
export { MODULE_OPTIONS_TOKEN as ENCRYPTION_OPTIONS_TOKEN } from './modules/encryption/encryption.module-definition';