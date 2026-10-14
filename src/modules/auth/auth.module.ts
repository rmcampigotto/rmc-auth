import { Module } from "@nestjs/common";
import { JwtModule } from "@nestjs/jwt";
import { AuthOptions } from "../../interfaces/auth.options";
import { MODULE_OPTIONS_TOKEN, ConfigurableModuleClass } from "./auth.module-definition";
import { AuthService } from "./auth.service";
import { AuthOptionsValidator } from "./auth-options.validator";
import { APP_GUARD } from "@nestjs/core";
import { GlobalJwtAuthGuard, JwtAuthGuard } from "../../guards/jwt-auth.guard";
import { GlobalRolesGuard, RolesGuard } from "../../guards/roles.guard";
import { GlobalPermissionsGuard, PermissionsGuard } from "../../guards/permissions.guard";
import { JwtStrategy } from "../../strategies/jwt.strategy";
import { PassportModule } from "@nestjs/passport";

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      inject: [MODULE_OPTIONS_TOKEN],
      useFactory: (options: AuthOptions) =>
        ({
          secret: options.jwtSecret,
          // Undefined keys are dropped: jsonwebtoken rejects e.g. `issuer: undefined`.
          signOptions: Object.fromEntries(
            Object.entries({
              expiresIn: options.expiresIn,
              issuer: options.jwtIssuer,
              audience: options.jwtAudience,
              algorithm: options.jwtAlgorithm ?? "HS256",
            }).filter(([, v]) => v !== undefined)
          ),
          verifyOptions: {
            algorithms: [options.jwtAlgorithm ?? "HS256"],
          },
        }) as import("@nestjs/jwt").JwtModuleOptions,
    }),
  ],
  providers: [
    AuthOptionsValidator,
    AuthService,
    JwtStrategy,
    JwtAuthGuard,
    RolesGuard,
    PermissionsGuard,
    {
      provide: 'ENCRYPTION_SERVICE',
      inject: [MODULE_OPTIONS_TOKEN],
      useFactory: (options: AuthOptions) => options.encryptionService,
    },
    // Global guards are no-ops unless `globalLock` is true. Order matters: authentication before authorization.
    { provide: APP_GUARD, useClass: GlobalJwtAuthGuard },
    { provide: APP_GUARD, useClass: GlobalRolesGuard },
    { provide: APP_GUARD, useClass: GlobalPermissionsGuard },
  ],
  exports: [AuthService, JwtAuthGuard, RolesGuard, PermissionsGuard, MODULE_OPTIONS_TOKEN],
})
export class AuthModule extends ConfigurableModuleClass {};
