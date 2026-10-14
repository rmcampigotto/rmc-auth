import { Module } from "@nestjs/common";
import { JwtModule } from "@nestjs/jwt";
import { AuthOptions } from "../../interfaces/auth.options";
import { MODULE_OPTIONS_TOKEN, ConfigurableModuleClass } from "./auth.module-definition";
import { AuthService } from "./auth.service";
import { AuthOptionsValidator } from "./auth-options.validator";
import { APP_GUARD } from "@nestjs/core";
import { GlobalJwtAuthGuard, JwtAuthGuard } from "../../guards/jwt-auth.guard";
import { GlobalRolesGuard, RolesGuard } from "../../guards/roles.guard";
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
          signOptions: {
            expiresIn: options.expiresIn,
            issuer: options.jwtIssuer,
            audience: options.jwtAudience,
            algorithm: options.jwtAlgorithm ?? "HS256",
          },
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
    {
      provide: 'ENCRYPTION_SERVICE',
      inject: [MODULE_OPTIONS_TOKEN],
      useFactory: (options: AuthOptions) => options.encryptionService,
    },
    // Both guards are no-ops unless `globalLock` is true. Order matters: authentication before roles.
    { provide: APP_GUARD, useClass: GlobalJwtAuthGuard },
    { provide: APP_GUARD, useClass: GlobalRolesGuard },
  ],
  exports: [AuthService, JwtAuthGuard, RolesGuard, MODULE_OPTIONS_TOKEN],
})
export class AuthModule extends ConfigurableModuleClass {};
