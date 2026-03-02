import { Module } from "@nestjs/common";
import { JwtModule } from "@nestjs/jwt";
import { AuthOptions } from "../../interfaces/auth.options";
import { MODULE_OPTIONS_TOKEN, ConfigurableModuleClass } from "./auth.module-definition";
import { AuthService } from "./auth.service";
import { Reflector, APP_GUARD } from "@nestjs/core";
import { JwtAuthGuard } from "../../guards/jwt-auth.guard";
import { JwtStrategy } from "../../strategies/jwt.strategy";
import { PassportModule } from "@nestjs/passport";

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      inject: [MODULE_OPTIONS_TOKEN],
      useFactory: (options: AuthOptions) => ({
        secret: options.jwtSecret,
        signOptions: {
          expiresIn: options.expiresIn as any,
          issuer: options.jwtIssuer,
          audience: options.jwtAudience,
        },
      }),
    }),
  ],
  providers: [
    AuthService,
    JwtStrategy,
    {
      provide: 'ENCRYPTION_SERVICE',
      inject: [MODULE_OPTIONS_TOKEN],
      useFactory: (options: AuthOptions) => options.encryptionService,
    },
    {
      provide: APP_GUARD,
      inject: [MODULE_OPTIONS_TOKEN, Reflector],
      useFactory: (options: AuthOptions, reflector: Reflector) => {
        return options.globalLock ? new JwtAuthGuard(reflector, options) : null;
      },
    },
  ],
  exports: [AuthService],
})
export class AuthModule extends ConfigurableModuleClass {};