import { Module } from '@nestjs/common';
import {
  AuthModule,
  EncryptionModule,
  EncryptionService,
} from 'rmc-auth';
import { UsersService } from './users.service';
import { AuthController, ProfileController } from './auth.controller';

@Module({
  imports: [
    EncryptionModule.register({
      saltRounds: 10,
      strongPasswordValidation: true,
    }),
    AuthModule.registerAsync({
      inject: [UsersService, EncryptionService],
      useFactory: (users: UsersService, encrypt: EncryptionService) => ({
        jwtSecret: process.env.JWT_SECRET || 'example-secret-change-in-production',
        expiresIn: '15m',
        jwtIssuer: 'rmc-auth-example',
        jwtAudience: 'rmc-auth-example',
        identifierField: 'email',
        passwordField: 'password',
        rolesField: 'roles',
        userService: users,
        encryptionService: encrypt,
        globalLock: true,
        useRefreshTokens: true,
        refreshSecret: process.env.JWT_REFRESH_SECRET || 'example-refresh-secret',
        refreshExpiresIn: '7d',
      }),
    }),
  ],
  controllers: [AuthController, ProfileController],
  providers: [UsersService],
})
export class AppModule {}
