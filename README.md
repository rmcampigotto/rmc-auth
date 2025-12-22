# 🛡️ RMC-AUTH

[![NPM Version](https://img.shields.io/npm/v/rmc-auth.svg)](https://www.npmjs.com/package/rmc-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![NestJS](https://img.shields.io/badge/built%20with-NestJS-red.svg)](https://nestjs.com/)

An **out-of-the-box, enterprise-grade** authentication and authorization library for NestJS. Designed to eliminate boilerplate while maintaining maximum security standards.

Features **Bcrypt with Pepper**, **Automated JWT Management**, **Refresh Token Rotation**, **Global Security Locks**, and **Native RBAC**.

## ✨ Key Features

* 🔐 **Automated JWT Management**: Simplified login, token signing, and automated verification.
* 🔄 **Refresh Token Rotation**: Advanced session security that detects and mitigates token theft by invalidating compromised sessions.
* 🛡️ **Global Security Lock**: Toggle `globalLock: true` to protect every route by default, forcing an explicit `@Public()` opt-out.
* 🔑 **Enhanced Bcrypt**: Hashing with optional **Pepper** support and built-in **Strong Password Validation**.
* 🎭 **Native RBAC**: Role-Based Access Control integrated directly into the JWT payload and guarded by a high-performance `RolesGuard`.
* 🔌 **Provider Agnostic**: Works with any database (Prisma, TypeORM, Mongoose) via simple interface injection.

---

## 📦 Installation

```bash
npm install rmc-auth @nestjs/jwt @nestjs/passport passport-jwt bcrypt
npm install --save-dev @types/passport-jwt @types/bcrypt
```

---

## 🛠️ Configuration

### 1. Database Integration
Your existing User Service must implement the `IAuthUserService` interface. This allows the library to communicate with your database regardless of the ORM you use.

```typescript
import { Injectable } from '@nestjs/common';
import { IAuthUserService } from 'your-lib-name';
import { PrismaService } from './prisma.service';

@Injectable()
export class UsersService implements IAuthUserService {
  constructor(private prisma: PrismaService) {}

  // Used for Login
  async findOneByField(field: string, value: any) {
    return this.prisma.user.findFirst({ where: { [field]: value } });
  }

  // Used for Refresh Token Rotation
  async saveRefreshToken(userId: string, token: string) {
    await this.prisma.user.update({ where: { id: userId }, data: { refreshToken: token } });
  }
  
  async isRefreshTokenValid(userId: string, token: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    return user && user.refreshToken === token;
  }

  async revokeAllTokens(userId: string) {
    await this.prisma.user.update({ where: { id: userId }, data: { refreshToken: null } });
  }
}
```

### 2. Module Registration
Initialize the modules in your `AppModule`. We recommend using `registerAsync` to inject configuration.

```typescript
import { Module } from '@nestjs/common';
import { AuthModule, EncryptionModule, EncryptionService } from 'your-lib-name';
import { UsersService } from './users/users.service';

@Module({
  imports: [
    // 1. Configure Encryption (Hashing)
    EncryptionModule.register({
      saltRounds: 12,
      pepper: process.env.AUTH_PEPPER,
      strongPasswordValidation: true,
    }),

    // 2. Configure Auth (JWT + Logic)
    AuthModule.registerAsync({
      inject: [UsersService, EncryptionService],
      useFactory: (users: UsersService, encrypt: EncryptionService) => ({
        // JWT Config
        jwtSecret: process.env.JWT_SECRET,
        expiresIn: 3600, // Short-lived access token
        
        // Database Mapping
        identifierField: 'email',
        passwordField: 'password',
        rolesField: 'roles', // Field in your DB containing user roles
        
        // Dependency Injection
        userService: users,
        encryptionService: encrypt,
        
        // Advanced Security Features
        globalLock: true, // 🛡️ Protects ALL routes by default
        useRefreshTokens: true,
        refreshSecret: process.env.JWT_REFRESH_SECRET,
        refreshExpiresIn: 36000,
      }),
    }),
  ],
})
export class AppModule {}
```

---

## 📖 Usage Guide

### Authentication Controller
Since the library handles the heavy lifting, your controller remains clean.

```typescript
import { Controller, Post, Body } from '@nestjs/common';
import { AuthService, Public } from 'your-lib-name';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public() // 🔓 Opens this route (required if globalLock is true)
  @Post('login')
  async login(@Body() loginDto: any) {
    return this.authService.login(loginDto);
  }

  @Public() // 🔓 Refresh endpoint must also be public to exchange tokens
  @Post('refresh')
  async refresh(@Body('refreshToken') token: string) {
    return this.authService.refresh(token);
  }
}
```

### Authorization (RBAC)
Use `@Authorize()` to restrict access based on user roles.

```typescript
import { Controller, Get } from '@nestjs/common';
import { Authorize } from 'your-lib-name';

@Controller('dashboard')
export class DashboardController {
  
  @Get('admin-stats')
  @Authorize('admin') // 🔒 Only users with 'admin' role can access
  getAdminStats() {
    return { data: 'Sensitive Data' };
  }

  @Get('profile')
  @Authorize('user', 'admin') // 🔒 'user' OR 'admin' roles
  getProfile() {
    return { message: 'Hello User' };
  }
}
```

---

## ⚙️ API Reference

### `AuthOptions` Configuration

| Property | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `jwtSecret` | `string` | ✅ | Secret key to sign Access Tokens. |
| `expiresIn` | ` number` | ✅ | Access Token TTL (e.g., `3600`). |
| `identifierField` | `string` | ✅ | Database field for login (e.g., `'email'`). |
| `passwordField` | `string` | ✅ | Database field for the password hash. |
| `userService` | `IAuthUserService` | ✅ | Instance of your user service. |
| `encryptionService` | `IEncryptionService` | ✅ | Instance of the encryption service. |
| `globalLock` | `boolean` | ❌ | If `true`, all routes require a JWT by default. |
| `useRefreshTokens` | `boolean` | ❌ | Enables Refresh Token generation and rotation. |
| `refreshSecret` | `string` | ❌ | Separate secret for Refresh Tokens (Recommended). |
| `refreshExpiresIn` | `number` | ❌ | Refresh Token TTL (e.g., `3600`). |
| `rolesField` | `string` | ❌ | Field in your User entity containing role strings. Default: `'roles'`. |

### `EncryptionOptions` Configuration

| Property | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `saltRounds` | `number` | `10` | Bcrypt salt cost factor. |
| `pepper` | `string` | `undefined` | Additional secret string. |
| `strongPasswordValidation` | `boolean` | `false` | Enforces minimum length (8) and complexity. |

---

## 🔒 Security Principles

1.  **Fail-Safe by Default**: With `globalLock`, we prevent accidental exposure of sensitive endpoints due to developer oversight. You must explicitly open routes with `@Public()`.
2.  **Generic Error Messages**: Login failures always return a generic `Unauthorized` error to prevent **User Enumeration Attacks**.
3.  **Token Rotation**: When a Refresh Token is used, a new pair (Access + Refresh) is issued. If a stolen token is reused, the library detects the anomaly (via `isRefreshTokenValid`) and revokes the entire session history (`revokeAllTokens`).

---

## 📄 License

Licensed under the [MIT License](LICENSE).