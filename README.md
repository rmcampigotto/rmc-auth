# 🛡️ RMC-AUTH

[![NPM Version](https://img.shields.io/npm/v/rmc-auth.svg)](https://www.npmjs.com/package/rmc-auth)
[![CI](https://github.com/rmcampigotto/rmc-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/rmcampigotto/rmc-auth/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![NestJS](https://img.shields.io/badge/built%20with-NestJS-red.svg)](https://nestjs.com/)

An **out-of-the-box, enterprise-grade** authentication and authorization library for NestJS.  
Designed to eliminate boilerplate while maintaining **maximum security standards**.

This library focuses on:

- **Password safety**: Bcrypt with pepper or Argon2, plus optional OWASP password-strength policy.
- **Token safety**: Short-lived JWTs, issuer/audience validation, and refresh token rotation.
- **Access control**: First-class RBAC (roles), global route locking and explicit public endpoints.

## ✨ Key Features

- 🔐 **Automated JWT Management**: Simplified login, token signing, and automated verification.
- 🔄 **Refresh Token Rotation**: Advanced session security that detects and mitigates token theft by invalidating compromised sessions.
- 🛡️ **Global Security Lock**: Toggle `globalLock: true` to protect every route by default, forcing an explicit `@Public()` opt-out.
- 🔑 **Configurable Hashing**: **Bcrypt (default)** or **Argon2**, with optional **Pepper** and **OWASP Password Policy**.
- 🎭 **Native RBAC**: Role-Based Access Control integrated directly into the JWT payload and guarded by a high-performance `RolesGuard`.
- 🔌 **Provider Agnostic**: Works with any database (Prisma, TypeORM, Mongoose, raw SQL) via simple interface injection.

---

## 📦 Installation

```bash
npm install rmc-auth @nestjs/jwt @nestjs/passport passport-jwt bcrypt argon2 owasp-password-strength-test
npm install --save-dev @types/passport-jwt @types/bcrypt
```

> **Node**: Node 18+ (Argon2 & toolchain).

A **minimal runnable example** is in [`examples/minimal`](examples/minimal).

---

## 🛠️ Configuration (Step by Step)

### 1. Implement `IAuthUserService` (database integration)

Your existing User Service must implement the `IAuthUserService` interface.  
This allows the library to communicate with your database regardless of the ORM you use.

```typescript
import { Injectable } from '@nestjs/common';
import { IAuthUserService } from 'rmc-auth';
import { PrismaService } from './prisma.service';

@Injectable()
export class UsersService implements IAuthUserService {
  constructor(private prisma: PrismaService) {}

  // Used for Login
  async findOneByField(field: string, value: unknown) {
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

### 2. Register Modules (Encryption + Auth)

RMC-AUTH is split into two modules:

- `EncryptionModule`: password hashing (bcrypt or argon2, pepper, password policy).
- `AuthModule`: JWT, refresh tokens, guards, roles and integration with your `UserService`.

#### 2.1. Basic setup (Bcrypt + strong validation)

```typescript
import { Module } from '@nestjs/common';
import { AuthModule, EncryptionModule, EncryptionService } from 'rmc-auth';
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
        expiresIn: '15m', // Short-lived access token
        jwtIssuer: 'my-api',
        jwtAudience: 'my-api-clients',

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
        refreshExpiresIn: '7d',
      }),
    }),
  ],
})
export class AppModule {}
```

#### 2.2. Maximum hardening (Argon2 + OWASP)

```typescript
EncryptionModule.register({
  algorithm: 'argon2',
  pepper: process.env.AUTH_PEPPER,
  // Use OWASP policy instead of simple validation
  useOwaspPolicy: true,
});

AuthModule.registerAsync({
  inject: [UsersService, EncryptionService],
  useFactory: (users: UsersService, encrypt: EncryptionService) => ({
    jwtSecret: process.env.JWT_SECRET,
    expiresIn: '10m',
    jwtIssuer: 'my-secure-api',
    jwtAudience: 'my-secure-clients',

    identifierField: 'email',
    passwordField: 'passwordHash',
    rolesField: 'roles',

    userService: users,
    encryptionService: encrypt,

    globalLock: true,
    useRefreshTokens: true,
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    refreshExpiresIn: '3d',
    refreshIssuer: 'my-secure-api-rt',
    refreshAudience: 'my-secure-clients',
  }),
});
```

---

## 📖 Usage Guide

### 3. Authentication Controller

Expose login and refresh; use `@Public()` so these routes are not protected by the global JWT guard.

```typescript
import { Controller, Post, Body } from '@nestjs/common';
import { AuthService, Public } from 'rmc-auth';

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

### 4. Authorization (RBAC)

Use `@Authorize()` to restrict access based on user roles.

```typescript
import { Controller, Get } from '@nestjs/common';
import { Authorize } from 'rmc-auth';

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

| Property            | Type                          | Required | Description                                                                 |
| :------------------ | :---------------------------- | :------- | :-------------------------------------------------------------------------- |
| `jwtSecret`         | `string`                      | ✅       | Secret key to sign Access Tokens.                                           |
| `expiresIn`         | `string \| number`            | ✅       | Access Token TTL (e.g., `3600`, `'15m'`).                                   |
| `identifierField`   | `string`                      | ✅       | Database field for login (e.g., `'email'`).                                 |
| `passwordField`     | `string`                      | ✅       | Database field for the password hash.                                       |
| `rolesField`        | `string`                      | ❌       | Field in your User entity containing role strings. Default: `'roles'`.      |
| `userService`       | `IAuthUserService`            | ✅       | Instance of your user service.                                              |
| `encryptionService` | `IEncryptionService`          | ✅       | Instance of the encryption service.                                         |
| `globalLock`        | `boolean`                     | ❌       | If `true`, all routes require a JWT by default.                             |
| `useRefreshTokens`  | `boolean`                     | ❌       | Enables Refresh Token generation and rotation.                              |
| `refreshSecret`     | `string`                      | ❌       | Separate secret for Refresh Tokens (recommended).                           |
| `refreshExpiresIn`  | `string \| number`            | ❌       | Refresh Token TTL (e.g., `3600`, `'7d'`).                                   |
| `jwtIssuer`         | `string`                      | ❌       | JWT `iss` claim for access tokens.                                          |
| `jwtAudience`       | `string`                      | ❌       | JWT `aud` claim for access tokens.                                          |
| `refreshIssuer`     | `string`                      | ❌       | `iss` claim for refresh tokens (fallback: `jwtIssuer`).                     |
| `refreshAudience`   | `string`                      | ❌       | `aud` claim for refresh tokens (fallback: `jwtAudience`).                   |

### `EncryptionOptions` Configuration

| Property               | Type                            | Default     | Description                                                                 |
| :--------------------- | :------------------------------ | :---------- | :-------------------------------------------------------------------------- |
| `saltRounds`           | `number`                        | `10`        | Bcrypt salt cost factor (only for `algorithm: 'bcrypt'`).                   |
| `pepper`               | `string`                        | `undefined` | Additional secret string appended to the password before hashing.           |
| `strongPasswordValidation` | `boolean`                   | `false`     | Enforces minimum length (8) and disallows passwords with only numbers.      |
| `algorithm`            | `'bcrypt' \| 'argon2'`          | `'bcrypt'`  | Hashing algorithm used for `hash` / `compare`.                              |
| `useOwaspPolicy`       | `boolean`                       | `false`     | If `true`, enforces OWASP password-strength rules instead of simple checks. |

### Exported types (TypeScript)

- `JwtPayload` — JWT claims after verification (`sub`, `username`, `roles?`). Use when decoding tokens or typing payloads.
- `RequestUser` — Object attached to `request.user` after JWT validation (`id`, `username`, `roles?`). Use to type route handlers.
- `AuthTokens` — Return type of `login()` and `refresh()`: `{ accessToken: string; refreshToken: string | null }`.

Example:

```typescript
import { RequestUser } from 'rmc-auth';

@Get('me')
getProfile(@Request() req: { user: RequestUser }) {
  return { id: req.user.id, username: req.user.username, roles: req.user.roles };
}
```

### Guards and decorators

| Export           | Description |
|------------------|-------------|
| `@Public()`      | Marks a route as public (no JWT required). Use when `globalLock` is `true`. |
| `@Authorize(...roles)` | Restricts access to users that have at least one of the given roles. Composes `JwtAuthGuard` + `RolesGuard`. |
| `Roles(...roles)` | Metadata for roles; used by `RolesGuard`. |
| `JwtAuthGuard`    | Guard that validates the JWT and attaches the user to the request. |
| `RolesGuard`      | Guard that checks the user has one of the required roles. |

### Interfaces

- `IAuthUserService` — Implement to plug your user/database layer.
- `IEncryptionService` — Implemented by `EncryptionService`; inject when using `AuthModule.registerAsync`.

These allow you to plug in **your own services** while keeping RMC-AUTH fully type-safe and testable.

---

## 🔒 Security Principles

1. **Fail-Safe by Default**: With `globalLock`, we prevent accidental exposure of sensitive endpoints due to developer oversight. You must explicitly open routes with `@Public()`.
2. **Generic Error Messages**: Login failures always return a generic `Unauthorized` error to prevent **User Enumeration Attacks**.
3. **Token Rotation**: When a Refresh Token is used, a new pair (Access + Refresh) is issued. If a stolen token is reused, the library detects the anomaly (via `isRefreshTokenValid`) and revokes the entire session history (`revokeAllTokens`).
4. **Strong Passwords by Design**: You can start with simple rules (`strongPasswordValidation`) and evolve to **OWASP policy + Argon2** without breaking your API.

---

## 🛡️ Cybersecurity Features

RMC-AUTH embeds industry-standard security controls so your app stays secure by default:

| Feature | Description |
|--------|-------------|
| **Input validation** | Identifier and password are length-capped (default 256 / 1024 chars) to prevent DoS. Invalid or oversized input returns `BadRequestException` with a generic message. |
| **Strict mode** | Set `strictMode: true` to enforce: JWT secret ≥ 32 chars, `jwtIssuer` and `jwtAudience` required, access token TTL ≤ 1 hour. |
| **Account lockout** | Optional: implement `getLockoutUntil`, `recordFailedLogin`, and `clearFailedLogin` on your user service and set `lockoutMaxAttempts` and `lockoutDurationMinutes`. Failed logins are recorded; successful login clears the counter. |
| **Login rate limiting** | Optional: provide `rateLimitStore` (e.g. `InMemoryLoginRateLimitStore`) and set `rateLimitMaxAttempts` / `rateLimitWindowMs`. Returns `429 Too Many Requests` when exceeded. |
| **Security audit hooks** | Optional callbacks: `onLoginSuccess`, `onLoginFailure`, `onRefreshSuccess`, `onRefreshFailure` for logging and SIEM. Do not throw inside them. |
| **Refresh token validation** | Refresh token string is checked for type, non-empty, and max length before verification to avoid abuse. |
| **Timing-safe comparison** | Export `timingSafeEqual(a, b)` for use in your `isRefreshTokenValid` to prevent timing attacks when comparing tokens. |
| **Password breach check** | Optional: set `checkPasswordBreach: async (password) => boolean` in `EncryptionModule` (e.g. HIBP k-anonymity). Rejects compromised passwords before hashing. |

**Example (strict mode + rate limit + hooks):**

```typescript
AuthModule.registerAsync({
  inject: [UsersService, EncryptionService],
  useFactory: (users: UsersService, encrypt: EncryptionService) => ({
    jwtSecret: process.env.JWT_SECRET,
    expiresIn: '15m',
    jwtIssuer: 'my-api',
    jwtAudience: 'my-api-clients',
    identifierField: 'email',
    passwordField: 'password',
    userService: users,
    encryptionService: encrypt,
    globalLock: true,
    useRefreshTokens: true,
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    refreshExpiresIn: '7d',

    strictMode: true,
    rateLimitStore: new InMemoryLoginRateLimitStore(),
    rateLimitMaxAttempts: 5,
    rateLimitWindowMs: 15 * 60 * 1000,
    onLoginFailure: (identifier, reason) => logger.warn({ identifier, reason }, 'Login failure'),
    onLoginSuccess: (userId, identifier) => logger.info({ userId, identifier }, 'Login success'),
  }),
});
```

---

## 📄 License

Licensed under the [MIT License](LICENSE).