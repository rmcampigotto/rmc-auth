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
- 👤 **`@CurrentUser()`**: Inject the authenticated user (or one of its fields) straight into your handlers.
- 🚪 **Logout & Token Utilities**: `logout()`, `verifyAccessToken()`, `validateUser()` for WebSockets, GraphQL or custom flows.
- 🧬 **Custom Claims**: Add tenant ids, permissions or any data to the JWT with `buildPayload`.
- 🔁 **Transparent Rehash**: Migrate from bcrypt to Argon2 (or raise the cost) without forcing password resets.
- 🧩 **Permissions (ABAC-lite)**: `@RequirePermissions('posts:delete')` with wildcards (`posts:*`, `*:read`) and role hierarchy.
- 🔓 **Optional Auth**: `@OptionalAuth()` routes work for anonymous users and personalize for logged-in ones.
- 🔑 **Password Reset & Change**: Stateless, single-use reset tokens and `changePassword()` — no extra tables needed.
- ⛔ **Access Token Revocation**: Kill an access token immediately on logout with a pluggable blacklist.
- 📡 **GraphQL & WebSockets**: Guards and `@CurrentUser()` work in HTTP, GraphQL and WS contexts.
- 📱 **Two-Factor Authentication (TOTP)**: Google Authenticator / Authy compatible, recovery codes, replay protection — zero extra dependencies.
- 🗝️ **API Keys**: `@ApiKeyAuth()` for machine-to-machine access, keys stored only as hashes.
- 💻 **Multi-device Sessions**: Stable session ids across refresh rotations; revoke a single device.
- 🔒 **Secret Encryption**: AES-256-GCM helpers to store TOTP secrets and other values encrypted.

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

#### Logout and the current user

```typescript
import { Controller, Post, Get, HttpCode, Ip } from '@nestjs/common';
import { AuthService, CurrentUser, RequestUser } from 'rmc-auth';

@Controller('auth')
export class SessionController {
  constructor(private authService: AuthService) {}

  @Post('logout')
  @HttpCode(204)
  logout(@CurrentUser('id') userId: string, @Ip() ip: string) {
    return this.authService.logout(userId, { ip }); // revokes refresh tokens
  }

  @Get('me')
  me(@CurrentUser() user: RequestUser) {
    return user; // { id, username, roles, claims? }
  }
}
```

> Pass `{ ip, userAgent }` as the second argument of `login()` / `refresh()`: rate limiting becomes per IP + identifier and the context is forwarded to the audit hooks.

### 4. Authorization (RBAC)

Use `@Authorize()` to restrict access based on user roles.

```typescript
import { Controller, Get } from '@nestjs/common';
import { Authorize, AuthorizeAll } from 'rmc-auth';

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

  @Get('audit')
  @AuthorizeAll('admin', 'auditor') // 🔒 'admin' AND 'auditor' roles
  getAudit() {
    return { data: 'Audit log' };
  }
}
```

With `globalLock: true`, `@Roles('admin')` alone is enough: authentication and roles are enforced globally.

#### Role hierarchy

```typescript
roleHierarchy: { admin: ['manager'], manager: ['user'] }, // admin inherits manager and user
```

### 5. Permissions

Set `permissionsField` (e.g. `'permissions'`) and the user's permissions are added to the JWT (`request.user.permissions`).

```typescript
import { RequirePermissions, RequireAnyPermission, Permissions } from 'rmc-auth';

@Controller('posts')
export class PostsController {
  @Delete(':id')
  @RequirePermissions('posts:delete') // every permission is required
  remove() {}

  @Get('reports')
  @RequireAnyPermission('reports:read', 'reports:*') // at least one
  reports() {}

  @Patch(':id')
  @Permissions('posts:update') // enough when globalLock is true
  update() {}
}
```

Wildcards: `*` grants everything, `posts:*` grants `posts:read` / `posts:comments:delete`, `*:read` grants every `read`.

### 6. Optional authentication

```typescript
@OptionalAuth()
@Get('feed')
feed(@CurrentUser() user?: RequestUser) {
  return user ? this.feed.personalized(user.id) : this.feed.public();
}
```

### 7. Password reset & change

Requires `updatePasswordHash(userId, hash)` in your `IAuthUserService`. Reset tokens are stateless and single-use:
they are bound to the current password hash, so they stop working as soon as the password changes.

```typescript
@Public()
@Post('forgot-password')
async forgot(@Body('email') email: string) {
  const reset = await this.authService.createPasswordResetToken(email);
  if (reset) await this.mailer.sendReset(reset.user.email, reset.token); // expires in passwordResetExpiresIn (15m)
  return { message: 'If the account exists, an e-mail was sent.' }; // same answer either way
}

@Public()
@Post('reset-password')
reset(@Body() body: { token: string; password: string }) {
  return this.authService.resetPassword(body.token, body.password); // revokes every session
}

@Post('change-password')
change(@CurrentUser('id') id: string, @Body() body: { current: string; next: string }) {
  return this.authService.changePassword(id, body.current, body.next);
}
```

#### Action tokens (e-mail verification, magic links, invites)

```typescript
const token = await authService.createActionToken(user.id, 'email_verification', '1d', { email: user.email });
const payload = await authService.verifyActionToken(token, 'email_verification'); // { sub, email, ... }
```

Action tokens never authenticate requests and are only accepted for their own purpose.

### 8. Revoking access tokens

```typescript
AuthModule.register({ ..., tokenBlacklist: new InMemoryTokenBlacklistStore() }); // or a Redis implementation

@Post('logout')
logout(@CurrentUser('id') id: string, @AccessToken() token: string) {
  return this.authService.logout(id, undefined, token); // refresh tokens + this access token
}
```

Implement `ITokenBlacklistStore` (`add(jti, expiresAt)`, `has(jti)`) with Redis for multi-instance deployments.

### 9. GraphQL and WebSockets

`JwtAuthGuard`, `RolesGuard`, `PermissionsGuard`, `@CurrentUser()` and `@AccessToken()` detect the context type automatically
(`context.req` for GraphQL, the socket handshake for WebSockets).

---

### 10. Two-factor authentication (TOTP)

Enable it with `twoFactor` and implement `getTwoFactorSecret` (plus, recommended, `consumeTotpStep` and `consumeRecoveryCode`).

```typescript
AuthModule.register({ ..., twoFactor: { issuer: 'My App' } });

// IAuthUserService
async getTwoFactorSecret(userId: string) {
  const user = await this.repo.findById(userId);
  return user.totpSecret ? decryptSecret(user.totpSecret, process.env.TOTP_KEY) : null;
}
async consumeTotpStep(userId: string, step: number) {  // replay protection
  const res = await this.repo.updateWhere({ id: userId, lastTotpStep: { lt: step } }, { lastTotpStep: step });
  return res.count === 1;
}
async consumeRecoveryCode(userId: string, codeHash: string) {
  return this.repo.deleteRecoveryCode(userId, codeHash); // true if it existed
}
```

**Enrollment**

```typescript
@Post('2fa/setup')
setup(@CurrentUser() user: RequestUser) {
  return this.authService.setupTwoFactor(user.username); // { secret, otpauthUrl, recoveryCodes, recoveryCodeHashes }
}

@Post('2fa/confirm')
async confirm(@CurrentUser('id') id: string, @Body() body: { secret: string; code: string; recoveryCodeHashes: string[] }) {
  if (!this.authService.confirmTwoFactorSetup(body.secret, body.code)) throw new BadRequestException('Invalid code');
  await this.users.enableTwoFactor(id, encryptSecret(body.secret, process.env.TOTP_KEY), body.recoveryCodeHashes);
}
```

**Login**: `login()` throws `TwoFactorRequiredException` (401 `{ mfaRequired: true, mfaToken }`) for users with 2FA.
Use `authenticate()` if you prefer a result object instead of an exception.

```typescript
@Public()
@Post('login/2fa')
verify(@Body() body: { mfaToken: string; code: string }) {
  return this.authService.verifyTwoFactorLogin(body.mfaToken, body.code); // TOTP or recovery code
}
```

Use `verifyTwoFactorCode(userId, code)` to protect sensitive actions (disable 2FA, change e-mail).

### 11. API keys

```typescript
// Issuing a key (e.g. in a dashboard)
const { key, hash, displayPrefix } = generateApiKey('sk_live'); // show `key` once, store `hash`

// AuthModule options
apiKeyService: {
  validateApiKey: async (keyHash) => {
    const k = await this.repo.findApiKeyByHash(keyHash);
    return k && !k.revoked ? { id: k.ownerId, username: k.name, permissions: k.scopes } : null;
  },
},

// Controller
@ApiKeyAuth()                       // x-api-key header or Authorization: ApiKey <key>
@Permissions('reports:read')        // enforced globally with globalLock, or add PermissionsGuard
@Get('reports')
reports(@CurrentUser() client: RequestUser) {}

@ApiKeyAuth({ allowJwt: true })     // API key OR Bearer JWT
@Get('data')
data() {}
```

`request.user.authMethod` is `'api_key'` or `'jwt'`.

### 12. Multi-device sessions

When refresh tokens are enabled, every login creates a **session id** that survives refresh rotations.
`saveRefreshToken` / `isRefreshTokenValid` receive `{ sessionId, jti, expiresAt, context }`:
store one refresh token per `sessionId` to support several devices per user.

```typescript
@Get('sessions/current')
current(@CurrentUser('sessionId') sessionId: string) {}

@Delete('sessions/:id')
revoke(@CurrentUser('id') userId: string, @Param('id') sessionId: string) {
  return this.authService.revokeSession(userId, sessionId); // requires userService.revokeSession
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
| `idField`           | `string`                      | ❌       | Field containing the user id. Default: `'id'`.                              |
| `hashRefreshTokens` | `boolean`                     | ❌       | Store only the SHA-256 hash of refresh tokens (recommended).                |
| `jwtAlgorithm`      | `'HS256' \| 'HS384' \| 'HS512'` | ❌     | Signing algorithm; verification accepts only this one. Default: `'HS256'`.  |
| `clockToleranceSeconds` | `number`                  | ❌       | Clock skew tolerance when verifying tokens. Default: `0`.                   |
| `accessTokenCookieName` | `string`                  | ❌       | Also read the access token from this cookie (requires `cookie-parser`).     |
| `buildPayload`      | `(user) => object`            | ❌       | Adds custom claims to the JWT (available as `request.user.claims`).         |
| `validateJwtPayload`| `(payload, user) => user \| null` | ❌  | Extra check on every request (user still active, blacklist...).            |
| `isUserActive`      | `(user) => boolean`           | ❌       | Blocks login/refresh for inactive users (same generic 401).                 |
| `normalizeIdentifier` | `(id) => string`            | ❌       | Normalizes the identifier (e.g. trim + lowercase).                          |
| `isGlobal`          | `boolean`                     | ❌       | Registers AuthModule globally. Default: `true`.                             |
| `permissionsField`  | `string`                      | ❌       | Field with fine-grained permissions; adds them to the JWT.                  |
| `roleHierarchy`     | `Record<string, string[]>`    | ❌       | Role inheritance, e.g. `{ admin: ['manager'] }`.                           |
| `tokenBlacklist`    | `ITokenBlacklistStore`        | ❌       | Enables `revokeAccessToken()` and immediate logout.                         |
| `actionTokenSecret` | `string`                      | ❌       | Secret for reset/verification tokens (fallback: `jwtSecret`).               |
| `passwordResetExpiresIn` | `string \| number`       | ❌       | Reset token TTL. Default: `'15m'`.                                          |
| `onPasswordChanged` | `(userId, method, ctx) => void` | ❌     | Audit hook for password change/reset.                                       |
| `twoFactor`         | `{ issuer?, window?, mfaTokenExpiresIn? }` | ❌ | Enables TOTP two-factor login.                                       |
| `apiKeyService`     | `IApiKeyService`              | ❌       | Validates API keys for `@ApiKeyAuth()`.                                     |
| `apiKeyHeader`      | `string`                      | ❌       | API key header. Default: `'x-api-key'`.                                    |

### `EncryptionOptions` Configuration

| Property               | Type                            | Default     | Description                                                                 |
| :--------------------- | :------------------------------ | :---------- | :-------------------------------------------------------------------------- |
| `saltRounds`           | `number`                        | `10`        | Bcrypt salt cost factor (only for `algorithm: 'bcrypt'`).                   |
| `pepper`               | `string`                        | `undefined` | Additional secret string appended to the password before hashing.           |
| `strongPasswordValidation` | `boolean`                   | `false`     | Enforces minimum length (8) and disallows passwords with only numbers.      |
| `algorithm`            | `'bcrypt' \| 'argon2'`          | `'bcrypt'`  | Hashing algorithm used for `hash` / `compare`.                              |
| `useOwaspPolicy`       | `boolean`                       | `false`     | If `true`, enforces OWASP password-strength rules instead of simple checks. |
| `passwordPolicy`       | `PasswordPolicy`                | `undefined` | Custom rules: `minLength`, `maxLength`, `requireUppercase`, `requireLowercase`, `requireNumber`, `requireSymbol`, `disallowOnlyNumbers`, `blacklist`. |
| `argon2Options`        | `Argon2Options`                 | argon2id, 64 MiB, t=3, p=4 | `type`, `memoryCost`, `timeCost`, `parallelism`.             |
| `pepperStrategy`       | `'append' \| 'hmac'`            | `'append'`  | `'hmac'` uses HMAC-SHA256 so the pepper is never truncated by bcrypt's 72-byte limit (recommended for new projects). |
| `checkPasswordBreach`  | `(password) => Promise<boolean>`| `undefined` | Rejects compromised passwords (e.g. HIBP).                                  |
| `isGlobal`             | `boolean`                       | `false`     | Registers EncryptionModule globally.                                        |

### `AuthService` methods

| Method | Description |
|--------|-------------|
| `login(credentials, context?)` | Validates credentials and returns `AuthTokens`. |
| `refresh(refreshToken, context?)` | Rotates tokens; reuse of an old token revokes every session. |
| `logout(userId, context?, accessToken?)` | Revokes refresh tokens (`revokeAllTokens`), the given access token (with `tokenBlacklist`) and fires `onLogout`. |
| `revokeAccessToken(token)` | Revokes an access token immediately (requires `tokenBlacklist`). |
| `changePassword(userId, current, next, context?)` | Checks the current password, stores the new hash and revokes sessions. |
| `createPasswordResetToken(identifier)` | Single-use reset token, or `null` if the user does not exist. |
| `resetPassword(token, newPassword, context?)` | Sets the new password and revokes sessions. |
| `createActionToken(userId, purpose, expiresIn?, data?)` / `verifyActionToken(token, purpose)` | Signed tokens for e-mail verification, magic links, invites. |
| `authenticate(credentials, context?)` | Like `login()`, returns `{ status: 'success', tokens }` or `{ status: 'two_factor_required', mfaToken }`. |
| `verifyTwoFactorLogin(mfaToken, code, context?)` | Second login step (TOTP or recovery code). |
| `setupTwoFactor(account)` / `confirmTwoFactorSetup(secret, code)` | 2FA enrollment. |
| `verifyTwoFactorCode(userId, code)` | Re-checks 2FA for sensitive actions. |
| `revokeSession(userId, sessionId, context?)` | Revokes one device session. |
| `validateApiKey(key, context?)` | Resolves the owner of an API key. |
| `validateUser(credentials, context?)` | Same checks as `login()`, returns the user without issuing tokens. |
| `generateTokens(user)` | Issues tokens for a user record (sign-up, OAuth, magic link...). |
| `verifyAccessToken(token)` | Verifies an access token (WebSockets, GraphQL, microservices). |
| `decodeToken(token)` | Decodes **without** verifying. Never use it for authorization. |

### `EncryptionService` methods

| Method | Description |
|--------|-------------|
| `hash(password)` | Validates the policy, checks breaches and hashes. |
| `compare(password, hash)` | Detects bcrypt/argon2 from the hash; never throws on malformed hashes. |
| `validatePassword(password)` | Returns `{ valid, errors }` without hashing (sign-up forms). |
| `needsRehash(hash)` | `true` when the hash uses another algorithm or weaker parameters. |

### Exported types (TypeScript)

- `JwtPayload` — JWT claims after verification (`sub`, `username`, `roles?`). Use when decoding tokens or typing payloads.
- `RequestUser` — Object attached to `request.user` after JWT validation (`id`, `username`, `roles?`). Use to type route handlers.
- `AuthTokens` — Return type of `login()` and `refresh()`: `{ accessToken, refreshToken, tokenType: 'Bearer', expiresIn, refreshExpiresIn? }` (lifetimes in seconds).
- `AuthContext` — Optional request metadata (`ip`, `userAgent`, ...) for `login()`, `refresh()` and `logout()`.
- `LoginFailureReason` / `RefreshFailureReason` — Reasons passed to the audit hooks.

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
| `@AuthorizeAll(...roles)` | Same as `@Authorize`, but the user must have **every** role. |
| `@CurrentUser(field?)` | Injects `request.user` (or one of its fields) into the handler. |
| `RolesMatch('any' \| 'all')` | Changes how `@Roles` are matched. |
| `@OptionalAuth()` | Populates `request.user` when a valid token is sent; anonymous requests still pass. |
| `@RequirePermissions(...perms)` | Requires a valid JWT and every permission (wildcards supported). |
| `@RequireAnyPermission(...perms)` | Requires a valid JWT and at least one permission. |
| `@Permissions(...perms)` | Permission metadata (enforced globally with `globalLock`). |
| `@AccessToken()` | Injects the raw access token of the request. |
| `PermissionsGuard` | Guard that checks `request.user.permissions`. |
| `@ApiKeyAuth(options?)` | Authenticates the route with an API key (`allowJwt` to also accept a JWT). |
| `ApiKeyGuard` | Guard behind `@ApiKeyAuth()`. |
| `TwoFactorRequiredException` | Thrown by `login()` when the second factor is required. |

### Standalone utilities

Usable outside NestJS modules as well:

| Function | Description |
|----------|-------------|
| `generateTotpSecret()`, `generateTotp()`, `verifyTotp()`, `buildOtpAuthUrl()` | RFC 6238 TOTP (validated against the official test vectors). |
| `generateRecoveryCodes()`, `hashRecoveryCode()` | One-time 2FA recovery codes. |
| `encryptSecret()`, `decryptSecret()` | AES-256-GCM encryption for values you must read back. |
| `generateApiKey()`, `hashApiKey()` | Prefixed API keys and their lookup hash. |
| `generateSecureToken()`, `hashToken()`, `timingSafeEqual()` | Random tokens, hashing and constant-time comparison. |
| `parseDurationToSeconds()` | `'15m'`, `'1 hour'`, `'7d'` → seconds. |
| `expandRoles()`, `permissionMatches()`, `hasPermission()` | Role hierarchy and permission wildcards. |
| `getRequestFromContext()` | Request object for HTTP, GraphQL and WS contexts. |
| `Roles(...roles)` | Metadata for roles; used by `RolesGuard`. |
| `JwtAuthGuard`    | Guard that validates the JWT and attaches the user to the request. |
| `RolesGuard`      | Guard that checks the user has one of the required roles. |

### Interfaces

- `IAuthUserService` — Implement to plug your user/database layer. Optional `updatePasswordHash(userId, hash)` enables transparent rehashing after login.
- `IEncryptionService` — Implemented by `EncryptionService`; inject when using `AuthModule.registerAsync`.

These allow you to plug in **your own services** while keeping RMC-AUTH fully type-safe and testable.

---

## 🔒 Security Principles

1. **Fail-Safe by Default**: With `globalLock`, we prevent accidental exposure of sensitive endpoints due to developer oversight. You must explicitly open routes with `@Public()`.
2. **Generic Error Messages**: Login failures always return a generic `Unauthorized` error to prevent **User Enumeration Attacks**.
3. **Token Rotation**: When a Refresh Token is used, a new pair (Access + Refresh) is issued. If a stolen token is reused, the library detects the anomaly (via `isRefreshTokenValid`) and revokes the entire session history (`revokeAllTokens`).
4. **Typed Tokens**: Every token carries a `type` claim. Refresh tokens are rejected by the guards and access tokens are rejected by `refresh()`, even when both share the same secret.
5. **No Algorithm Confusion**: Verification accepts only the configured `jwtAlgorithm`.
6. **Strong Passwords by Design**: You can start with simple rules (`strongPasswordValidation`) and evolve to **OWASP policy + Argon2** without breaking your API.

---

## 🛡️ Cybersecurity Features

RMC-AUTH embeds industry-standard security controls so your app stays secure by default:

| Feature | Description |
|--------|-------------|
| **Input validation** | Identifier and password are length-capped (default 256 / 1024 chars) to prevent DoS. Invalid or oversized input returns `BadRequestException` with a generic message. |
| **Strict mode** | Set `strictMode: true` to enforce: JWT secret ≥ 32 chars, `jwtIssuer` and `jwtAudience` required, access token TTL ≤ 1 hour, distinct `refreshSecret` (≥ 32 chars) when refresh tokens are enabled. |
| **Account lockout** | Optional: implement `getLockoutUntil`, `recordFailedLogin`, and `clearFailedLogin` on your user service and set `lockoutMaxAttempts` and `lockoutDurationMinutes`. `recordFailedLogin(identifier, { maxAttempts, durationMinutes })` receives the policy; successful login clears the counter. |
| **Login rate limiting** | Optional: provide `rateLimitStore` (e.g. `InMemoryLoginRateLimitStore`, bounded by `maxEntries`) and set `rateLimitMaxAttempts` / `rateLimitWindowMs`. Keyed by IP + identifier when `context.ip` is given. Returns `429 Too Many Requests` when exceeded. |
| **Security audit hooks** | Optional callbacks: `onLoginSuccess`, `onLoginFailure`, `onRefreshSuccess`, `onRefreshFailure`, `onLogout` for logging and SIEM. They receive the request context; errors thrown inside them are swallowed. |
| **Refresh token validation** | Refresh token string is checked for type, non-empty, and max length before verification to avoid abuse. |
| **Timing-safe comparison** | Export `timingSafeEqual(a, b)` for use in your `isRefreshTokenValid` to prevent timing attacks when comparing tokens. |
| **Timing-attack protection** | When the user does not exist, a dummy hash comparison runs so response time does not reveal valid identifiers. |
| **Hashed refresh tokens** | `hashRefreshTokens: true` stores only SHA-256 hashes, so a database leak does not expose usable tokens. |
| **Secure tokens** | `generateSecureToken()` and `hashToken()` for password reset, e-mail verification, API keys. |
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

### Migrating password hashes (bcrypt → Argon2)

```typescript
EncryptionModule.register({ algorithm: 'argon2', pepper: process.env.AUTH_PEPPER });

// UsersService
async updatePasswordHash(userId: string, newHash: string) {
  await this.prisma.user.update({ where: { id: userId }, data: { password: newHash } });
}
```

`compare()` still verifies old bcrypt hashes. After each successful login, outdated hashes are re-hashed with the current configuration and saved through `updatePasswordHash`.

---

## ⬆️ Upgrading from 1.0.0

- Tokens now carry a `type` claim. Refresh tokens issued by 1.0.0 have no `type` and are rejected by `refresh()`: users simply log in again once.
- `AuthModule` is registered globally by default (`isGlobal: true`) so `@Authorize()` works in any feature module.
- Duration options (`expiresIn`, `refreshExpiresIn`) are validated at bootstrap; invalid formats now fail fast.
- Only access tokens (no `type`, or `type: 'access'`) authenticate requests; refresh and action tokens are rejected.

---

## 📄 License

Licensed under the [MIT License](LICENSE).