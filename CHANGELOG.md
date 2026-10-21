# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.1.0] - 2026-10-21

### Security

- bcrypt: passwords over 72 bytes are rejected by `hash()` / `validatePassword()` (bcrypt ignores everything after byte 72, so two such passwords could match each other). Not applied with argon2 or `pepperStrategy: 'hmac'`; existing hashes still verify.
- The `mfaToken` of a two-factor login is single-use when `tokenBlacklist` is configured.
- `changePassword()` is rate limited per user when `rateLimitStore` is configured (stops brute-forcing the current password with a stolen access token).
- `refresh()` rejects tokens without a `sub` claim before looking up the user.

### Changed

- Strict mode requires `userService.isRefreshTokenValid` and `revokeAllTokens` when `useRefreshTokens` is true; without strict mode a warning is logged, since refresh tokens could not be rotated or revoked.
- A warning is logged when bcrypt is used with a pepper and `pepperStrategy: 'append'`.

## [2.0.0] - 2026-10-14

### Added

- `AuthService.logout()`, `validateUser()`, `verifyAccessToken()` and `decodeToken()`.
- `@CurrentUser()` param decorator, `@AuthorizeAll()` and `RolesMatch('any' | 'all')`.
- Optional request context (`AuthContext`: ip, userAgent) for `login()`, `refresh()` and `logout()`; rate limiting per IP + identifier; context forwarded to audit hooks.
- New `AuthOptions`: `idField`, `hashRefreshTokens`, `jwtAlgorithm`, `clockToleranceSeconds`, `accessTokenCookieName`, `buildPayload`, `validateJwtPayload`, `isUserActive`, `normalizeIdentifier`, `onLogout`.
- `AuthTokens` now includes `tokenType`, `expiresIn` and `refreshExpiresIn` (seconds).
- New `EncryptionOptions`: `passwordPolicy`, `argon2Options`, `pepperStrategy: 'hmac'`.
- `EncryptionService.validatePassword()`, `needsRehash()` and `compareDummy()`; transparent rehash on login via `IAuthUserService.updatePasswordHash`.
- `lockoutDurationMinutes` is now used: `recordFailedLogin(identifier, { maxAttempts, durationMinutes })`.
- `isGlobal` option for both modules (AuthModule global by default).
- Utilities: `generateSecureToken()`, `hashToken()`, `parseDurationToSeconds()`.
- `InMemoryLoginRateLimitStore` is bounded (`maxEntries`) and exposes `prune()`, `clear()` and `size`.
- Permissions: `permissionsField`, `@Permissions()`, `@RequirePermissions()`, `@RequireAnyPermission()`, `PermissionsMatch`, `PermissionsGuard` (global with `globalLock`), wildcard matching (`posts:*`, `*:read`).
- Role hierarchy (`roleHierarchy`), applied by `RolesGuard`.
- `@OptionalAuth()` for routes that work with or without a token.
- Access token revocation: `tokenBlacklist` (`ITokenBlacklistStore`, `InMemoryTokenBlacklistStore`), `revokeAccessToken()`, `logout(userId, context, accessToken)` and `@AccessToken()`. Access tokens now include a `jti`.
- Passwords: `changePassword()`, stateless single-use `createPasswordResetToken()` / `resetPassword()`, `onPasswordChanged` hook, `passwordResetExpiresIn`.
- Action tokens: `createActionToken()` / `verifyActionToken()` (e-mail verification, magic links, invites), `actionTokenSecret`.
- GraphQL and WebSocket support in guards, `@CurrentUser()` and `@AccessToken()` (`getRequestFromContext()`).
- Utilities: `expandRoles()`, `permissionMatches()`, `hasPermission()`.
- Two-factor authentication (TOTP, RFC 6238): `twoFactor` option, `authenticate()`, `verifyTwoFactorLogin()`, `setupTwoFactor()`, `confirmTwoFactorSetup()`, `verifyTwoFactorCode()`, `TwoFactorRequiredException`, recovery codes and replay protection (`getTwoFactorSecret`, `consumeTotpStep`, `consumeRecoveryCode`).
- API keys: `@ApiKeyAuth()`, `ApiKeyGuard`, `IApiKeyService`, `apiKeyHeader`, `AuthService.validateApiKey()`, `generateApiKey()`, `hashApiKey()`.
- Multi-device sessions: session id (`sid`) kept across refresh rotations, `RefreshSessionInfo` passed to `saveRefreshToken` / `isRefreshTokenValid`, `revokeSession()`, `request.user.sessionId`, `AuthTokens.sessionId`.
- `request.user.authMethod` (`'jwt'` or `'api_key'`).
- Secret encryption helpers: `encryptSecret()` / `decryptSecret()` (AES-256-GCM).
- TOTP utilities: `generateTotpSecret()`, `generateTotp()`, `verifyTotp()`, `buildOtpAuthUrl()`, `base32Encode()`, `base32Decode()`; `generateRecoveryCodes()`, `hashRecoveryCode()`.
- Password reset requests are rate limited when `rateLimitStore` is configured.
- Tests for all new features, plus full-module integration tests.

### Changed

- Tokens carry a `type` claim (`access` / `refresh`); refresh tokens include a unique `jti`.
- Strict mode also requires a distinct `refreshSecret` (≥ 32 chars) when refresh tokens are enabled.
- Duration options are validated at bootstrap (supports `'15m'`, `'1 hour'`, `'7d'`, `'2w'`...).

### Fixed

- Access tokens could be used as refresh tokens (and vice versa) when both shared the same secret.
- Login with a non-existent user returned faster than with a wrong password (user enumeration via timing).
- Audit hooks that threw synchronously broke the login/refresh flow.
- `@Authorize()` without roles denied every user.
- `compare()` threw on malformed hashes instead of returning `false`.
- Token verification did not pin the signing algorithm.
- `InMemoryLoginRateLimitStore` could grow without bound.
- Signing tokens failed with `"issuer" must be a string` when `jwtIssuer` / `jwtAudience` were not configured.

## [1.0.0] - 2025-03-02

### Added

- **Cybersecurity features**: Input validation (max lengths for identifier/password and refresh token), strict mode (JWT secret length, issuer/audience required, max access TTL 1h), optional account lockout (`getLockoutUntil`, `recordFailedLogin`, `clearFailedLogin`), optional login rate limiting (`ILoginRateLimitStore`, `InMemoryLoginRateLimitStore`), security audit hooks (`onLoginSuccess`, `onLoginFailure`, `onRefreshSuccess`, `onRefreshFailure`), timing-safe compare utility (`timingSafeEqual`), optional password breach check in `EncryptionModule` (`checkPasswordBreach`). See README "Cybersecurity Features" section.
- Unit tests for `AuthService`, `EncryptionService`, `JwtAuthGuard`, and `RolesGuard`.
- Integration test for Auth + Encryption login flow.
- CI workflow (GitHub Actions) for test and build.
- Exported types: `JwtPayload`, `RequestUser`, `AuthTokens` for TypeScript consumers.
- Validation of required options at module bootstrap (Auth and Encryption).
- CONTRIBUTING.md and minimal example app in `examples/minimal`.
- API Reference section in README (types and request user shape).

### Changed

- Reduced use of `any` in public APIs; credentials and user records use stricter types.
- `IAuthUserService.findOneByField` value parameter typed as `unknown`; return as `Promise<unknown>`.
- README: all code samples use `rmc-auth`; duplicate configuration block removed; TypeScript usage noted.

## [0.0.2] - (previous)

- Initial public release with AuthModule, EncryptionModule, JWT, refresh tokens, RBAC, and guards.
