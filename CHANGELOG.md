# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Tests for all new features, plus a full-module integration test.

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
