# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
