# RMC-AUTH minimal example

Minimal NestJS app using `rmc-auth` for login, refresh token, and a protected route.

## Run

From this directory:

```bash
npm install
npm run start:dev
```

Then:

- **Login:** `POST http://localhost:3000/auth/login` with body `{ "email": "user@example.com", "password": "Password123!" }`
- **Refresh:** `POST http://localhost:3000/auth/refresh` with body `{ "refreshToken": "<refresh_token>" }`
- **Protected route:** `GET http://localhost:3000/profile` with header `Authorization: Bearer <access_token>`

## Note

The library is linked via `"rmc-auth": "file:../.."`. To use a published version, replace that in `package.json` with `"rmc-auth": "^0.0.2"` (or the current version).
