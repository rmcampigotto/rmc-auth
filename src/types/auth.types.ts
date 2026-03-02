/**
 * JWT payload shape (claims) after verification.
 * Use this to type `request.user` or decode results.
 */
export interface JwtPayload {
  sub: string;
  username: string;
  roles?: string[];
}

/**
 * User object attached to the request after JWT validation.
 * Populated by JwtStrategy and available as `request.user`.
 */
export interface RequestUser {
  id: string;
  username: string;
  roles?: string[];
}

/**
 * Return type of login() and refresh().
 */
export interface AuthTokens {
  accessToken: string;
  refreshToken: string | null;
}
