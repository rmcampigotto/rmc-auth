import { SetMetadata } from "@nestjs/common";

export const IS_PUBLIC_KEY = 'isPublic';
export const IS_OPTIONAL_AUTH_KEY = 'isOptionalAuth';

/** Marks a route as public (no JWT required). */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);

/**
 * Authentication is optional: when a valid token is sent, `request.user` is populated;
 * otherwise the request goes through with `request.user` empty (invalid tokens are ignored).
 */
export const OptionalAuth = () => SetMetadata(IS_OPTIONAL_AUTH_KEY, true);
