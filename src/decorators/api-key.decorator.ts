import { SetMetadata } from "@nestjs/common";

export const API_KEY_AUTH_KEY = 'apiKeyAuth';

export interface ApiKeyAuthOptions {
  /** Also accept a JWT (Bearer) when no API key is sent. @default false */
  allowJwt?: boolean;
}

/** API key metadata. Use `@ApiKeyAuth()` (which also applies ApiKeyGuard) in controllers. */
export const ApiKeyAuthMetadata = (options: ApiKeyAuthOptions = {}) => SetMetadata(API_KEY_AUTH_KEY, options);
