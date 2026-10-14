import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import type { RequestUser } from "../types/auth.types";
import { ACCESS_TOKEN_REQUEST_KEY, getRequestFromContext } from "../utils/request.util";

/**
 * Injects the authenticated user (`request.user`) into a route handler.
 * Works with HTTP, GraphQL and WebSocket contexts.
 * @example
 * getProfile(@CurrentUser() user: RequestUser) {}
 * getId(@CurrentUser('id') id: string) {}
 */
export const CurrentUser = createParamDecorator(
  (field: keyof RequestUser | undefined, context: ExecutionContext) => {
    const user: RequestUser | undefined = getRequestFromContext(context)?.user ?? undefined;
    if (!user) return undefined;
    return field ? user[field] : user;
  },
);

/**
 * Injects the raw access token of the authenticated request (header or cookie).
 * Useful to revoke it on logout: `authService.revokeAccessToken(token)`.
 */
export const AccessToken = createParamDecorator(
  (_data: unknown, context: ExecutionContext): string | undefined => {
    const request = getRequestFromContext(context);
    const stored = request?.[ACCESS_TOKEN_REQUEST_KEY];
    if (typeof stored === "string") return stored;
    const header = request?.headers?.authorization;
    if (typeof header === "string" && header.startsWith("Bearer ")) return header.slice(7);
    return undefined;
  },
);
