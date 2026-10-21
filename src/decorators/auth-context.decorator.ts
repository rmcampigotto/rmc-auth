import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import type { AuthContext } from "../types/auth.types";
import { getRequestFromContext } from "../utils/request.util";

/**
 * Builds the `AuthContext` (ip, userAgent) of a request. Uses `request.ip`, so configure `trust proxy`
 * behind a load balancer. Works with HTTP, GraphQL and WebSocket contexts.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function getAuthContext(request: any): AuthContext {
  const context: AuthContext = {};
  const ip = request?.ip ?? request?.address ?? request?.socket?.remoteAddress;
  if (typeof ip === "string" && ip) context.ip = ip;
  const userAgent = request?.headers?.["user-agent"];
  if (typeof userAgent === "string" && userAgent) context.userAgent = userAgent;
  return context;
}

/**
 * Injects the request `AuthContext` ({ ip, userAgent }) to pass to `login()`, `refresh()`, `logout()`...
 * @example
 * login(@Body() body: LoginDto, @AuthCtx() ctx: AuthContext) { return this.auth.login(body, ctx); }
 */
export const AuthCtx = createParamDecorator((_data: unknown, context: ExecutionContext): AuthContext =>
  getAuthContext(getRequestFromContext(context))
);
