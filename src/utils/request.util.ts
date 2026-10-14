import type { ExecutionContext } from "@nestjs/common";

/**
 * Returns the request-like object for HTTP, GraphQL and WebSocket contexts.
 * - HTTP: the Express/Fastify request.
 * - GraphQL: `context.req` (Apollo/Mercurius context).
 * - WebSocket: the socket handshake (socket.io) or the client itself.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function getRequestFromContext(context: ExecutionContext): any {
  const type = typeof context.getType === "function" ? context.getType<string>() : "http";
  if (type === "graphql") {
    const gqlContext = context.getArgByIndex(2);
    return gqlContext?.req ?? gqlContext?.request ?? gqlContext;
  }
  if (type === "ws") {
    const client = context.switchToWs().getClient();
    return client?.handshake ?? client?.request ?? client;
  }
  return context.switchToHttp().getRequest();
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function getResponseFromContext(context: ExecutionContext): any {
  const type = typeof context.getType === "function" ? context.getType<string>() : "http";
  if (type === "graphql") {
    const gqlContext = context.getArgByIndex(2);
    return gqlContext?.res ?? gqlContext?.reply;
  }
  if (type === "ws") return undefined;
  return context.switchToHttp().getResponse();
}

/** Request property where JwtStrategy stores the raw access token (read by `@AccessToken()`). */
export const ACCESS_TOKEN_REQUEST_KEY = Symbol.for("rmc-auth:access-token");
