import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import type { RequestUser } from "../types/auth.types";

/**
 * Injects the authenticated user (`request.user`) into a route handler.
 * @example
 * getProfile(@CurrentUser() user: RequestUser) {}
 * getId(@CurrentUser('id') id: string) {}
 */
export const CurrentUser = createParamDecorator(
  (field: keyof RequestUser | undefined, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest<{ user?: RequestUser }>();
    const user = request?.user;
    if (!user) return undefined;
    return field ? user[field] : user;
  },
);
