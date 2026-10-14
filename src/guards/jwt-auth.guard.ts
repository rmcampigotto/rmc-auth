import { ExecutionContext, Inject, Injectable, Optional, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { AuthGuard } from "@nestjs/passport";
import { IS_OPTIONAL_AUTH_KEY, IS_PUBLIC_KEY } from "../decorators/public.decorator";
import { API_KEY_AUTH_KEY } from "../decorators/api-key.decorator";
import { MODULE_OPTIONS_TOKEN } from "../modules/auth/auth.module-definition";
import type { AuthOptions } from "../interfaces/auth.options";
import type { RequestUser } from "../types/auth.types";
import { getRequestFromContext, getResponseFromContext } from "../utils/request.util";

@Injectable()
export class JwtAuthGuard extends AuthGuard("jwt") {
  constructor(
    protected reflector: Reflector,
    @Optional() @Inject(MODULE_OPTIONS_TOKEN) protected options?: AuthOptions
  ) {
    super();
  }

  private hasFlag(context: ExecutionContext, key: string): boolean {
    return this.reflector.getAllAndOverride<boolean>(key, [
      context.getHandler(),
      context.getClass(),
    ]) === true;
  }

  protected isPublic(context: ExecutionContext): boolean {
    return this.hasFlag(context, IS_PUBLIC_KEY);
  }

  protected isOptional(context: ExecutionContext): boolean {
    return this.hasFlag(context, IS_OPTIONAL_AUTH_KEY);
  }

  getRequest(context: ExecutionContext) {
    return getRequestFromContext(context);
  }

  getResponse(context: ExecutionContext) {
    return getResponseFromContext(context);
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (this.isPublic(context)) return true;
    if (this.isOptional(context)) {
      try {
        await super.canActivate(context);
      } catch {
        // Invalid or missing token: continue anonymously.
      }
      return true;
    }
    return (await super.canActivate(context)) as boolean;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  handleRequest(err: unknown, user: RequestUser | null | false, _info?: unknown, context?: ExecutionContext): any {
    if (context && this.isOptional(context)) return user || null;
    if (err) throw err;
    if (!user) throw new UnauthorizedException("Access denied: Invalid or missing token");
    return user;
  }
}

/**
 * Registered as APP_GUARD by AuthModule. Only enforces authentication when `globalLock` is true.
 * `@OptionalAuth()` routes are still evaluated when `globalLock` is false.
 */
@Injectable()
export class GlobalJwtAuthGuard extends JwtAuthGuard {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // `@ApiKeyAuth()` routes are authenticated by ApiKeyGuard.
    if (this.reflector.getAllAndOverride(API_KEY_AUTH_KEY, [context.getHandler(), context.getClass()])) return true;
    if (!this.options?.globalLock && !this.isOptional(context)) return true;
    return super.canActivate(context);
  }
}
