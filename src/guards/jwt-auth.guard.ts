import { ExecutionContext, Inject, Injectable, Optional, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { AuthGuard } from "@nestjs/passport";
import { IS_PUBLIC_KEY } from "../decorators/public.decorator";
import { MODULE_OPTIONS_TOKEN } from "../modules/auth/auth.module-definition";
import type { AuthOptions } from "../interfaces/auth.options";
import type { RequestUser } from "../types/auth.types";

@Injectable()
export class JwtAuthGuard extends AuthGuard("jwt") {
  constructor(
    protected reflector: Reflector,
    @Optional() @Inject(MODULE_OPTIONS_TOKEN) protected options?: AuthOptions
  ) {
    super();
  }

  protected isPublic(context: ExecutionContext): boolean {
    return this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]) === true;
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (this.isPublic(context)) return true;
    return (await super.canActivate(context)) as boolean;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  handleRequest(err: unknown, user: RequestUser | null | false): any {
    if (err) throw err;
    if (!user) throw new UnauthorizedException("Access denied: Invalid or missing token");
    return user;
  }
}

/**
 * Registered as APP_GUARD by AuthModule. Only enforces authentication when `globalLock` is true.
 */
@Injectable()
export class GlobalJwtAuthGuard extends JwtAuthGuard {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (!this.options?.globalLock) return true;
    return super.canActivate(context);
  }
}
