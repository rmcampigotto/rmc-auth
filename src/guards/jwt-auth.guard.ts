import { ExecutionContext, Inject, Injectable, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { AuthGuard } from "@nestjs/passport";
import { IS_PUBLIC_KEY } from "../decorators/public.decorator";
import { MODULE_OPTIONS_TOKEN } from "../modules/auth/auth.module-definition";
import type { AuthOptions } from "../interfaces/auth.options";
import type { RequestUser } from "../types/auth.types";

@Injectable()
export class JwtAuthGuard extends AuthGuard("jwt") {
  constructor(
    private reflector: Reflector,
    @Inject(MODULE_OPTIONS_TOKEN) private options: AuthOptions
  ) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) return true;
    return (await super.canActivate(context)) as boolean;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  handleRequest(err: unknown, user: RequestUser | null): any {
    if (err) throw err;
    if (!user) throw new UnauthorizedException("Access denied: Invalid or missing token");
    return user;
  }
}