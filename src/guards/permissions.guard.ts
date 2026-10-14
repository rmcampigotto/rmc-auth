import { CanActivate, ExecutionContext, ForbiddenException, Inject, Injectable, Optional } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { PERMISSIONS_KEY, PERMISSIONS_MATCH_KEY, PermissionsMatchMode } from "../decorators/permissions.decorator";
import { IS_PUBLIC_KEY } from "../decorators/public.decorator";
import { MODULE_OPTIONS_TOKEN } from "../modules/auth/auth.module-definition";
import type { AuthOptions } from "../interfaces/auth.options";
import { getRequestFromContext } from "../utils/request.util";
import { hasPermission } from "../utils/authorization.util";

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(
    protected reflector: Reflector,
    @Optional() @Inject(MODULE_OPTIONS_TOKEN) protected options?: AuthOptions
  ) {}

  canActivate(context: ExecutionContext) {
    const targets = [context.getHandler(), context.getClass()];
    const required = this.reflector.getAllAndOverride<string[]>(PERMISSIONS_KEY, targets);
    if (!required || required.length === 0) {
      return true;
    };
    if (this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, targets) === true) {
      return true;
    };

    const user = getRequestFromContext(context)?.user;
    if (!user) {
      throw new ForbiddenException('PermissionsGuard requires authentication. Ensure JwtAuthGuard is active.');
    };

    const granted: string[] = Array.isArray(user.permissions) ? user.permissions : [];
    const mode = this.reflector.getAllAndOverride<PermissionsMatchMode>(PERMISSIONS_MATCH_KEY, targets) ?? 'all';
    const allowed = mode === 'any'
      ? required.some((p) => hasPermission(granted, p))
      : required.every((p) => hasPermission(granted, p));
    if (!allowed) {
      throw new ForbiddenException('Insufficient permissions');
    };

    return true;
  };
};

/**
 * Registered as APP_GUARD by AuthModule. Enforces `@Permissions()` on every route when `globalLock` is true.
 */
@Injectable()
export class GlobalPermissionsGuard extends PermissionsGuard {
  canActivate(context: ExecutionContext) {
    if (!this.options?.globalLock) return true;
    return super.canActivate(context);
  };
};
