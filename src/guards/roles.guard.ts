import { CanActivate, ExecutionContext, ForbiddenException, Inject, Injectable, Optional } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { ROLES_KEY, ROLES_MATCH_KEY, RolesMatchMode } from "../decorators/roles.decorator";
import { IS_PUBLIC_KEY } from "../decorators/public.decorator";
import { MODULE_OPTIONS_TOKEN } from "../modules/auth/auth.module-definition";
import type { AuthOptions } from "../interfaces/auth.options";
import { getRequestFromContext } from "../utils/request.util";
import { expandRoles } from "../utils/authorization.util";

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(
    protected reflector: Reflector,
    @Optional() @Inject(MODULE_OPTIONS_TOKEN) protected options?: AuthOptions
  ) {}

  canActivate(context: ExecutionContext) {
    const targets = [context.getHandler(), context.getClass()];
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, targets);
    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    };
    if (this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, targets) === true) {
      return true;
    };

    const request = getRequestFromContext(context);
    const user = request?.user;

    if (!user) {
      throw new ForbiddenException('RolesGuard requires authentication. Ensure JwtAuthGuard is active.');
    };

    if (!Array.isArray(user.roles)) {
      throw new ForbiddenException('User has no permissions assigned');
    };

    const mode = this.reflector.getAllAndOverride<RolesMatchMode>(ROLES_MATCH_KEY, targets) ?? 'any';
    const userRoles = expandRoles(user.roles, this.options?.roleHierarchy);
    const hasRole = mode === 'all'
      ? requiredRoles.every((role) => userRoles.includes(role))
      : requiredRoles.some((role) => userRoles.includes(role));
    if (!hasRole) {
      throw new ForbiddenException('Insufficient permissions');
    };

    return true;
  };

};

/**
 * Registered as APP_GUARD by AuthModule. Enforces `@Roles()` on every route when `globalLock` is true.
 */
@Injectable()
export class GlobalRolesGuard extends RolesGuard {
  canActivate(context: ExecutionContext) {
    if (!this.options?.globalLock) return true;
    return super.canActivate(context);
  };
};
