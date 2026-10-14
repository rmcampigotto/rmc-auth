import { applyDecorators, UseGuards } from "@nestjs/common";
import { Roles, RolesMatch } from "./roles.decorator";
import { JwtAuthGuard } from "../guards/jwt-auth.guard";
import { RolesGuard } from "../guards/roles.guard";
import { PermissionsGuard } from "../guards/permissions.guard";
import { Permissions, PermissionsMatch } from "./permissions.decorator";

/** Requires a valid JWT and, if roles are given, at least one of them. */
export function Authorize(...roles: string[]) {
  return applyDecorators(
    Roles(...roles),
    UseGuards(JwtAuthGuard, RolesGuard),
  );
};

/** Requires a valid JWT and every one of the given roles. */
export function AuthorizeAll(...roles: string[]) {
  return applyDecorators(
    Roles(...roles),
    RolesMatch('all'),
    UseGuards(JwtAuthGuard, RolesGuard),
  );
};

/** Requires a valid JWT and every given permission (wildcards like `posts:*` are supported). */
export function RequirePermissions(...permissions: string[]) {
  return applyDecorators(
    Permissions(...permissions),
    UseGuards(JwtAuthGuard, PermissionsGuard),
  );
};

/** Requires a valid JWT and at least one of the given permissions. */
export function RequireAnyPermission(...permissions: string[]) {
  return applyDecorators(
    Permissions(...permissions),
    PermissionsMatch('any'),
    UseGuards(JwtAuthGuard, PermissionsGuard),
  );
};
