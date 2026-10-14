import { applyDecorators, UseGuards } from "@nestjs/common";
import { Roles, RolesMatch } from "./roles.decorator";
import { JwtAuthGuard } from "../guards/jwt-auth.guard";
import { RolesGuard } from "../guards/roles.guard";

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
