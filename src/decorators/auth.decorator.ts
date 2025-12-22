import { applyDecorators, UseGuards } from "@nestjs/common";
import { Roles } from "./roles.decorator";
import { JwtAuthGuard } from "../guards/jwt-auth.guard";
import { RolesGuard } from "../guards/roles.guard";

export function Authorize(...roles: string[]) {
  return applyDecorators(
    Roles(...roles),
    UseGuards(JwtAuthGuard, RolesGuard),
  );
};