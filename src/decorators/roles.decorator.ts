import { SetMetadata } from "@nestjs/common";

export const ROLES_KEY = 'roles';
export const ROLES_MATCH_KEY = 'rolesMatch';

/** How required roles are matched: `'any'` (at least one) or `'all'` (every role). */
export type RolesMatchMode = 'any' | 'all';

export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);
export const RolesMatch = (mode: RolesMatchMode) => SetMetadata(ROLES_MATCH_KEY, mode);
