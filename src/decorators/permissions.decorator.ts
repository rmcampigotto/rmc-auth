import { SetMetadata } from "@nestjs/common";

export const PERMISSIONS_KEY = 'permissions';
export const PERMISSIONS_MATCH_KEY = 'permissionsMatch';

/** How required permissions are matched: `'all'` (default) or `'any'`. */
export type PermissionsMatchMode = 'any' | 'all';

/** Permission metadata, checked by PermissionsGuard (and globally when `globalLock` is true). */
export const Permissions = (...permissions: string[]) => SetMetadata(PERMISSIONS_KEY, permissions);
export const PermissionsMatch = (mode: PermissionsMatchMode) => SetMetadata(PERMISSIONS_MATCH_KEY, mode);
