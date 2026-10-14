/**
 * Expands roles through a hierarchy (transitively).
 * @example expandRoles(['admin'], { admin: ['manager'], manager: ['user'] }) // ['admin', 'manager', 'user']
 */
export function expandRoles(roles: string[], hierarchy?: Record<string, string[]>): string[] {
  if (!hierarchy) return roles;
  const result = new Set<string>();
  const stack = [...roles];
  while (stack.length > 0) {
    const role = stack.pop()!;
    if (result.has(role)) continue;
    result.add(role);
    for (const inherited of hierarchy[role] ?? []) stack.push(inherited);
  }
  return [...result];
}

/**
 * Checks if a granted permission covers the required one. Supports wildcards per segment (`:` separated):
 * `*` covers everything, `posts:*` covers `posts:read` and `posts:comments:delete`,
 * `*:read` covers `posts:read` and `users:read`.
 */
export function permissionMatches(granted: string, required: string): boolean {
  if (granted === required || granted === "*") return true;
  const g = granted.split(":");
  const r = required.split(":");
  for (let i = 0; i < g.length; i++) {
    if (g[i] === "*") {
      if (r[i] === undefined) return false;
      if (i === g.length - 1) return true;
      continue;
    }
    if (g[i] !== r[i]) return false;
  }
  return g.length === r.length;
}

export function hasPermission(granted: string[], required: string): boolean {
  return granted.some((p) => permissionMatches(p, required));
}
