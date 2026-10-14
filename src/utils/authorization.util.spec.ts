import { expandRoles, hasPermission, permissionMatches } from "./authorization.util";

describe("authorization utils", () => {
  describe("expandRoles", () => {
    const hierarchy = { admin: ["manager"], manager: ["user"], user: [] };

    it("expands roles transitively", () => {
      expect(expandRoles(["admin"], hierarchy).sort()).toEqual(["admin", "manager", "user"]);
    });

    it("returns the roles unchanged without a hierarchy", () => {
      expect(expandRoles(["user"])).toEqual(["user"]);
    });

    it("handles cycles", () => {
      expect(expandRoles(["a"], { a: ["b"], b: ["a"] }).sort()).toEqual(["a", "b"]);
    });
  });

  describe("permissionMatches", () => {
    it.each([
      ["posts:read", "posts:read", true],
      ["posts:read", "posts:write", false],
      ["*", "anything:here", true],
      ["posts:*", "posts:read", true],
      ["posts:*", "posts:comments:delete", true],
      ["posts:*", "posts", false],
      ["posts:*", "users:read", false],
      ["*:read", "users:read", true],
      ["*:read", "users:write", false],
      ["posts", "posts:read", false],
    ])("%s covers %s → %s", (granted, required, expected) => {
      expect(permissionMatches(granted, required)).toBe(expected);
    });

    it("hasPermission checks a list", () => {
      expect(hasPermission(["users:read", "posts:*"], "posts:delete")).toBe(true);
      expect(hasPermission([], "posts:delete")).toBe(false);
    });
  });
});
