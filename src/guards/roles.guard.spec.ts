import { ExecutionContext, ForbiddenException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { RolesGuard } from "./roles.guard";
import { ROLES_KEY, ROLES_MATCH_KEY } from "../decorators/roles.decorator";
import { IS_PUBLIC_KEY } from "../decorators/public.decorator";

describe("RolesGuard", () => {
  let guard: RolesGuard;
  let reflector: Reflector;

  const createMockContext = (user: { id?: string; username?: string; roles?: string[] } | null) => {
    return {
      getHandler: () => ({}),
      getClass: () => ({}),
      switchToHttp: () => ({
        getRequest: () => ({ user }),
      }),
    } as unknown as ExecutionContext;
  };

  beforeEach(() => {
    reflector = new Reflector();
    guard = new RolesGuard(reflector);
  });

  it("should be defined", () => {
    expect(guard).toBeDefined();
  });

  it("should return true when no roles are required", () => {
    jest.spyOn(reflector, "getAllAndOverride").mockReturnValue(undefined);
    const context = createMockContext({ id: "1", roles: ["user"] });
    expect(guard.canActivate(context)).toBe(true);
  });

  it("should return true when user has one of the required roles", () => {
    jest.spyOn(reflector, "getAllAndOverride").mockReturnValue(["admin", "user"]);
    const context = createMockContext({ id: "1", username: "u", roles: ["user"] });
    expect(guard.canActivate(context)).toBe(true);
  });

  it("should throw ForbiddenException when user is missing", () => {
    jest.spyOn(reflector, "getAllAndOverride").mockReturnValue(["admin"]);
    const context = createMockContext(null);

    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
    expect(() => guard.canActivate(context)).toThrow("RolesGuard requires authentication");
  });

  it("should throw ForbiddenException when user has no roles", () => {
    jest.spyOn(reflector, "getAllAndOverride").mockReturnValue(["admin"]);
    const context = createMockContext({ id: "1", username: "u" });

    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
    expect(() => guard.canActivate(context)).toThrow("User has no permissions assigned");
  });

  it("should throw ForbiddenException when user lacks required role", () => {
    jest.spyOn(reflector, "getAllAndOverride").mockReturnValue(["admin"]);
    const context = createMockContext({ id: "1", username: "u", roles: ["user"] });

    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
    expect(() => guard.canActivate(context)).toThrow("Insufficient permissions");
  });
});

describe("RolesGuard (match modes)", () => {
  const ctx = (roles: string[]) =>
    ({
      getHandler: () => ({}),
      getClass: () => ({}),
      switchToHttp: () => ({ getRequest: () => ({ user: { id: "1", username: "u", roles } }) }),
    }) as unknown as ExecutionContext;

  const guardWith = (metadata: Record<string, unknown>) => {
    const reflector = new Reflector();
    jest.spyOn(reflector, "getAllAndOverride").mockImplementation((key) => metadata[key as string]);
    return new RolesGuard(reflector);
  };

  it("allows when the required roles list is empty (@Authorize())", () => {
    expect(guardWith({ [ROLES_KEY]: [] }).canActivate(ctx([]))).toBe(true);
  });

  it("'all' mode requires every role", () => {
    const guard = guardWith({ [ROLES_KEY]: ["a", "b"], [ROLES_MATCH_KEY]: "all" });
    expect(() => guard.canActivate(ctx(["a"]))).toThrow(ForbiddenException);
    expect(guard.canActivate(ctx(["a", "b"]))).toBe(true);
  });

  it("skips public routes", () => {
    expect(guardWith({ [ROLES_KEY]: ["admin"], [IS_PUBLIC_KEY]: true }).canActivate(ctx([]))).toBe(true);
  });
});
