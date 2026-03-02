import { ExecutionContext, ForbiddenException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { RolesGuard } from "./roles.guard";
import { ROLES_KEY } from "../decorators/roles.decorator";

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
