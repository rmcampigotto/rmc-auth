import { ExecutionContext, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { JwtAuthGuard } from "./jwt-auth.guard";
import { MODULE_OPTIONS_TOKEN } from "../modules/auth/auth.module-definition";
import type { AuthOptions } from "../interfaces/auth.options";

describe("JwtAuthGuard", () => {
  let guard: JwtAuthGuard;
  let reflector: Reflector;

  const mockAuthOptions: AuthOptions = {
    jwtSecret: "secret",
    expiresIn: "15m",
    identifierField: "email",
    passwordField: "password",
    userService: {} as never,
    encryptionService: {} as never,
  };

  const createMockContext = (isPublic = false): ExecutionContext => {
    const mockHandler = {};
    const mockClass = {};
    return {
      getHandler: () => mockHandler,
      getClass: () => mockClass,
      switchToHttp: () => ({
        getRequest: () => ({}),
        getResponse: () => ({}),
        getNext: () => ({}),
      }),
      getArgByIndex: () => ({}),
      getArgs: () => [],
      getType: () => "http",
      switchToRpc: () => ({}),
      switchToWs: () => ({}),
    } as unknown as ExecutionContext;
  };

  beforeEach(() => {
    reflector = new Reflector();
    guard = new JwtAuthGuard(reflector, mockAuthOptions);
  });

  it("should be defined", () => {
    expect(guard).toBeDefined();
  });

  describe("canActivate", () => {
    it("should return true when route is public", async () => {
      jest.spyOn(reflector, "getAllAndOverride").mockReturnValue(true);
      const context = createMockContext(true);
      const result = await guard.canActivate(context);
      expect(result).toBe(true);
    });
  });

  describe("handleRequest", () => {
    it("should return user when no error and user present", () => {
      const user = { id: "1", username: "test" };
      expect(guard.handleRequest(null, user)).toBe(user);
    });

    it("should throw UnauthorizedException when user is null", () => {
      expect(() => guard.handleRequest(null, null)).toThrow(UnauthorizedException);
      expect(() => guard.handleRequest(null, null)).toThrow("Access denied: Invalid or missing token");
    });

    it("should throw error when err is provided", () => {
      const err = new Error("Token expired");
      expect(() => guard.handleRequest(err, null)).toThrow(err);
    });
  });
});
