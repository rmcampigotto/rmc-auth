import { Controller, ExecutionContext, ForbiddenException, Get, Module, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { Test, TestingModule } from "@nestjs/testing";
import { ROUTE_ARGS_METADATA } from "@nestjs/common/constants";
import {
  AccessToken,
  AUTH_OPTIONS_TOKEN,
  AuthModule,
  AuthService,
  CurrentUser,
  EncryptionModule,
  EncryptionService,
  GlobalJwtAuthGuard,
  GlobalPermissionsGuard,
  GlobalRolesGuard,
  InMemoryTokenBlacklistStore,
  OptionalAuth,
  Permissions,
  PermissionsGuard,
  RequirePermissions,
  Roles,
} from "../src";
import type { AuthOptions, IAuthUserService } from "../src";

@Controller("posts")
class PostsController {
  @OptionalAuth()
  @Get()
  feed(@CurrentUser() _user: unknown) {
    return "feed";
  }

  @Permissions("posts:delete")
  @Get("delete")
  remove() {
    return "deleted";
  }

  @RequirePermissions("billing:read")
  @Get("billing")
  billing(@AccessToken() _token: string) {
    return "billing";
  }

  @Roles("user")
  @Get("members")
  members() {
    return "members";
  }
}

@Module({ controllers: [PostsController] })
class PostsModule {}

describe("AuthModule (permissions, optional auth, hierarchy, revocation, GraphQL)", () => {
  const users = [
    { id: "1", email: "editor@example.com", password: "", roles: ["editor"], permissions: ["posts:*"] },
    { id: "2", email: "admin@example.com", password: "", roles: ["admin"], permissions: ["*"] },
  ];
  const userService: IAuthUserService = {
    findOneByField: async (field, value) => users.find((u) => (u as Record<string, unknown>)[field] === value) ?? null,
  };

  async function bootstrap(overrides: Partial<AuthOptions> = {}): Promise<TestingModule> {
    const moduleRef = await Test.createTestingModule({
      imports: [
        EncryptionModule.register({ saltRounds: 4, isGlobal: true }),
        AuthModule.registerAsync({
          inject: [EncryptionService],
          useFactory: (encryption: EncryptionService) => ({
            // No issuer/audience on purpose: regression test for `"issuer" must be a string`.
            jwtSecret: "s".repeat(32),
            expiresIn: "15m",
            identifierField: "email",
            passwordField: "password",
            permissionsField: "permissions",
            roleHierarchy: { admin: ["editor"], editor: ["user"] },
            userService,
            encryptionService: encryption,
            globalLock: true,
            ...overrides,
          }),
        }),
        PostsModule,
      ],
    }).compile();
    await moduleRef.init();
    const encryption = moduleRef.get(EncryptionService);
    for (const u of users) u.password = await encryption.hash("Password123!");
    return moduleRef;
  }

  const http = (handler: keyof PostsController, request: Record<string, unknown>): ExecutionContext =>
    ({
      getHandler: () => PostsController.prototype[handler],
      getClass: () => PostsController,
      getType: () => "http",
      getArgs: () => [request, {}, () => undefined],
      getArgByIndex: (i: number) => [request, {}, () => undefined][i],
      switchToHttp: () => ({ getRequest: () => request, getResponse: () => ({}), getNext: () => undefined }),
    }) as unknown as ExecutionContext;

  const graphql = (handler: keyof PostsController, req: Record<string, unknown>): ExecutionContext =>
    ({
      getHandler: () => PostsController.prototype[handler],
      getClass: () => PostsController,
      getType: () => "graphql",
      getArgs: () => [{}, {}, { req }, {}],
      getArgByIndex: (i: number) => [{}, {}, { req }, {}][i],
    }) as unknown as ExecutionContext;

  async function guards(moduleRef: TestingModule, ctx: ExecutionContext) {
    const reflector = moduleRef.get(Reflector);
    const options = moduleRef.get<AuthOptions>(AUTH_OPTIONS_TOKEN);
    return (
      (await new GlobalJwtAuthGuard(reflector, options).canActivate(ctx)) &&
      new GlobalRolesGuard(reflector, options).canActivate(ctx) &&
      new GlobalPermissionsGuard(reflector, options).canActivate(ctx)
    );
  }

  const bearer = (token: string) => ({ headers: { authorization: `Bearer ${token}` } });
  const login = async (moduleRef: TestingModule, email: string) =>
    (await moduleRef.get(AuthService).login({ email, password: "Password123!" })).accessToken;

  function paramFactory(method: keyof PostsController) {
    const args = Reflect.getMetadata(ROUTE_ARGS_METADATA, PostsController, method);
    return (Object.values(args)[0] as { factory: (data: unknown, ctx: ExecutionContext) => unknown }).factory;
  }

  it("logs in without issuer/audience configured", async () => {
    const moduleRef = await bootstrap();
    await expect(login(moduleRef, "editor@example.com")).resolves.toEqual(expect.any(String));
  });

  describe("@OptionalAuth", () => {
    it("lets anonymous requests through and ignores invalid tokens", async () => {
      const moduleRef = await bootstrap();
      const anonymous: Record<string, unknown> = { headers: {} };
      await expect(guards(moduleRef, http("feed", anonymous))).resolves.toBe(true);
      expect(anonymous.user).toBeFalsy();
      await expect(guards(moduleRef, http("feed", bearer("invalid")))).resolves.toBe(true);
    });

    it("populates the user when a valid token is sent, even without globalLock", async () => {
      const moduleRef = await bootstrap({ globalLock: false });
      const request: Record<string, unknown> = bearer(await login(moduleRef, "editor@example.com"));
      await expect(guards(moduleRef, http("feed", request))).resolves.toBe(true);
      expect(request.user).toMatchObject({ id: "1", permissions: ["posts:*"] });
    });
  });

  describe("permissions", () => {
    it("enforces @Permissions globally with wildcards", async () => {
      const moduleRef = await bootstrap();
      await expect(guards(moduleRef, http("remove", bearer(await login(moduleRef, "editor@example.com"))))).resolves.toBe(true);
    });

    it("@RequirePermissions denies missing permissions and exposes @AccessToken", async () => {
      const moduleRef = await bootstrap({ globalLock: false });
      const guard = moduleRef.get(PermissionsGuard);
      const editor = { user: { id: "1", username: "e", permissions: ["posts:*"] } };
      expect(() => guard.canActivate(http("billing", editor))).toThrow(ForbiddenException);
      expect(guard.canActivate(http("billing", { user: { id: "2", username: "a", permissions: ["*"] } }))).toBe(true);

      const token = await login(moduleRef, "admin@example.com");
      const request: Record<string, unknown> = bearer(token);
      await new GlobalJwtAuthGuard(moduleRef.get(Reflector), { ...moduleRef.get<AuthOptions>(AUTH_OPTIONS_TOKEN), globalLock: true }).canActivate(
        http("billing", request)
      );
      expect(paramFactory("billing")(undefined, http("billing", request))).toBe(token);
    });
  });

  it("applies the role hierarchy (admin → editor → user)", async () => {
    const moduleRef = await bootstrap();
    await expect(guards(moduleRef, http("members", bearer(await login(moduleRef, "admin@example.com"))))).resolves.toBe(true);
    await expect(
      guards(moduleRef, http("members", bearer(await login(moduleRef, "editor@example.com"))))
    ).resolves.toBe(true);
  });

  it("rejects revoked access tokens in the guard", async () => {
    const moduleRef = await bootstrap({ tokenBlacklist: new InMemoryTokenBlacklistStore() });
    const token = await login(moduleRef, "editor@example.com");
    await expect(guards(moduleRef, http("members", bearer(token)))).resolves.toBe(true);
    await moduleRef.get(AuthService).revokeAccessToken(token);
    await expect(guards(moduleRef, http("members", bearer(token)))).rejects.toThrow(UnauthorizedException);
  });

  it("works with GraphQL contexts", async () => {
    const moduleRef = await bootstrap();
    const req: Record<string, unknown> = bearer(await login(moduleRef, "editor@example.com"));
    await expect(guards(moduleRef, graphql("members", req))).resolves.toBe(true);
    expect(req.user).toMatchObject({ id: "1" });
    expect(paramFactory("feed")("id", graphql("feed", req))).toBe("1");
    await expect(guards(moduleRef, graphql("members", { headers: {} }))).rejects.toThrow(UnauthorizedException);
  });

  it("rejects action tokens used as access tokens", async () => {
    const moduleRef = await bootstrap();
    const actionToken = await moduleRef.get(AuthService).createActionToken("1", "email_verification");
    await expect(guards(moduleRef, http("members", bearer(actionToken)))).rejects.toThrow(UnauthorizedException);
  });
});
