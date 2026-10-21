import { Controller, ExecutionContext, Get, Module, UnauthorizedException, ForbiddenException } from "@nestjs/common";
import { Test, TestingModule } from "@nestjs/testing";
import { Reflector } from "@nestjs/core";
import {
  AUTH_OPTIONS_TOKEN,
  AuthModule,
  AuthService,
  Authorize,
  AuthorizeAll,
  CurrentUser,
  EncryptionModule,
  EncryptionService,
  GlobalJwtAuthGuard,
  GlobalRolesGuard,
  JwtAuthGuard,
  Public,
  Roles,
} from "../src";
import type { AuthOptions, IAuthUserService, RequestUser } from "../src";
import { ROUTE_ARGS_METADATA } from "@nestjs/common/constants";

@Controller("items")
class ItemsController {
  @Public()
  @Get("public")
  open() {
    return "open";
  }

  @Get("private")
  closed(@CurrentUser() user: RequestUser) {
    return user;
  }

  @Roles("admin")
  @Get("admin")
  admin() {
    return "admin";
  }

  @Authorize("user")
  @Get("authorize")
  authorized() {
    return "ok";
  }

  @AuthorizeAll("user", "admin")
  @Get("all")
  all() {
    return "ok";
  }
}

// Feature module: guards used via @Authorize must resolve without importing AuthModule here.
@Module({ controllers: [ItemsController] })
class ItemsModule {}

describe("AuthModule (full wiring)", () => {
  const users = [
    { id: "1", email: "user@example.com", password: "", roles: ["user"] },
    { id: "2", email: "admin@example.com", password: "", roles: ["user", "admin"] },
  ];

  const userService: IAuthUserService = {
    findOneByField: async (field, value) => users.find((u) => (u as Record<string, unknown>)[field] === value) ?? null,
    saveRefreshToken: async () => undefined,
    isRefreshTokenValid: async () => true,
    revokeAllTokens: async () => undefined,
  };

  async function bootstrap(overrides: Partial<AuthOptions> = {}): Promise<TestingModule> {
    const moduleRef = await Test.createTestingModule({
      imports: [
        EncryptionModule.register({ saltRounds: 4, isGlobal: true }),
        AuthModule.registerAsync({
          inject: [EncryptionService],
          useFactory: (encryption: EncryptionService) => ({
            jwtSecret: "a".repeat(32),
            refreshSecret: "b".repeat(32),
            expiresIn: "15m",
            jwtIssuer: "test",
            jwtAudience: "test",
            identifierField: "email",
            passwordField: "password",
            userService,
            encryptionService: encryption,
            useRefreshTokens: true,
            globalLock: true,
            strictMode: true,
            accessTokenCookieName: "access_token",
            ...overrides,
          }),
        }),
        ItemsModule,
      ],
    }).compile();
    await moduleRef.init();
    const encryption = moduleRef.get(EncryptionService);
    for (const u of users) u.password = await encryption.hash("Password123!");
    return moduleRef;
  }

  function context(handler: keyof ItemsController, request: Record<string, unknown>): ExecutionContext {
    return {
      getHandler: () => ItemsController.prototype[handler],
      getClass: () => ItemsController,
      getType: () => "http",
      getArgs: () => [request, {}, () => undefined],
      getArgByIndex: (i: number) => [request, {}, () => undefined][i],
      switchToHttp: () => ({ getRequest: () => request, getResponse: () => ({}), getNext: () => undefined }),
    } as unknown as ExecutionContext;
  }

  async function runGlobalGuards(moduleRef: TestingModule, handler: keyof ItemsController, request: Record<string, unknown>) {
    const reflector = moduleRef.get(Reflector);
    const options = moduleRef.get<AuthOptions>(AUTH_OPTIONS_TOKEN);
    const jwtGuard = new GlobalJwtAuthGuard(reflector, options);
    const rolesGuard = new GlobalRolesGuard(reflector, options);
    const ctx = context(handler, request);
    return (await jwtGuard.canActivate(ctx)) && rolesGuard.canActivate(ctx);
  }

  async function tokenFor(moduleRef: TestingModule, email: string) {
    return (await moduleRef.get(AuthService).login({ email, password: "Password123!" })).accessToken;
  }

  it("boots with strict mode and resolves guards in feature modules", async () => {
    const moduleRef = await bootstrap();
    expect(moduleRef.get(AuthService)).toBeDefined();
    expect(moduleRef.get(JwtAuthGuard)).toBeDefined();
  });

  it("fails fast on invalid configuration", async () => {
    await expect(bootstrap({ refreshSecret: "a".repeat(32) })).rejects.toThrow("refreshSecret");
    await expect(bootstrap({ expiresIn: "2h" })).rejects.toThrow("expiresIn");
    await expect(bootstrap({ expiresIn: "soon" })).rejects.toThrow("invalid 'expiresIn'");
    await expect(bootstrap({ cookieOptions: { secure: false } })).rejects.toThrow("cookieOptions.secure");
    await expect(bootstrap({ strictMode: false, cookieOptions: { sameSite: "none", secure: false } })).rejects.toThrow("sameSite");
    const { isRefreshTokenValid: _, ...withoutReuseDetection } = userService;
    await expect(bootstrap({ userService: withoutReuseDetection })).rejects.toThrow("isRefreshTokenValid");
  });

  it("globalLock: allows @Public routes and blocks anonymous requests", async () => {
    const moduleRef = await bootstrap();
    await expect(runGlobalGuards(moduleRef, "open", { headers: {} })).resolves.toBe(true);
    await expect(runGlobalGuards(moduleRef, "closed", { headers: {} })).rejects.toThrow(UnauthorizedException);
  });

  it("authenticates with a Bearer header or cookie and exposes @CurrentUser", async () => {
    const moduleRef = await bootstrap();
    const token = await tokenFor(moduleRef, "user@example.com");

    const viaHeader: Record<string, unknown> = { headers: { authorization: `Bearer ${token}` } };
    await expect(runGlobalGuards(moduleRef, "closed", viaHeader)).resolves.toBe(true);
    expect(viaHeader.user).toMatchObject({ id: "1", username: "user@example.com", roles: ["user"] });

    const viaCookie: Record<string, unknown> = { headers: {}, cookies: { access_token: token } };
    await expect(runGlobalGuards(moduleRef, "closed", viaCookie)).resolves.toBe(true);

    const args = Reflect.getMetadata(ROUTE_ARGS_METADATA, ItemsController, "closed");
    const { factory } = Object.values(args)[0] as { factory: (data: unknown, ctx: ExecutionContext) => unknown };
    expect(factory(undefined, context("closed", viaHeader))).toMatchObject({ id: "1" });
    expect(factory("id", context("closed", viaHeader))).toBe("1");
  });

  it("rejects refresh tokens used as access tokens", async () => {
    const moduleRef = await bootstrap();
    const { refreshToken } = await moduleRef.get(AuthService).login({ email: "user@example.com", password: "Password123!" });
    await expect(
      runGlobalGuards(moduleRef, "closed", { headers: { authorization: `Bearer ${refreshToken}` } })
    ).rejects.toThrow(UnauthorizedException);
  });

  it("enforces @Roles globally when globalLock is true", async () => {
    const moduleRef = await bootstrap();
    const userToken = await tokenFor(moduleRef, "user@example.com");
    const adminToken = await tokenFor(moduleRef, "admin@example.com");
    await expect(
      runGlobalGuards(moduleRef, "admin", { headers: { authorization: `Bearer ${userToken}` } })
    ).rejects.toThrow(ForbiddenException);
    await expect(
      runGlobalGuards(moduleRef, "admin", { headers: { authorization: `Bearer ${adminToken}` } })
    ).resolves.toBe(true);
  });

  it("global guards are no-ops when globalLock is false", async () => {
    const moduleRef = await bootstrap({ globalLock: false });
    await expect(runGlobalGuards(moduleRef, "closed", { headers: {} })).resolves.toBe(true);
  });

  it("@AuthorizeAll requires every role", async () => {
    const moduleRef = await bootstrap({ globalLock: false });
    const { RolesGuard } = await import("../src");
    const guard = moduleRef.get(RolesGuard);
    expect(() => guard.canActivate(context("all", { user: { id: "1", username: "u", roles: ["user"] } }))).toThrow(
      ForbiddenException
    );
    expect(guard.canActivate(context("all", { user: { id: "2", username: "a", roles: ["user", "admin"] } }))).toBe(true);
  });

  it("validateJwtPayload can reject authenticated requests", async () => {
    const moduleRef = await bootstrap({ validateJwtPayload: (payload) => payload.sub !== "1" && null });
    const token = await tokenFor(moduleRef, "user@example.com");
    await expect(
      runGlobalGuards(moduleRef, "closed", { headers: { authorization: `Bearer ${token}` } })
    ).rejects.toThrow(UnauthorizedException);
  });
});
