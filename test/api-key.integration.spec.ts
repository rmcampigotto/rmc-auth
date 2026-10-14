import { Controller, ExecutionContext, Get, Module, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { Test, TestingModule } from "@nestjs/testing";
import {
  ApiKeyAuth,
  ApiKeyGuard,
  AUTH_OPTIONS_TOKEN,
  AuthModule,
  AuthService,
  EncryptionModule,
  EncryptionService,
  generateApiKey,
  GlobalJwtAuthGuard,
  GlobalPermissionsGuard,
  Permissions,
} from "../src";
import type { AuthOptions, IApiKeyService, IAuthUserService } from "../src";

@Controller("integrations")
class IntegrationsController {
  @ApiKeyAuth()
  @Permissions("reports:read")
  @Get("reports")
  reports() {
    return "reports";
  }

  @ApiKeyAuth({ allowJwt: true })
  @Get("hybrid")
  hybrid() {
    return "hybrid";
  }
}

@Module({ controllers: [IntegrationsController] })
class IntegrationsModule {}

describe("API keys (ApiKeyGuard)", () => {
  const issued = generateApiKey("sk_test");
  const keys = new Map([[issued.hash, { id: "client-1", username: "Reporting bot", permissions: ["reports:read"] }]]);
  const apiKeyService: IApiKeyService = { validateApiKey: jest.fn(async (hash) => keys.get(hash) ?? null) };
  const users = [{ id: "1", email: "user@example.com", password: "" }];
  const userService: IAuthUserService = {
    findOneByField: async (field, value) => users.find((u) => (u as Record<string, unknown>)[field] === value) ?? null,
  };

  let moduleRef: TestingModule;

  beforeAll(async () => {
    moduleRef = await Test.createTestingModule({
      imports: [
        EncryptionModule.register({ saltRounds: 4, isGlobal: true }),
        AuthModule.registerAsync({
          inject: [EncryptionService],
          useFactory: (encryption: EncryptionService) => ({
            jwtSecret: "s".repeat(32),
            expiresIn: "15m",
            identifierField: "email",
            passwordField: "password",
            userService,
            encryptionService: encryption,
            apiKeyService,
            globalLock: true,
          }),
        }),
        IntegrationsModule,
      ],
    }).compile();
    await moduleRef.init();
    users[0].password = await moduleRef.get(EncryptionService).hash("Password123!");
  });

  const http = (handler: keyof IntegrationsController, request: Record<string, unknown>): ExecutionContext =>
    ({
      getHandler: () => IntegrationsController.prototype[handler],
      getClass: () => IntegrationsController,
      getType: () => "http",
      getArgs: () => [request, {}, () => undefined],
      getArgByIndex: (i: number) => [request, {}, () => undefined][i],
      switchToHttp: () => ({ getRequest: () => request, getResponse: () => ({}), getNext: () => undefined }),
    }) as unknown as ExecutionContext;

  async function run(handler: keyof IntegrationsController, request: Record<string, unknown>) {
    const reflector = moduleRef.get(Reflector);
    const options = moduleRef.get<AuthOptions>(AUTH_OPTIONS_TOKEN);
    const ctx = http(handler, request);
    return (
      (await new GlobalJwtAuthGuard(reflector, options).canActivate(ctx)) &&
      (await moduleRef.get(ApiKeyGuard).canActivate(ctx)) &&
      new GlobalPermissionsGuard(reflector, options).canActivate(ctx)
    );
  }

  it("authenticates with the x-api-key header and enforces permissions", async () => {
    const request: Record<string, unknown> = { headers: { "x-api-key": issued.key } };
    await expect(run("reports", request)).resolves.toBe(true);
    expect(request.user).toMatchObject({ id: "client-1", authMethod: "api_key" });
    expect(apiKeyService.validateApiKey).toHaveBeenCalledWith(issued.hash, expect.any(Object));
  });

  it("accepts Authorization: ApiKey <key>", async () => {
    await expect(run("reports", { headers: { authorization: `ApiKey ${issued.key}` } })).resolves.toBe(true);
  });

  it("rejects missing or unknown keys", async () => {
    await expect(run("reports", { headers: {} })).rejects.toThrow(UnauthorizedException);
    await expect(run("reports", { headers: { "x-api-key": "sk_test_unknown" } })).rejects.toThrow(UnauthorizedException);
  });

  it("allowJwt accepts a Bearer token when no key is sent", async () => {
    const { accessToken } = await moduleRef.get(AuthService).login({ email: "user@example.com", password: "Password123!" });
    const request: Record<string, unknown> = { headers: { authorization: `Bearer ${accessToken}` } };
    await expect(run("hybrid", request)).resolves.toBe(true);
    expect(request.user).toMatchObject({ id: "1", authMethod: "jwt" });
  });

  it("AuthService.validateApiKey resolves the owner of a key", async () => {
    await expect(moduleRef.get(AuthService).validateApiKey(issued.key)).resolves.toMatchObject({ id: "client-1" });
    await expect(moduleRef.get(AuthService).validateApiKey("nope")).resolves.toBeNull();
  });
});
