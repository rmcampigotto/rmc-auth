import { INestApplication, Module } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import request from "supertest";
import cookieParser from "cookie-parser";
import {
  AuthModule,
  AuthOptions,
  AuthControllerOptions,
  createAuthController,
  EncryptionModule,
  EncryptionService,
  IAuthUserService,
  InMemoryTokenBlacklistStore,
} from "../src";

describe("createAuthController (HTTP)", () => {
  let app: INestApplication;
  let sessions: Map<string, string>;
  const user = { id: "1", email: "user@example.com", password: "", roles: ["user"] };

  const userService: Required<Pick<IAuthUserService, "findOneByField" | "saveRefreshToken" | "isRefreshTokenValid" | "revokeAllTokens" | "revokeSession" | "updatePasswordHash">> = {
    findOneByField: async (field, value) => ((user as Record<string, unknown>)[field] === value ? { ...user } : null),
    saveRefreshToken: async (_id, token, session) => {
      sessions.set(session!.sessionId, token);
    },
    isRefreshTokenValid: async (_id, token, session) => sessions.get(session!.sessionId) === token,
    revokeAllTokens: async () => sessions.clear(),
    revokeSession: async (_id, sessionId) => {
      sessions.delete(sessionId);
    },
    updatePasswordHash: async (_id, hash) => {
      user.password = hash;
    },
  };

  async function start(overrides: Partial<AuthOptions> = {}, controllerOptions: AuthControllerOptions = {}) {
    @Module({ controllers: [createAuthController(controllerOptions)] })
    class AppModule {}

    const moduleRef = await Test.createTestingModule({
      imports: [
        EncryptionModule.register({ saltRounds: 4, isGlobal: true }),
        AuthModule.registerAsync({
          inject: [EncryptionService],
          useFactory: (encryption: EncryptionService) => ({
            jwtSecret: "a".repeat(32),
            refreshSecret: "b".repeat(32),
            expiresIn: "15m",
            identifierField: "email",
            passwordField: "password",
            useRefreshTokens: true,
            globalLock: true,
            tokenBlacklist: new InMemoryTokenBlacklistStore(),
            userService,
            encryptionService: encryption,
            ...overrides,
          }),
        }),
        AppModule,
      ],
    }).compile();
    app = moduleRef.createNestApplication({ logger: false });
    app.use(cookieParser());
    await app.init();
    user.password = await moduleRef.get(EncryptionService).hash("Password123!");
  }

  beforeEach(() => {
    sessions = new Map();
  });

  afterEach(async () => {
    await app?.close();
  });

  const login = () => request(app.getHttpServer()).post("/auth/login").send({ email: user.email, password: "Password123!" });

  it("logs in, reads /me, refreshes and logs out the current session", async () => {
    await start();
    const res = await login().expect(200);
    expect(res.body).toMatchObject({ accessToken: expect.any(String), refreshToken: expect.any(String), tokenType: "Bearer" });
    const auth = { Authorization: `Bearer ${res.body.accessToken}` };

    await request(app.getHttpServer()).get("/auth/me").set(auth).expect(200).expect((r) => expect(r.body).toMatchObject({ id: "1" }));
    await request(app.getHttpServer()).get("/auth/me").expect(401);

    const refreshed = await request(app.getHttpServer()).post("/auth/refresh").send({ refreshToken: res.body.refreshToken }).expect(200);
    expect(refreshed.body.refreshToken).not.toBe(res.body.refreshToken);

    await request(app.getHttpServer()).post("/auth/logout").set(auth).expect(204);
    await request(app.getHttpServer()).get("/auth/me").set(auth).expect(401); // access token revoked
    await request(app.getHttpServer()).post("/auth/refresh").send({ refreshToken: refreshed.body.refreshToken }).expect(401);
  });

  it("rejects wrong credentials and invalid bodies", async () => {
    await start();
    await request(app.getHttpServer()).post("/auth/login").send({ email: user.email, password: "nope" }).expect(401);
    await request(app.getHttpServer()).post("/auth/login").send({}).expect(400);
    await request(app.getHttpServer()).post("/auth/two-factor/verify").send({ mfaToken: 1 }).expect(401);
  });

  it("logging out one device keeps the others", async () => {
    await start();
    const a = await login();
    const b = await login();
    await request(app.getHttpServer()).post("/auth/logout").set({ Authorization: `Bearer ${a.body.accessToken}` }).expect(204);
    await request(app.getHttpServer()).post("/auth/refresh").send({ refreshToken: b.body.refreshToken }).expect(200);
  });

  it("uses httpOnly cookies when cookie names are configured", async () => {
    await start({
      accessTokenCookieName: "access_token",
      refreshTokenCookieName: "refresh_token",
      cookieOptions: { refreshTokenPath: "/auth" },
    });
    const res = await login().expect(200);
    expect(res.body.accessToken).toBeUndefined();
    expect(res.body.refreshToken).toBeUndefined();
    const cookies = res.headers["set-cookie"] as unknown as string[];
    expect(cookies).toEqual([
      expect.stringMatching(/^access_token=.+; Max-Age=900; Path=\/; .*HttpOnly; Secure; SameSite=Strict/),
      expect.stringMatching(/^refresh_token=.+; Max-Age=604800; Path=\/auth; .*HttpOnly; Secure; SameSite=Strict/),
    ]);
    const cookieHeader = cookies.map((c) => c.split(";")[0]).join("; ");

    await request(app.getHttpServer()).get("/auth/me").set("Cookie", cookieHeader).expect(200);
    const refreshed = await request(app.getHttpServer()).post("/auth/refresh").set("Cookie", cookieHeader).expect(200);
    expect(refreshed.headers["set-cookie"]).toHaveLength(2);

    const newCookies = (refreshed.headers["set-cookie"] as unknown as string[]).map((c) => c.split(";")[0]).join("; ");
    const logout = await request(app.getHttpServer()).post("/auth/logout").set("Cookie", newCookies).expect(204);
    expect(logout.headers["set-cookie"]).toEqual([expect.stringMatching(/^access_token=;/), expect.stringMatching(/^refresh_token=;/)]);
  });

  it("changes the password", async () => {
    await start();
    const { body } = await login();
    await request(app.getHttpServer())
      .post("/auth/change-password")
      .set({ Authorization: `Bearer ${body.accessToken}` })
      .send({ currentPassword: "Password123!", newPassword: "N3w-Password!" })
      .expect(204);
    await request(app.getHttpServer()).post("/auth/login").send({ email: user.email, password: "N3w-Password!" }).expect(200);
  });

  it("supports a custom path and excluded routes", async () => {
    await start({}, { path: "session", exclude: ["changePassword", "me"] });
    await request(app.getHttpServer()).post("/session/login").send({ email: user.email, password: "Password123!" }).expect(200);
    await request(app.getHttpServer()).post("/session/change-password").expect(404);
    await request(app.getHttpServer()).get("/session/me").expect(404);
  });
});
