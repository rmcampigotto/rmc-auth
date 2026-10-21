import { Body, Controller, Get, HttpCode, Inject, Post, Req, Res, Type, UnauthorizedException, UseGuards } from "@nestjs/common";
import { MODULE_OPTIONS_TOKEN } from "../modules/auth/auth.module-definition";
import { AuthService } from "../modules/auth/auth.service";
import type { AuthOptions } from "../interfaces/auth.options";
import type { AuthContext, AuthTokens, RequestUser } from "../types/auth.types";
import { JwtAuthGuard } from "../guards/jwt-auth.guard";
import { Public } from "../decorators/public.decorator";
import { AccessToken, CurrentUser } from "../decorators/current-user.decorator";
import { AuthCtx } from "../decorators/auth-context.decorator";
import { getRequestCookie } from "../utils/cookie.util";

export type AuthControllerRoute = "login" | "refresh" | "logout" | "me" | "twoFactor" | "changePassword";

export interface AuthControllerOptions {
  /** Route prefix. @default 'auth' */
  path?: string;
  /**
   * Store tokens in httpOnly cookies (`setAuthCookies`) instead of returning them in the body.
   * Only the tokens with a configured cookie name are moved to cookies.
   * @default true when `accessTokenCookieName` or `refreshTokenCookieName` is set
   */
  cookies?: boolean;
  /** Routes to leave out. */
  exclude?: AuthControllerRoute[];
}

type Body = Record<string, unknown> | undefined;

/**
 * Creates a ready-to-use controller with the common auth routes. Add it to `controllers` of any module:
 *
 * | Route | |
 * |---|---|
 * | `POST /auth/login` | `{ <identifierField>, <passwordField> }` → tokens (401 with `mfaToken` when 2FA is required) |
 * | `POST /auth/two-factor/verify` | `{ mfaToken, code }` → tokens |
 * | `POST /auth/refresh` | `{ refreshToken }` or the refresh cookie → new tokens |
 * | `POST /auth/logout` | logs out the current device (204) |
 * | `GET /auth/me` | the authenticated user |
 * | `POST /auth/change-password` | `{ currentPassword, newPassword }` (204) |
 *
 * @example
 * @Module({ controllers: [createAuthController({ path: 'auth' })] })
 */
export function createAuthController(controllerOptions: AuthControllerOptions = {}): Type<unknown> {
  const exclude = new Set(controllerOptions.exclude ?? []);

  @Controller(controllerOptions.path ?? "auth")
  class AuthController {
    constructor(
      @Inject(AuthService) readonly authService: AuthService,
      @Inject(MODULE_OPTIONS_TOKEN) readonly options: AuthOptions
    ) {}

    get useCookies(): boolean {
      return controllerOptions.cookies ?? Boolean(this.options.accessTokenCookieName || this.options.refreshTokenCookieName);
    }

    respond(tokens: AuthTokens, response: unknown): Partial<AuthTokens> {
      if (!this.useCookies) return tokens;
      this.authService.setAuthCookies(response, tokens);
      const body: Partial<AuthTokens> = { ...tokens };
      if (this.options.accessTokenCookieName) delete body.accessToken;
      if (this.options.refreshTokenCookieName) delete body.refreshToken;
      return body;
    }

    async login(@Body() body: Body, @AuthCtx() context: AuthContext, @Res({ passthrough: true }) response: unknown) {
      return this.respond(await this.authService.login(body ?? {}, context), response);
    }

    async verifyTwoFactor(@Body() body: Body, @AuthCtx() context: AuthContext, @Res({ passthrough: true }) response: unknown) {
      const { mfaToken, code } = body ?? {};
      if (typeof mfaToken !== "string" || typeof code !== "string") throw new UnauthorizedException("Invalid token");
      return this.respond(await this.authService.verifyTwoFactorLogin(mfaToken, code, context), response);
    }

    async refresh(
      @Body() body: Body,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      @Req() request: any,
      @AuthCtx() context: AuthContext,
      @Res({ passthrough: true }) response: unknown
    ) {
      const fromBody = body?.refreshToken;
      const cookieName = this.options.refreshTokenCookieName;
      const token = typeof fromBody === "string" && fromBody ? fromBody : cookieName ? getRequestCookie(request, cookieName) : undefined;
      return this.respond(await this.authService.refresh(token as string, context), response);
    }

    async logout(
      @CurrentUser() user: RequestUser,
      @AccessToken() accessToken: string | undefined,
      @AuthCtx() context: AuthContext,
      @Res({ passthrough: true }) response: unknown
    ) {
      await this.authService.logoutCurrentSession(user, accessToken, context);
      if (this.useCookies) this.authService.clearAuthCookies(response);
    }

    me(@CurrentUser() user: RequestUser) {
      return user;
    }

    async changePassword(@CurrentUser("id") userId: string, @Body() body: Body, @AuthCtx() context: AuthContext) {
      const { currentPassword, newPassword } = body ?? {};
      await this.authService.changePassword(userId, currentPassword as string, newPassword as string, context);
    }
  }

  // Route decorators are applied here so excluded routes are not registered at all.
  const routes: Record<AuthControllerRoute, [keyof AuthController, MethodDecorator[]]> = {
    login: ["login", [Public(), Post("login"), HttpCode(200)]],
    twoFactor: ["verifyTwoFactor", [Public(), Post("two-factor/verify"), HttpCode(200)]],
    refresh: ["refresh", [Public(), Post("refresh"), HttpCode(200)]],
    logout: ["logout", [Post("logout"), HttpCode(204), UseGuards(JwtAuthGuard)]],
    me: ["me", [Get("me"), UseGuards(JwtAuthGuard)]],
    changePassword: ["changePassword", [Post("change-password"), HttpCode(204), UseGuards(JwtAuthGuard)]],
  };
  for (const [route, [method, decorators]] of Object.entries(routes) as [AuthControllerRoute, (typeof routes)[AuthControllerRoute]][]) {
    if (exclude.has(route)) continue;
    const descriptor = Object.getOwnPropertyDescriptor(AuthController.prototype, method)!;
    Object.defineProperty(AuthController.prototype, method, Reflect.decorate(decorators, AuthController.prototype, method, descriptor) as PropertyDescriptor);
  }

  return AuthController;
}
