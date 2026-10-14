import { Injectable, Inject } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy, JwtFromRequestFunction } from "passport-jwt";
import { MODULE_OPTIONS_TOKEN } from "../modules/auth/auth.module-definition";
import type { AuthOptions } from "../interfaces/auth.options";
import type { JwtPayload, RequestUser } from "../types/auth.types";
import { ACCESS_TOKEN_REQUEST_KEY } from "../utils/request.util";

const STANDARD_CLAIMS = ["sub", "username", "roles", "permissions", "type", "purpose", "sid", "jti", "iat", "exp", "nbf", "iss", "aud"];

function cookieExtractor(cookieName: string): JwtFromRequestFunction {
  return (req) => {
    const cookies = (req as unknown as { cookies?: Record<string, unknown> })?.cookies;
    const value = cookies?.[cookieName];
    return typeof value === "string" && value ? value : null;
  };
}

function buildExtractor(options: AuthOptions): JwtFromRequestFunction {
  const extractors: JwtFromRequestFunction[] = [ExtractJwt.fromAuthHeaderAsBearerToken()];
  if (options.accessTokenCookieName) {
    extractors.push(cookieExtractor(options.accessTokenCookieName));
  }
  return ExtractJwt.fromExtractors(extractors);
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  private readonly extractToken: JwtFromRequestFunction;

  constructor(@Inject(MODULE_OPTIONS_TOKEN) private readonly options: AuthOptions) {
    const extractor = buildExtractor(options);
    super({
      jwtFromRequest: extractor,
      ignoreExpiration: false,
      secretOrKey: options.jwtSecret,
      issuer: options.jwtIssuer,
      audience: options.jwtAudience,
      algorithms: [options.jwtAlgorithm ?? "HS256"],
      jsonWebTokenOptions: options.clockToleranceSeconds
        ? { clockTolerance: options.clockToleranceSeconds }
        : undefined,
      passReqToCallback: true,
    });
    this.extractToken = extractor;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async validate(request: any, payload: JwtPayload): Promise<RequestUser | null> {
    // Only access tokens authenticate requests (refresh and action tokens are rejected).
    if (!payload || !payload.sub || (payload.type !== undefined && payload.type !== "access")) return null;

    if (this.options.tokenBlacklist && payload.jti && (await this.options.tokenBlacklist.has(payload.jti))) {
      return null;
    }

    const claims: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(payload)) {
      if (!STANDARD_CLAIMS.includes(key)) claims[key] = value;
    }

    const user: RequestUser = { id: payload.sub, username: payload.username, roles: payload.roles, authMethod: "jwt" };
    if (typeof payload.sid === "string") user.sessionId = payload.sid;
    if (Array.isArray(payload.permissions)) user.permissions = payload.permissions;
    if (Object.keys(claims).length > 0) user.claims = claims;

    let result: RequestUser | null = user;
    if (this.options.validateJwtPayload) {
      result = (await this.options.validateJwtPayload(payload, user)) || null;
    }
    if (result && request && typeof request === "object") {
      request[ACCESS_TOKEN_REQUEST_KEY] = this.extractToken(request) ?? undefined;
    }
    return result;
  }
}
