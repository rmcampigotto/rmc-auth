import { Injectable, Inject } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy, JwtFromRequestFunction } from "passport-jwt";
import { MODULE_OPTIONS_TOKEN } from "../modules/auth/auth.module-definition";
import type { AuthOptions } from "../interfaces/auth.options";
import type { JwtPayload, RequestUser } from "../types/auth.types";

const STANDARD_CLAIMS = ["sub", "username", "roles", "type", "jti", "iat", "exp", "nbf", "iss", "aud"];

function cookieExtractor(cookieName: string): JwtFromRequestFunction {
  return (req) => {
    const cookies = (req as unknown as { cookies?: Record<string, unknown> })?.cookies;
    const value = cookies?.[cookieName];
    return typeof value === "string" && value ? value : null;
  };
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(@Inject(MODULE_OPTIONS_TOKEN) private readonly options: AuthOptions) {
    const extractors: JwtFromRequestFunction[] = [ExtractJwt.fromAuthHeaderAsBearerToken()];
    if (options.accessTokenCookieName) {
      extractors.push(cookieExtractor(options.accessTokenCookieName));
    }
    super({
      jwtFromRequest: ExtractJwt.fromExtractors(extractors),
      ignoreExpiration: false,
      secretOrKey: options.jwtSecret,
      issuer: options.jwtIssuer,
      audience: options.jwtAudience,
      algorithms: [options.jwtAlgorithm ?? "HS256"],
      jsonWebTokenOptions: options.clockToleranceSeconds
        ? { clockTolerance: options.clockToleranceSeconds }
        : undefined,
    });
  }

  async validate(payload: JwtPayload): Promise<RequestUser | null> {
    // Refresh tokens must never authenticate requests.
    if (!payload || !payload.sub || payload.type === "refresh") return null;

    const claims: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(payload)) {
      if (!STANDARD_CLAIMS.includes(key)) claims[key] = value;
    }

    const user: RequestUser = { id: payload.sub, username: payload.username, roles: payload.roles };
    if (Object.keys(claims).length > 0) user.claims = claims;

    if (this.options.validateJwtPayload) {
      const result = await this.options.validateJwtPayload(payload, user);
      return result || null;
    }
    return user;
  }
}
