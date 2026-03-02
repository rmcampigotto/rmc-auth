import { Injectable, Inject } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { MODULE_OPTIONS_TOKEN } from "../modules/auth/auth.module-definition";
import type { AuthOptions } from "../interfaces/auth.options";

export interface JwtPayload {
  sub: string;
  username: string;
  roles?: string[];
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(@Inject(MODULE_OPTIONS_TOKEN) options: AuthOptions) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: options.jwtSecret,
      issuer: options.jwtIssuer,
      audience: options.jwtAudience,
    });
  };

  async validate(payload: JwtPayload) {
    return { id: payload.sub, username: payload.username, roles: payload.roles };
  };

};