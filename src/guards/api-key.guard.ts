import { CanActivate, ExecutionContext, Inject, Injectable, Optional, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { API_KEY_AUTH_KEY, ApiKeyAuthOptions } from "../decorators/api-key.decorator";
import { MODULE_OPTIONS_TOKEN } from "../modules/auth/auth.module-definition";
import type { AuthOptions } from "../interfaces/auth.options";
import { hashToken } from "../security/token.util";
import { getRequestFromContext } from "../utils/request.util";
import { JwtAuthGuard } from "./jwt-auth.guard";

const MAX_API_KEY_LENGTH = 512;

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    @Optional() @Inject(MODULE_OPTIONS_TOKEN) private readonly options?: AuthOptions,
    @Optional() private readonly jwtGuard?: JwtAuthGuard
  ) {}

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private extractKey(request: any): string | null {
    const headers = request?.headers ?? {};
    const headerName = (this.options?.apiKeyHeader ?? "x-api-key").toLowerCase();
    const direct = headers[headerName];
    if (typeof direct === "string" && direct) return direct;
    const authorization = headers.authorization;
    if (typeof authorization === "string" && authorization.startsWith("ApiKey ")) return authorization.slice(7).trim();
    return null;
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const config =
      this.reflector.getAllAndOverride<ApiKeyAuthOptions>(API_KEY_AUTH_KEY, [context.getHandler(), context.getClass()]) ?? {};
    const request = getRequestFromContext(context);
    const key = this.extractKey(request);

    if (!key) {
      if (config.allowJwt && this.jwtGuard) {
        return (await this.jwtGuard.canActivate(context)) as boolean;
      }
      throw new UnauthorizedException("Access denied: Invalid or missing API key");
    }

    const service = this.options?.apiKeyService;
    if (!service) throw new Error("AuthModule: 'apiKeyService' is required for @ApiKeyAuth() routes");
    if (key.length > MAX_API_KEY_LENGTH) throw new UnauthorizedException("Access denied: Invalid or missing API key");

    const user = await service.validateApiKey(hashToken(key), { ip: request?.ip });
    if (!user) throw new UnauthorizedException("Access denied: Invalid or missing API key");
    request.user = { ...user, authMethod: "api_key" };
    return true;
  }
}
