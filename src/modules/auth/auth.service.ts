import { Inject, Injectable, UnauthorizedException } from "@nestjs/common";
import { MODULE_OPTIONS_TOKEN } from "./auth.module-definition";
import type { AuthOptions } from "../../interfaces/auth.options";
import { JwtService } from "@nestjs/jwt";
import type { IEncryptionService } from "../../interfaces/encryption-service.interface";

@Injectable()
export class AuthService {
  constructor(
    @Inject(MODULE_OPTIONS_TOKEN) private authOptions: AuthOptions,
    private readonly jwtService: JwtService,
    @Inject('ENCRYPTION_SERVICE') private readonly encryptionService: IEncryptionService
  ) {};

  async generateTokens(user: any) {
    const rolesField = this.authOptions.rolesField || 'roles';
    const payload = { sub: user.id, username: user[this.authOptions.identifierField], roles: user[rolesField] };
    const accessToken = await this.jwtService.signAsync(payload, {
      secret: this.authOptions.jwtSecret,
      expiresIn: this.authOptions.expiresIn
    });

    let refreshToken = null;

    if (this.authOptions.useRefreshTokens) {
      refreshToken = await this.jwtService.signAsync(payload, {
        secret: this.authOptions.refreshSecret || this.authOptions.jwtSecret,
        expiresIn: this.authOptions.refreshExpiresIn || '7d',
      });
      if (!this.authOptions.userService.saveRefreshToken) {
        throw new Error('userService must implement saveRefreshToken to use Refresh Tokens');
      };
      await this.authOptions.userService.saveRefreshToken(user.id, refreshToken);
    };

    return { accessToken, refreshToken };
  };

  async refresh(rt: string) {
    try {
      const payload = await this.jwtService.verifyAsync(rt, {
        secret: this.authOptions.refreshSecret || this.authOptions.jwtSecret,
      });
      const user = await this.authOptions.userService.findOneByField('id', payload.sub);

      if (this.authOptions.userService.isRefreshTokenValid) {
        const isValid = await this.authOptions.userService.isRefreshTokenValid(user.id, rt);
        if (!isValid) {
          if (this.authOptions.userService.revokeAllTokens) {
            await this.authOptions.userService.revokeAllTokens(user.id);
          };
          throw new UnauthorizedException('Refresh Token compromised.');
        };
      };

      return this.generateTokens(user);
    } catch (e) {
      throw new UnauthorizedException('Invalid Refresh Token');
    };
  };

  /**
   * Realiza a autenticação completa do usuário.
   * 1. Busca o usuário pelo identificador.
   * 2. Compara as senhas usando o serviço de encriptação.
   * 3. Gera o par de tokens (Access e Refresh se habilitado).
   * @param credentials Objeto contendo os campos de login e senha.
   * @throws UnauthorizedException se as credenciais forem inválidas.
   */
  async login(credentials: Record<string, any>) {
    const identifier = credentials[this.authOptions.identifierField];
    const password = credentials[this.authOptions.passwordField];
    const user = await this.authOptions.userService.findOneByField(
      this.authOptions.identifierField,
      identifier
    );

    if(!user) throw new UnauthorizedException('Invalid Credentials');

    const isPasswordValid = await this.encryptionService.compare(
      password,
      user[this.authOptions.passwordField]
    );

    if(!isPasswordValid) throw new UnauthorizedException('Invalid Credentials');

    return this.generateTokens(user);
  };

};