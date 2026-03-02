import { IEncryptionService } from "./encryption-service.interface";
import { IAuthUserService } from "./user-service.interface";

export interface AuthOptions {
  /** * Chave secreta para assinar o JWT. 
   * @example 'minha-chave-ultra-secreta'
   */
  jwtSecret: string;
  /** * Tempo de vida do Access Token. 
   * Pode ser um número (segundos) ou uma string (ex: '15m', '1h').
   */
  expiresIn: string | number;
  /** Nome do campo de login (ex: 'email', 'usename', etc). */
  identifierField: string;
  /** Nome do campo de senha (ex: 'password', 'senha', etc). */
  passwordField: string;
  /** Nome do campo que contém as roles no objeto do usuário (ex: 'roles', 'permissions') */
  rolesField?: string;
  /** Instância do serviço que implementa a busca de usuários no banco de dados */
  userService: IAuthUserService;
  /** Instância do serviço de criptografia (EncryptionService) */
  encryptionService: IEncryptionService;
  /** Ativa o sistema de Refresh Tokens e Rotação de Segurança */
  useRefreshTokens?: boolean;
  /** Segredo diferente para o Refresh Token (mais segurança) */
  refreshSecret?: string;
  /** Tempo de expiração do Refresh Token. Exemplo: 3000. Valor em segundos ou string (ex: '7d'). */
  refreshExpiresIn?: string | number;
  /** Se true, o JwtAuthGuard será aplicado automaticamente em todas as rotas da aplicação */
  globalLock?: boolean;
  /**
   * Emissor (issuer) padrão para o Access Token.
   * Recomenda-se sempre definir.
   */
  jwtIssuer?: string;

  /**
   * Audiência (audience) padrão para o Access Token.
   * Recomenda-se sempre definir.
   */
  jwtAudience?: string;

  /**
   * Emissor específico para o Refresh Token.
   * Se não informado, será usado jwtIssuer.
   */
  refreshIssuer?: string;

  /**
   * Audiência específica para o Refresh Token.
   * Se não informado, será usado jwtAudience.
   */
  refreshAudience?: string;
}