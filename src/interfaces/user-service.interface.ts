export interface IAuthUserService {
  /** Busca o usuário pelo campo identificador (email, username, etc) */
  findOneByField(field: string, value: any): Promise<any>;
  /** Método necessários para Refresh Token Rotation */
  saveRefreshToken?(userId: string, token: string): Promise<void>;
  /** Método necessários para Refresh Token Rotation */
  isRefreshTokenValid?(userId: string, token: string): Promise<boolean>;
  /** Método necessários para Refresh Token Rotation */
  revokeAllTokens?(userId: string): Promise<void>;
}