export interface EncryptionOptions {
  /**
   * Número de rounds para o processamento do Bcrypt.
   * Recomendado: 10 ou mais.
   * @default 10
   */
  saltRounds?: number;

  /**
   * Uma string opcional para ser adicionada à senha antes do hashing.
   * Aumenta a segurança contra ataques de Rainbow Tables.
   */
  pepper?: string;

  /** * Se true, a lib lança erro se a senha for "fraca" 
   * (ex: menos de 8 caracteres ou apenas números) 
   */
  strongPasswordValidation?: boolean;

  /** * Opção para usar algoritmos alternativos no futuro (como Argon2), 
   * embora agora o suporte seja apenas para o Bcrypt.
   */
  algorithm?: 'bcrypt';

};