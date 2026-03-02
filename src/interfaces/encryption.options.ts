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

  /**
   * Se true, a lib lança erro se a senha for "fraca"
   * (ex: menos de 8 caracteres ou apenas números)
   */
  strongPasswordValidation?: boolean;

  /**
   * Algoritmo de hashing a ser utilizado.
   * @default 'bcrypt'
   */
  algorithm?: "bcrypt" | "argon2";

  /**
   * Se true, utiliza validação de senha baseada em OWASP (owasp-password-strength-test)
   * em vez da validação simples de tamanho/numérica.
   */
  useOwaspPolicy?: boolean;
};