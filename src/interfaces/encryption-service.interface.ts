export interface IEncryptionService {
  compare(password: string, hash: string): Promise<boolean>;
  hash(password: string): Promise<string>;
  /** Optional: true if the hash was produced with outdated algorithm/parameters. */
  needsRehash?(hash: string): boolean;
  /**
   * Optional: performs a comparison against a dummy hash with the same cost as a real one.
   * Used when the user does not exist so response time does not reveal valid identifiers.
   */
  compareDummy?(password: string): Promise<false>;
}
