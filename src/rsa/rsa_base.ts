export abstract class RSABase {
  public abstract async encrypt(m: Uint8Array): Promise<Uint8Array>;
  public abstract async decrypt(m: Uint8Array): Promise<Uint8Array>;
}
