export abstract class AESBase {
  public abstract encrypt(m: Uint8Array): Promise<Uint8Array>;
  public abstract decrypt(m: Uint8Array): Promise<Uint8Array>;
}
