export interface BlockCiperConfig {
  mode?: "ctr" | "cfb" | "ofb" | "ecb";
  padding?: "pkcs5";
  iv?: Uint8Array;
}

export abstract class BlockCiper {
  abstract encrypt(m: Uint8Array): Uint8Array;
  abstract decrypt(m: Uint8Array): Uint8Array;
}

export class BlockCiperOperation {
  static encrypt(m: Uint8Array, ciper: BlockCiper, config: BlockCiperConfig) {
  }
}
