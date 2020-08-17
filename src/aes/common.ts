export interface BlockCiperConfig {
  mode?: "ctr" | "cfb" | "ofb" | "ecb" | "cbc";
  padding?: "pkcs5";
  iv?: Uint8Array | string;
}

type AESBlockMode = "cbc" | "ecb" | "cfb";

export interface AESOption {
  mode: AESBlockMode;
  iv: string | Uint8Array;
}
