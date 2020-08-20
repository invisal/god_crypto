export interface RSAKey {
  n: bigint;
  e?: bigint;
  d?: bigint;
  p?: bigint;
  q?: bigint;
  dp?: bigint;
  dq?: bigint;
  qi?: bigint;
  length: number;
}

export interface RSAOption {
  hash: "sha1" | "sha256";
  padding: "oaep" | "pkcs1";
}

export interface RSASignOption {
  hash: "sha256";
  algorithm: "rsassa-pkcs1-v1_5";
}
