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
