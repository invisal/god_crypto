export interface RSAKeyParams {
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

export interface JSONWebKey {
  kty: string;
  kid?: string;
  use?: string;
  e?: string;
  d?: string;
  n?: string;
  p?: string;
  q?: string;
  dp?: string;
  dq?: string;
  qi?: string;
  alg?: string;
}
