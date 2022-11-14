import { RSAHashAlgorithm } from "./rsa/common.ts";

export async function digest(
  algorithm: RSAHashAlgorithm,
  m: Uint8Array,
): Promise<Uint8Array> {
  if (algorithm === "sha1") {
    return new Uint8Array(await crypto.subtle.digest("SHA-1", m));
  } else if (algorithm === "sha256") {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", m));
  } else if (algorithm === "sha512") {
    return new Uint8Array(await crypto.subtle.digest("SHA-512", m));
  }

  throw "Unsupport hash algorithm";
}

export function digestLength(algorithm: RSAHashAlgorithm) {
  if (algorithm === "sha512") return 64;
  if (algorithm === "sha256") return 32;

  return 20;
}
