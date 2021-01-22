import { Sha1 } from "https://deno.land/std@0.84.0/hash/sha1.ts";
import { Sha256 } from "https://deno.land/std@0.84.0/hash/sha256.ts";
import { Sha512 } from "https://deno.land/std@0.84.0/hash/sha512.ts";
import { RSAHashAlgorithm } from "./rsa/common.ts";

export function digest(
  algorithm: RSAHashAlgorithm,
  m: Uint8Array,
): Uint8Array {
  if (algorithm === "sha1") {
    return new Uint8Array(new Sha1().update(m).arrayBuffer());
  } else if (algorithm === "sha256") {
    return new Uint8Array(new Sha256().update(m).arrayBuffer());
  } else if (algorithm === "sha512") {
    return new Uint8Array(new Sha512().update(m).arrayBuffer());
  }

  throw "Unsupport hash algorithm";
}

export function digestLength(algorithm: RSAHashAlgorithm) {
  if (algorithm === "sha512") return 64;
  if (algorithm === "sha256") return 32;

  return 20;
}
