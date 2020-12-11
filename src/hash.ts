import { sha1 } from "https://denopkg.com/chiefbiiko/sha1@v1.0.3/mod.ts";
import { sha256 } from "https://denopkg.com/chiefbiiko/sha256@v1.0.2/mod.ts";
import { sha512 } from "https://denopkg.com/chiefbiiko/sha512/mod.ts";
import { RSAHashAlgorithm } from "./rsa/common.ts";

export function digest(
  algorithm: RSAHashAlgorithm,
  m: Uint8Array,
): Uint8Array {
  if (algorithm === "sha1") {
    return sha1(m) as Uint8Array;
  } else if (algorithm === "sha256") {
    return sha256(m) as Uint8Array;
  } else if (algorithm === "sha512") {
    return sha512(m) as Uint8Array;
  }

  throw "Unsupport hash algorithm";
}

export function digestLength(algorithm: RSAHashAlgorithm) {
  if (algorithm === "sha512") return 64;
  if (algorithm === "sha256") return 32;

  return 20;
}
