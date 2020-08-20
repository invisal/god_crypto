import { RawBinary } from "./../binary.ts";
import { concat } from "./../helper.ts";
import { createHash } from "../hash.ts";

/**
 * https://tools.ietf.org/html/rfc4868
 * 
 * @param algorithm 
 * @param key 
 * @param data 
 */
export function hmac(
  algorithm: "sha1" | "sha256",
  key: Uint8Array | string,
  data: Uint8Array | string,
) {
  const blockSize = 64;
  const hasher = createHash(algorithm);

  const computedData: Uint8Array = typeof data === "string"
    ? new TextEncoder().encode(data)
    : data;

  let computedKey: Uint8Array = typeof key === "string"
    ? new TextEncoder().encode(key)
    : key;

  // Hash if key is bigger block size
  if (computedKey.length > blockSize) {
    computedKey = hasher.update(computedKey).digest();
  }

  // Adding zero padding
  if (computedKey.length < blockSize) {
    const tmp = new Uint8Array(blockSize);
    tmp.set(computedKey, 0);
    computedKey = tmp;
  }

  const opad = new Uint8Array(computedKey);
  const ipad = new Uint8Array(computedKey);
  for (let i = 0; i < blockSize; i++) {
    opad[i] = computedKey[i] ^ 0x5c;
    ipad[i] = computedKey[i] ^ 0x36;
  }

  const output = hasher.update(
    concat(opad, hasher.update(concat(ipad, computedData)).digest()),
  ).digest();

  return new RawBinary(output);
}
