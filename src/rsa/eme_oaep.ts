import { digest } from "./../hash.ts";
import { mgf1 } from "./primitives.ts";
import { concat, random_bytes, xor } from "./../helper.ts";
import { RSAHashAlgorithm } from "./common.ts";

/**
 * https://tools.ietf.org/html/rfc3447#page-10
 *
 * @param label
 * @param m
 * @param k
 * @param algorithm
 */
export function eme_oaep_encode(
  label: Uint8Array,
  m: Uint8Array,
  k: number,
  algorithm: RSAHashAlgorithm,
): Uint8Array {
  const labelHash = new Uint8Array(digest(algorithm, label));
  const ps = new Uint8Array(k - labelHash.length * 2 - 2 - m.length);
  const db = concat(labelHash, ps, [0x01], m);
  const seed = random_bytes(labelHash.length);
  const dbMask = mgf1(seed, k - labelHash.length - 1, algorithm);
  const maskedDb = xor(db, dbMask);
  const seedMask = mgf1(maskedDb, labelHash.length, algorithm);
  const maskedSeed = xor(seed, seedMask);

  return concat([0x00], maskedSeed, maskedDb);
}

export function eme_oaep_decode(
  label: Uint8Array,
  c: Uint8Array,
  k: number,
  algorithm: RSAHashAlgorithm,
): Uint8Array {
  const labelHash = new Uint8Array(digest(algorithm, label));
  const maskedSeed = c.slice(1, 1 + labelHash.length);
  const maskedDb = c.slice(1 + labelHash.length);
  const seedMask = mgf1(maskedDb, labelHash.length, algorithm);
  const seed = xor(maskedSeed, seedMask);
  const dbMask = mgf1(seed, k - labelHash.length - 1, algorithm);
  const db = xor(maskedDb, dbMask);

  let ptr = labelHash.length;
  while (ptr < db.length && db[ptr] === 0) ptr++;

  return db.slice(ptr + 1);
}
