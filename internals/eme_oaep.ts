import { createHash } from "https://deno.land/std/hash/mod.ts";
import { mgf1 } from "./primitives.ts";
import { concat, xor, random_bytes } from "./helper.ts";

/**
 * https://tools.ietf.org/html/rfc3447#page-10
 * 
 * @param label 
 * @param m 
 * @param k 
 * @param algorithm 
 */
export function eme_oaep(label: Uint8Array, m: Uint8Array, k: number, algorithm: "sha1" | "sha256"): Uint8Array {
  const labelHash = new Uint8Array(createHash(algorithm).update(label).digest());

  const ps = new Uint8Array(k - labelHash.length * 2 - 2 - m.length);
  const db = concat(labelHash, ps, [0x01], m);
  const seed = random_bytes(labelHash.length);
  const dbMask = mgf1(seed, k - labelHash.length - 1, algorithm);
  const maskedDb = xor(db, dbMask);
  const seedMask = mgf1(maskedDb, labelHash.length, algorithm);
  const maskedSeed = xor(seed, seedMask);

  return concat([0x00], maskedSeed, maskedDb);
}