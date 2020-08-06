import { power_mod } from "./math.ts";
import { eme_oaep } from "./eme_oaep.ts";
import { os2ip, i2osp } from "./primitives.ts";
import { concat, random_bytes } from "./helper.ts";

/**
 * @param n public key modulus
 * @param e public key exponent
 * @param m message representative
 */
export function rsaep(n: bigint, e: bigint, m: bigint): bigint {
  return power_mod(m, e, n);
}

/**
 * @param n private key modulus
 * @param d private key exponent
 * @param c ciphertext representative
 */
export function rsadp(n: bigint, d: bigint, c: bigint): bigint {
  return power_mod(c, d, n);
}

export function rsa_oaep_encrypt(bytes: number, n: bigint, e: bigint, m: Uint8Array, algorithm: "sha1" | "sha256") {
  const em = eme_oaep(new Uint8Array(0), m, bytes, algorithm);
  const msg = os2ip(em);
  const c = rsaep(n, e, msg);
  return i2osp(c, bytes);
}

export function rsa_pkcs1_encrypt(bytes: number, n: bigint, e: bigint, m: Uint8Array) {
  const p = concat([0x00, 0x02], random_bytes(bytes - m.length - 3), [0x00], m);
  const msg = os2ip(p);
  const c = rsaep(n, e, msg);
  return i2osp(c, bytes);
}