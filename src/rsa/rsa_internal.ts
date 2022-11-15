import { power_mod } from "./../math.ts";
import { eme_oaep_decode, eme_oaep_encode } from "./eme_oaep.ts";
import { i2osp, os2ip } from "./primitives.ts";
import { concat, random_bytes } from "./../helper.ts";
import { ber_decode, ber_simple } from "./basic_encoding_rule.ts";
import { RawBinary } from "../binary.ts";
import { RSAKey } from "./rsa_key.ts";
import { RSAHashAlgorithm } from "./common.ts";

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
export function rsadp(key: RSAKey, c: bigint): bigint {
  if (!key.d) throw "Invalid RSA key";

  if (key.dp && key.dq && key.qi && key.q && key.p) {
    // Using the Chinese remainder algorithm
    const m1 = power_mod(c % key.p, key.dp, key.p);
    const m2 = power_mod(c % key.q, key.dq, key.q);

    let h = 0n;
    if (m1 >= m2) {
      h = (key.qi * (m1 - m2)) % key.p;
    } else {
      h = ((key.qi * (m1 - m2 + key.p * (key.p / key.q))) % key.p + key.p) %
        key.p;
    }

    return (m2 + h * key.q) % (key.q * key.p);
  } else {
    return power_mod(c, key.d, key.n);
  }
}

export async function rsa_oaep_encrypt(
  bytes: number,
  n: bigint,
  e: bigint,
  m: Uint8Array,
  algorithm: RSAHashAlgorithm,
) {
  const em = await eme_oaep_encode(new Uint8Array(0), m, bytes, algorithm);
  const msg = os2ip(em);
  const c = rsaep(n, e, msg);
  return i2osp(c, bytes);
}

export async function rsa_oaep_decrypt(
  key: RSAKey,
  c: Uint8Array,
  algorithm: RSAHashAlgorithm,
) {
  const em = rsadp(key, os2ip(c));
  const m = await eme_oaep_decode(
    new Uint8Array(0),
    i2osp(em, key.length),
    key.length,
    algorithm,
  );
  return m;
}

export function rsa_pkcs1_encrypt(
  bytes: number,
  n: bigint,
  e: bigint,
  m: Uint8Array,
) {
  const p = concat([0x00, 0x02], random_bytes(bytes - m.length - 3), [0x00], m);
  const msg = os2ip(p);
  const c = rsaep(n, e, msg);
  return i2osp(c, bytes);
}

export function rsa_pkcs1_decrypt(key: RSAKey, c: Uint8Array) {
  const em = i2osp(rsadp(key, os2ip(c)), key.length);

  if (em[0] !== 0) throw "Decryption error";
  if (em[1] !== 0x02) throw "Decryption error";

  let psCursor = 2;
  for (; psCursor < em.length; psCursor++) {
    if (em[psCursor] === 0x00) break;
  }

  if (psCursor < 10) throw "Decryption error";

  return em.slice(psCursor + 1);
}

export function rsa_pkcs1_verify(
  key: RSAKey,
  s: Uint8Array,
  m: Uint8Array,
): boolean {
  if (!key.e) throw "Invalid RSA key";

  let em = i2osp(rsaep(key.n, key.e, os2ip(s)), key.length);

  if (em[0] !== 0) throw "Decryption error";
  if (em[1] !== 0x01) throw "Decryption error";

  let psCursor = 2;
  for (; psCursor < em.length; psCursor++) {
    if (em[psCursor] === 0x00) break;
  }

  if (psCursor < 10) throw "Decryption error";

  // Removing padding
  em = em.slice(psCursor + 1);

  // Parsing the BER
  const ber = ber_simple(ber_decode(em)) as [[number, null], Uint8Array];
  const decryptedMessage = ber[1];

  // Comparing the value
  if (decryptedMessage.length !== m.length) return false;
  for (let i = 0; i < decryptedMessage.length; i++) {
    if (decryptedMessage[i] !== m[i]) return false;
  }

  return true;
}

export function rsa_pkcs1_sign(
  bytes: number,
  n: bigint,
  d: bigint,
  message: Uint8Array,
  algorithm: RSAHashAlgorithm,
): RawBinary {
  // deno-fmt-ignore
  const oid = [
    0x30,
    0x0d,
    0x06,
    0x09,
    0x60,
    0x86,
    0x48,
    0x01,
    0x65,
    0x03,
    0x04,
    0x02,
    algorithm === "sha512" ? 0x03 : 0x01, // <--
    0x05,
    0x00,
  ];

  const der = [
    0x30,
    message.length + 2 + oid.length,
    ...oid,
    0x04,
    message.length,
    ...message,
  ];

  const ps = new Array(bytes - 3 - der.length).fill(0xff);
  const em = new Uint8Array([0x00, 0x01, ...ps, 0x00, ...der]);

  const msg = os2ip(em);
  const c = rsaep(n, d, msg);
  return new RawBinary(i2osp(c, bytes));
}
