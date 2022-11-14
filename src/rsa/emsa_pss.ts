import { digest } from "../hash.ts";
import { xor } from "../helper.ts";
import { RSAHashAlgorithm } from "./common.ts";
import { mgf1 } from "./primitives.ts";

export async function emsa_pss_encode(
  m: Uint8Array,
  emBits: number,
  sLen: number,
  algorithm: RSAHashAlgorithm,
) {
  const mHash = await digest(algorithm, m);
  const hLen = mHash.length;
  const emLen = Math.ceil(emBits / 8);

  if (emLen < hLen + sLen + 2) throw "Encoding Error";

  const salt = new Uint8Array(sLen);
  crypto.getRandomValues(salt);

  const m1 = new Uint8Array(
    [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, ...mHash, ...salt],
  );

  const h = await digest(algorithm, m1);
  const ps = new Uint8Array(emLen - sLen - hLen - 2);
  const db = new Uint8Array([...ps, 0x01, ...salt]);

  const dbMask = await mgf1(h, emLen - hLen - 1, algorithm);
  const maskedDB = xor(db, dbMask);

  const leftMost = 8 * emLen - emBits;
  maskedDB[0] = maskedDB[0] & (0xff >> leftMost);

  return new Uint8Array([...maskedDB, ...h, 0xbc]);
}

export async function emsa_pss_verify(
  m: Uint8Array,
  em: Uint8Array,
  emBits: number,
  sLen: number,
  algorithm: RSAHashAlgorithm,
): Promise<boolean> {
  const mHash = await digest(algorithm, m);
  const hLen = mHash.length;
  const emLen = Math.ceil(emBits / 8);

  if (emLen < hLen + sLen + 2) return false;
  if (em[em.length - 1] !== 0xbc) return false;

  const maskedDB = em.slice(0, emLen - hLen - 1);
  const h = em.slice(emLen - hLen - 1, emLen - 1);

  const leftMost = 8 * emLen - emBits;
  if ((maskedDB[0] >> (8 - leftMost)) != 0) return false;

  const dbMask = await mgf1(h, emLen - hLen - 1, algorithm);
  const db = xor(maskedDB, dbMask);
  db[0] = db[0] & (0xff >> leftMost);

  for (let i = 1; i < emLen - hLen - sLen - 2; i++) {
    if (db[i] !== 0x00) return false;
  }

  if (db[emLen - hLen - sLen - 2] !== 0x01) return false;
  const salt = db.slice(emLen - hLen - sLen - 1);

  const m1 = new Uint8Array(
    [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, ...mHash, ...salt],
  );

  const h1 = await digest(algorithm, m1);

  for (let i = 0; i < hLen; i++) {
    if (h1[i] !== h[i]) return false;
  }

  return true;
}
