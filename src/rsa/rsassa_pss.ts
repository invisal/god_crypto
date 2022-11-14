import { RawBinary } from "../binary.ts";
import { digestLength } from "../hash.ts";
import { RSAHashAlgorithm } from "./common.ts";
import { emsa_pss_encode, emsa_pss_verify } from "./emsa_pss.ts";
import { i2osp, os2ip } from "./primitives.ts";
import { rsaep } from "./rsa_internal.ts";
import { RSAKey } from "./rsa_key.ts";

export async function rsassa_pss_sign(
  key: RSAKey,
  m: Uint8Array,
  algorithm: RSAHashAlgorithm,
): Promise<RawBinary> {
  if (!key.d) throw "Invalid RSA Key";

  const hLen = digestLength(algorithm);
  const em = await emsa_pss_encode(m, key.length * 8 - 1, hLen, algorithm);
  return new RawBinary(i2osp(rsaep(key.n, key.d, os2ip(em)), key.length));
}

export async function rsassa_pss_verify(
  key: RSAKey,
  m: Uint8Array,
  signature: Uint8Array,
  algorithm: RSAHashAlgorithm,
): Promise<boolean> {
  if (!key.e) throw "Invalid RSA Key";

  const hLen = digestLength(algorithm);
  const em = i2osp(rsaep(key.n, key.e, os2ip(signature)), key.length);
  return await emsa_pss_verify(m, em, key.length * 8 - 1, hLen, algorithm);
}
