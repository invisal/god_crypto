import { digest } from "./../hash.ts";
import { RSAHashAlgorithm } from "./common.ts";

/**
 * I2OSP converts a nonnegative integer to an octet string of a specified length.
 * @param x nonnegative integer to be converted
 * @param length intended length of the resulting octet string
 */
export function i2osp(x: bigint, length: number): Uint8Array {
  const t = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    if (x === 0n) break;
    t[i] = Number(x & 255n);
    x = x >> 8n;
  }

  return t;
}

export function os2ip(m: Uint8Array): bigint {
  let n = 0n;
  for (const c of m) n = (n << 8n) + BigInt(c);
  return n;
}

/**
 * MGF1 is a Mask Generation Function based on a hash function.
 * https://tools.ietf.org/html/rfc3447#appendix-B.2.1
 *
 * @param seed seed from which mask is generated, an octet string
 * @param length intended length in octets of the mask
 * @param hash Hash function
 */
export async function mgf1(
  seed: Uint8Array,
  length: number,
  hash: RSAHashAlgorithm,
): Promise<Uint8Array> {
  let counter = 0n;
  let output: number[] = [];

  while (output.length < length) {
    const c = i2osp(counter, 4);

    const h = new Uint8Array(
      await digest(hash, new Uint8Array([...seed, ...c])),
    );

    output = [...output, ...h];
    counter++;
  }

  return new Uint8Array(output.slice(0, length));
}
