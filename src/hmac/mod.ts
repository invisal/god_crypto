import { RawBinary } from "./../binary.ts";

const ALGORITHM_MAPPING = {
  "sha1": "SHA-1",
  "sha256": "SHA-256",
  "sha512": "SHA-512",
};

/**
 * https://tools.ietf.org/html/rfc4868
 *
 * @param algorithm
 * @param key
 * @param data
 */
export async function hmac(
  algorithm: "sha1" | "sha256" | "sha512",
  key: Uint8Array | string,
  data: Uint8Array | string,
) {
  const computedData: Uint8Array = typeof data === "string"
    ? new TextEncoder().encode(data)
    : data;

  const computedKey: Uint8Array = typeof key === "string"
    ? new TextEncoder().encode(key)
    : key;

  const importedKey = await window.crypto.subtle.importKey(
    "raw", // raw format of the key - should be Uint8Array
    computedKey,
    { // algorithm details
      name: "HMAC",
      hash: { name: ALGORITHM_MAPPING[algorithm] },
    },
    false, // export = false
    ["sign", "verify"], // what this key can do
  );

  const output = await window.crypto.subtle.sign(
    "HMAC",
    importedKey,
    computedData,
  );

  return new RawBinary(output);
}
