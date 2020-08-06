import { rsa_oaep_encrypt, rsa_pkcs1_encrypt } from "./internals/rsa.ts";
import { ber_decode, ber_simple } from "./internals/basic_encoding_rule.ts";
import { base64_to_binary, get_key_size, str2bytes } from "./internals/helper.ts";

interface RSAKey {
  n: bigint;
  e?: bigint;
  d?: bigint;
  length: number;
}

interface RSAOption {
  hash: "sha1" | "sha256",
  padding: "oaep" | "pkcs1",
}

type RSAPublicKeyFormat = [[string, null], [[bigint, bigint]]]

export class RSA {
  static encrypt(message: Uint8Array | string, key: RSAKey, options?: Partial<RSAOption>): Uint8Array {
    if (!key.e) throw "Invalid RSA key";

    const computedOptions: RSAOption = { hash: "sha1", padding: "oaep", ...options };
    const computedMessage = typeof message === "string" ? str2bytes(message) : message;

    if (computedOptions.padding === "oaep") {
      return rsa_oaep_encrypt(key.length, key.n, key.e, computedMessage, computedOptions.hash);
    } else if (computedOptions.padding === "pkcs1") {
      return rsa_pkcs1_encrypt(key.length, key.n, key.e, computedMessage);
    }

    throw "Invalid parameters";
  }

  static parseKey(key: string): RSAKey {
    if (key.indexOf("-----BEGIN RSA PRIVATE KEY-----") === 0) {
      const trimmedKey = key.substr(31, key.length - 61);
      const parseKey = ber_simple(ber_decode(base64_to_binary(trimmedKey))) as bigint[];

      return {
        n: parseKey[1],
        d: parseKey[2],
        e: parseKey[3],
        length: get_key_size(parseKey[1])
      }
    } else if (key.indexOf("-----BEGIN PUBLIC KEY-----") === 0) {
      const trimmedKey = key.substr(26, key.length - 51)
      const parseKey = ber_simple(ber_decode(base64_to_binary(trimmedKey))) as RSAPublicKeyFormat;

      return {
        length: get_key_size(parseKey[1][0][0]),
        n: parseKey[1][0][0],
        e: parseKey[1][0][1],
      }
    }

    throw "Invalid key format";
  }
}