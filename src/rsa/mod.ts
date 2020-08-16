import { RSAKey, RSAOption } from "./common.ts";
import { ber_decode, ber_simple } from "./basic_encoding_rule.ts";
import { base64_to_binary, get_key_size, str2bytes } from "./../helper.ts";
import { RSABase } from "./rsa_base.ts";
import { WebCryptoRSA } from "./rsa_wc.ts";
import { PureRSA } from "./rsa_js.ts";
import { RawBinary } from "../binary.ts";

type RSAPublicKeyFormat = [[string, null], [[bigint, bigint]]];

function computeMessage(m: Uint8Array | string) {
  return typeof m === "string" ? new TextEncoder().encode(m) : m;
}

export class RSA {
  options: RSAOption;
  lib: RSABase;

  constructor(key: RSAKey, options?: Partial<RSAOption>) {
    this.options = {
      hash: "sha1",
      padding: "oaep",
      ...options,
    };

    if (crypto.subtle && this.options.padding === "oaep") {
      this.lib = new WebCryptoRSA(key, this.options);
    } else {
      this.lib = new PureRSA(key, this.options);
    }
  }

  async encrypt(m: Uint8Array | string) {
    return new RawBinary(await this.lib.encrypt(computeMessage(m)));
  }

  async decrypt(m: Uint8Array | string) {
    return new RawBinary(await this.lib.decrypt(computeMessage(m)));
  }

  static parseKey(key: string): RSAKey {
    if (key.indexOf("-----BEGIN RSA PRIVATE KEY-----") === 0) {
      const trimmedKey = key.substr(31, key.length - 61);
      const parseKey = ber_simple(
        ber_decode(base64_to_binary(trimmedKey)),
      ) as bigint[];

      return {
        n: parseKey[1],
        d: parseKey[3],
        e: parseKey[2],
        p: parseKey[4],
        q: parseKey[5],
        dp: parseKey[6],
        dq: parseKey[7],
        qi: parseKey[8],
        length: get_key_size(parseKey[1]),
      };
    } else if (key.indexOf("-----BEGIN PUBLIC KEY-----") === 0) {
      const trimmedKey = key.substr(26, key.length - 51);
      const parseKey = ber_simple(
        ber_decode(base64_to_binary(trimmedKey)),
      ) as RSAPublicKeyFormat;

      return {
        length: get_key_size(parseKey[1][0][0]),
        n: parseKey[1][0][0],
        e: parseKey[1][0][1],
      };
    }

    throw "Invalid key format";
  }
}
