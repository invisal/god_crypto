import { RSAKey, RSAOption, RSASignOption } from "./common.ts";
import { ber_decode, ber_simple } from "./basic_encoding_rule.ts";
import { base64_to_binary, get_key_size, str2bytes } from "./../helper.ts";
import { WebCryptoRSA } from "./rsa_wc.ts";
import { PureRSA } from "./rsa_js.ts";
import { RawBinary } from "../binary.ts";

type RSAPublicKeyFormat = [[string, null], [[bigint, bigint]]];

function computeMessage(m: Uint8Array | string) {
  return typeof m === "string" ? new TextEncoder().encode(m) : m;
}

function computeOption(options?: Partial<RSAOption>): RSAOption {
  return {
    hash: "sha1",
    padding: "oaep",
    ...options,
  };
}

export class RSA {
  protected key: RSAKey;

  constructor(key: RSAKey) {
    this.key = key;
  }

  async encrypt(
    m: Uint8Array | string,
    options?: Partial<RSAOption>,
  ) {
    const computedOption = computeOption(options);

    const func = WebCryptoRSA.isSupported(computedOption)
      ? WebCryptoRSA.encrypt
      : PureRSA.encrypt;

    return new RawBinary(
      await func(this.key, computeMessage(m), computedOption),
    );
  }

  async decrypt(
    m: Uint8Array,
    options?: Partial<RSAOption>,
  ) {
    const computedOption = computeOption(options);

    const func = WebCryptoRSA.isSupported(computedOption)
      ? WebCryptoRSA.decrypt
      : PureRSA.decrypt;

    return new RawBinary(
      await func(this.key, m, computedOption),
    );
  }

  async verify(
    signature: Uint8Array,
    message: Uint8Array | string,
    options?: Partial<RSASignOption>,
  ): Promise<boolean> {
    const computedOption: RSASignOption = {
      ...options,
      algorithm: "rsassa-pkcs1-v1_5",
      hash: "sha256",
    };

    return await PureRSA.verify(
      this.key,
      signature,
      computeMessage(message),
      computedOption,
    );
  }

  async sign(
    message: Uint8Array | string,
    options?: Partial<RSASignOption>,
  ): Promise<RawBinary> {
    const computedOption: RSASignOption = {
      ...options,
      algorithm: "rsassa-pkcs1-v1_5",
      hash: "sha256",
    };

    return await PureRSA.sign(
      this.key,
      computeMessage(message),
      computedOption,
    );
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
