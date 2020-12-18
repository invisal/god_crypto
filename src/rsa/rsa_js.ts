import {
  rsa_oaep_decrypt,
  rsa_oaep_encrypt,
  rsa_pkcs1_decrypt,
  rsa_pkcs1_encrypt,
  rsa_pkcs1_sign,
  rsa_pkcs1_verify,
} from "./rsa_internal.ts";
import { RawBinary } from "./../binary.ts";
import type { RSAOption, RSASignOption } from "./common.ts";
import { digest } from "../hash.ts";
import type { RSAKey } from "./rsa_key.ts";
import { rsassa_pss_sign, rsassa_pss_verify } from "./rsassa_pss.ts";

export class PureRSA {
  static async encrypt(key: RSAKey, message: Uint8Array, options: RSAOption) {
    if (!key.e) throw "Invalid RSA key";

    if (options.padding === "oaep") {
      return new RawBinary(
        rsa_oaep_encrypt(key.length, key.n, key.e, message, options.hash),
      );
    } else if (options.padding === "pkcs1") {
      return new RawBinary(
        rsa_pkcs1_encrypt(key.length, key.n, key.e, message),
      );
    }

    throw "Invalid parameters";
  }

  static async decrypt(key: RSAKey, ciper: Uint8Array, options: RSAOption) {
    if (!key.d) throw "Invalid RSA key";

    if (options.padding === "oaep") {
      return new RawBinary(rsa_oaep_decrypt(key, ciper, options.hash));
    } else if (options.padding === "pkcs1") {
      return new RawBinary(rsa_pkcs1_decrypt(key, ciper));
    }

    throw "Invalid parameters";
  }

  static async verify(
    key: RSAKey,
    signature: Uint8Array,
    message: Uint8Array,
    options: RSASignOption,
  ) {
    if (!key.e) throw "Invalid RSA key";

    if (options.algorithm === "rsassa-pkcs1-v1_5") {
      return rsa_pkcs1_verify(
        key,
        signature,
        digest(options.hash, message),
      );
    } else {
      return rsassa_pss_verify(key, message, signature, options.hash);
    }
  }

  static async sign(key: RSAKey, message: Uint8Array, options: RSASignOption) {
    if (!key.d) throw "You need private key to sign the message";

    if (options.algorithm === "rsassa-pkcs1-v1_5") {
      return rsa_pkcs1_sign(
        key.length,
        key.n,
        key.d,
        digest(options.hash, message),
        options.hash,
      );
    } else {
      return rsassa_pss_sign(key, message, options.hash);
    }
  }
}
