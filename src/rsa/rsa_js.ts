import {
  rsa_oaep_encrypt,
  rsa_pkcs1_encrypt,
  rsa_oaep_decrypt,
  rsa_pkcs1_decrypt,
} from "./rsa_internal.ts";
import { RawBinary } from "./../binary.ts";
import { RSAKey, RSAOption } from "./common.ts";
import { RSABase } from "./rsa_base.ts";

export class PureRSA implements RSABase {
  key: RSAKey;
  options: RSAOption;

  constructor(key: RSAKey, options: RSAOption) {
    this.key = key;
    this.options = options;
  }

  async encrypt(message: Uint8Array) {
    if (!this.key.e) throw "Invalid RSA key";

    if (this.options.padding === "oaep") {
      return new RawBinary(rsa_oaep_encrypt(
        this.key.length,
        this.key.n,
        this.key.e,
        message,
        this.options.hash,
      ));
    } else if (this.options.padding === "pkcs1") {
      return new RawBinary(
        rsa_pkcs1_encrypt(this.key.length, this.key.n, this.key.e, message),
      );
    }

    throw "Invalid parameters";
  }

  async decrypt(ciper: Uint8Array) {
    if (!this.key.d) throw "Invalid RSA key";

    if (this.options.padding === "oaep") {
      return new RawBinary(rsa_oaep_decrypt(
        this.key.length,
        this.key.n,
        this.key.d,
        ciper,
        this.options.hash,
      ));
    } else if (this.options.padding === "pkcs1") {
      return new RawBinary(
        rsa_pkcs1_decrypt(this.key.length, this.key.n, this.key.d, ciper),
      );
    }

    throw "Invalid parameters";
  }
}
