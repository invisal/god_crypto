import { RawBinary } from "../binary.ts";
import type { AESBase } from "./aes_base.ts";
import { WebCryptoAES } from "./aes_wc.ts";
import { PureAES } from "./aes_js.ts";
import type { AESOption } from "./common.ts";

function computeMessage(m: Uint8Array | string) {
  return typeof m === "string" ? new TextEncoder().encode(m) : m;
}

export class AES {
  protected ciper: AESBase;

  constructor(
    key: Uint8Array | string,
    options?: Partial<AESOption>,
  ) {
    // Compute default value
    const computedKey = computeMessage(key);
    const computedOption: AESOption = {
      mode: "cbc",
      ...options,
      iv: options?.iv ? computeMessage(options.iv) : new Uint8Array(16),
    };

    // We only support 128/192/256 bits keys
    if ([16, 24, 32].indexOf(computedKey.length) < 0) {
      throw "Invalid key length";
    }

    // Check if there is native webcrypto
    if (crypto.subtle && options?.mode === "cbc") {
      this.ciper = new WebCryptoAES(computedKey, computedOption);
    } else {
      this.ciper = new PureAES(computedKey, computedOption);
    }
  }

  async encrypt(m: Uint8Array | string): Promise<RawBinary> {
    return new RawBinary(await this.ciper.encrypt(computeMessage(m)));
  }

  async decrypt(m: Uint8Array): Promise<RawBinary> {
    return new RawBinary(await this.ciper.decrypt(computeMessage(m)));
  }
}
