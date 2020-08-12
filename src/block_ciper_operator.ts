import { RawBinary } from "./binary.ts";
import { xor } from "./helper.ts";

export interface BlockCiperConfig {
  mode?: "ctr" | "cfb" | "ofb" | "ecb" | "cbc";
  padding?: "pkcs5";
  iv?: Uint8Array;
}

export abstract class BlockCiper {
  abstract encrypt(m: Uint8Array): Uint8Array;
  abstract decrypt(m: Uint8Array): Uint8Array;
}

class ECB {
  static encrypt(m: Uint8Array, ciper: BlockCiper, blockSize: number) {
    if (m.length % blockSize !== 0) throw "Message is not properly padded";

    const output = new Uint8Array(m.length);
    for (let i = 0; i < m.length; i += blockSize) {
      output.set(ciper.encrypt(m.slice(i, i + blockSize)), i);
    }

    return new RawBinary(output);
  }
}

class CBC {
  static encrypt(
    m: Uint8Array,
    ciper: BlockCiper,
    blockSize: number,
    iv?: Uint8Array,
  ) {
    if (!iv) throw "Please provide IV value";
    if (m.length % blockSize !== 0) throw "Message is not properly padded";

    const output = new Uint8Array(m.length);
    let prev = iv;

    for (let i = 0; i < m.length; i += blockSize) {
      prev = ciper.encrypt(xor(m.slice(i, i + blockSize), prev));
      output.set(prev, i);
    }

    return new RawBinary(output);
  }
}

export class BlockCiperOperation {
  static encrypt(m: Uint8Array, ciper: BlockCiper, config?: BlockCiperConfig) {
    const computedConfig: BlockCiperConfig = {
      mode: "cbc",
      padding: "pkcs5",
      ...config,
    };

    // PKCS5 Padding
    const blockNumber = Math.ceil((m.length + 1) / 16);
    const paddedMessageLength = blockNumber * 16;
    const remainedLength = paddedMessageLength - m.length;
    const paddedMessage = new Uint8Array(paddedMessageLength);
    paddedMessage.set(m, 0);
    paddedMessage.set(new Array(remainedLength).fill(remainedLength), m.length);

    if (computedConfig.mode === "ecb") {
      return ECB.encrypt(paddedMessage, ciper, 16);
    } else if (computedConfig.mode === "cbc") {
      return CBC.encrypt(paddedMessage, ciper, 16, computedConfig.iv);
    } else throw "Not implemented";
  }
}
