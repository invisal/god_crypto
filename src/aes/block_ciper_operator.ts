import { xor } from "./../helper.ts";
import { BlockCiperConfig } from "./common.ts";

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

    return output;
  }

  static decrypt(m: Uint8Array, ciper: BlockCiper, blockSize: number) {
    if (m.length % blockSize !== 0) throw "Message is not properly padded";

    const output = new Uint8Array(m.length);
    for (let i = 0; i < m.length; i += blockSize) {
      output.set(ciper.decrypt(m.slice(i, i + blockSize)), i);
    }

    return output;
  }
}

class CFB {
  static encrypt(
    m: Uint8Array,
    ciper: BlockCiper,
    blockSize: number,
    iv: Uint8Array,
  ) {
    const output = new Uint8Array(m.length);
    let prev = iv;

    for (let i = 0; i < m.length; i += blockSize) {
      prev = xor(m.slice(i, i + blockSize), ciper.encrypt(prev));
      output.set(prev, i);
    }

    return output;
  }

  static decrypt(
    m: Uint8Array,
    ciper: BlockCiper,
    blockSize: number,
    iv: Uint8Array,
  ) {
    const output = new Uint8Array(m.length);
    let prev = iv;

    for (let i = 0; i < m.length; i += blockSize) {
      const t = m.slice(i, Math.min(i + blockSize, m.length));
      output.set(xor(t, ciper.encrypt(prev)), i);
      prev = t;
    }

    return output;
  }
}

class CBC {
  static encrypt(
    m: Uint8Array,
    ciper: BlockCiper,
    blockSize: number,
    iv: Uint8Array,
  ) {
    const output = new Uint8Array(m.length);
    let prev = iv;

    for (let i = 0; i < m.length; i += blockSize) {
      prev = ciper.encrypt(xor(m.slice(i, i + blockSize), prev));
      output.set(prev, i);
    }

    return output;
  }

  static decrypt(
    m: Uint8Array,
    ciper: BlockCiper,
    blockSize: number,
    iv: Uint8Array,
  ) {
    const output = new Uint8Array(m.length);
    let prev = iv;

    for (let i = 0; i < m.length; i += blockSize) {
      const t = m.slice(i, i + blockSize);
      output.set(xor(ciper.decrypt(t), prev), i);
      prev = t;
    }

    return output;
  }
}

function pad(m: Uint8Array): Uint8Array {
  const blockNumber = Math.ceil((m.length + 1) / 16);
  const paddedMessageLength = blockNumber * 16;
  const remainedLength = paddedMessageLength - m.length;
  const paddedMessage = new Uint8Array(paddedMessageLength);
  paddedMessage.set(m, 0);
  paddedMessage.set(new Array(remainedLength).fill(remainedLength), m.length);

  return paddedMessage;
}

function unpad(m: Uint8Array): Uint8Array {
  const lastByte = m[m.length - 1];
  return new Uint8Array(m.slice(0, m.length - lastByte));
}

export class BlockCiperOperation {
  static encrypt(
    m: Uint8Array,
    ciper: BlockCiper,
    blockSize: number,
    config?: BlockCiperConfig,
  ) {
    const computedConfig: BlockCiperConfig = {
      mode: "cbc",
      padding: "pkcs5",
      ...config,
    };

    // Compute IV
    const computedIV = typeof computedConfig.iv === "string"
      ? new TextEncoder().encode(computedConfig.iv)
      : computedConfig.iv;

    if (blockSize !== computedIV?.length) throw "Invalid IV size";

    if (computedConfig.mode === "ecb") {
      return ECB.encrypt(pad(m), ciper, 16);
    } else if (computedConfig.mode === "cbc") {
      return CBC.encrypt(pad(m), ciper, 16, computedIV);
    } else if (computedConfig.mode === "cfb") {
      return CFB.encrypt(m, ciper, 16, computedIV);
    } else throw "Not implemented";
  }

  static decrypt(
    m: Uint8Array,
    ciper: BlockCiper,
    blockSize: number,
    config?: BlockCiperConfig,
  ) {
    const computedConfig: BlockCiperConfig = {
      mode: "cbc",
      padding: "pkcs5",
      ...config,
    };

    // Compute IV
    const computedIV = typeof computedConfig.iv === "string"
      ? new TextEncoder().encode(computedConfig.iv)
      : computedConfig.iv;

    if (blockSize !== computedIV?.length) throw "Invalid IV size";

    let output;
    if (computedConfig.mode === "ecb") {
      output = ECB.decrypt(m, ciper, 16);
    } else if (computedConfig.mode === "cbc") {
      output = CBC.decrypt(m, ciper, 16, computedIV);
    } else if (computedConfig.mode === "cfb") {
      return CFB.decrypt(m, ciper, 16, computedIV);
    } else throw "Not implemented";

    return unpad(output);
  }
}
