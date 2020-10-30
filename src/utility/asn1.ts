function createSizeBuffer(size: number): Uint8Array {
  if (size <= 127) return new Uint8Array([size]);

  const bytes = [];
  while (size > 0) {
    bytes.push(size & 0xff);
    size = size >> 8;
  }

  bytes.reverse();
  return new Uint8Array([0x80 + bytes.length, ...bytes]);
}

export class BER {
  public static createSequence(children: Uint8Array[]): Uint8Array {
    // Combine the total size of its children
    const size = children.reduce(
      (accumlatedSize, child) => accumlatedSize + child.length,
      0
    );

    return new Uint8Array([
      0x30,
      ...createSizeBuffer(size),
      ...children.reduce<number[]>(
        (buffer, child) => [...buffer, ...child],
        []
      ),
    ]);
  }

  public static createNull() {
    return new Uint8Array([0x05, 0x00]);
  }

  public static createBoolean(value: boolean) {
    return new Uint8Array([0x01, 0x01, value ? 0x01 : 0x00]);
  }

  public static createInteger(value: bigint | number): Uint8Array {
    if (typeof value === "number") return BER.createBigInteger(BigInt(value));
    return BER.createBigInteger(value);
  }

  public static createBigInteger(value: bigint): Uint8Array {
    if (value === 0n) return new Uint8Array([0x02, 0x01, 0x00]);

    const isNegative = value < 0;
    const content: number[] = [];
    let n = isNegative ? -value : value;

    while (n > 0n) {
      content.push(Number(n & 255n));
      n = n >> 8n;
    }

    if (!isNegative) {
      if (content[content.length - 1] & 0x80) content.push(0x00);
    } else {
      // Flipping the bit
      for (let i = 0; i < content.length; i++) content[i] = 256 - content[i];
      if (!(content[content.length - 1] & 0x80)) content.push(0xff);
    }

    content.reverse();

    return new Uint8Array([
      0x02,
      ...createSizeBuffer(content.length),
      ...content,
    ]);
  }

  public static createBitString(value: Uint8Array): Uint8Array {
    return new Uint8Array([
      0x03,
      ...createSizeBuffer(value.length + 1),
      0x00,
      ...value,
    ]);
  }
}
