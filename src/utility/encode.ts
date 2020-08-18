import { RawBinary } from "../binary.ts";

export class encode {
  static hex(data: string) {
    if (data.length % 2 !== 0) throw "Invalid hex format";

    const output = new RawBinary(data.length >> 1);
    let ptr = 0;

    for (let i = 0; i < data.length; i += 2) {
      output[ptr++] = parseInt(data.substr(i, 2), 16);
    }

    return output;
  }

  static string(data: string) {
    return new RawBinary(new TextEncoder().encode(data));
  }

  static base64(data: string) {
    return new RawBinary(Uint8Array.from(atob(data), (c) => c.charCodeAt(0)));
  }

  static binary(data: Uint8Array | number[]) {
    return new RawBinary(data);
  }
}
