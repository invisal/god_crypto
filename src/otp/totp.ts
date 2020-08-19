import { encode } from "./../utility/encode.ts";
import { hmac } from "../hmac/mod.ts";
import { RawBinary } from "../binary.ts";

function numberToByte(n: number) {
  const a = new Uint8Array(8);

  for (let i = 7; i >= 0; i--) {
    a[i] = n & 0xff;
    n = n >> 8;
  }

  return a;
}

function dt(h: Uint8Array, digits: number) {
  let offset = h[h.length - 1] & 0x0f;
  const a = h.slice(offset, offset + 4);

  const code = ((a[0] & 0x7f) << 24) +
    ((a[1] & 0xff) << 16) +
    ((a[2] & 0xff) << 8) +
    (a[3] & 0xff);

  return code % Math.pow(10, digits);
}

export class TOTP {
  protected secret: Uint8Array;
  protected secretInBase32: string;
  protected period: number;
  protected digits: number;
  protected algorithm: "sha1" | "sha256";

  /**
   * @param secret Secret in base32
   * @param algorithm Hash algorithm
   * @param period Period in second
   */
  constructor(
    secret: string,
    digits: number = 6,
    algorithm: "sha1" | "sha256" = "sha1",
    period: number = 30,
  ) {
    this.period = period;
    this.algorithm = algorithm;
    this.secret = encode.base32(secret);
    this.secretInBase32 = secret;
    this.digits = digits;
  }

  /**
   * @param numberOfByte Number of bytes used to generate the random key
   */
  static generateSecret(numberOfByte: number) {
    const bin = new RawBinary(numberOfByte);
    crypto.getRandomValues(bin);
    return bin.base32();
  }

  uri(name: string, issuer: string): string {
    name = encodeURIComponent(name);
    issuer = encodeURIComponent(issuer);

    return `otpauth://totp/${issuer}:${name}?secret=${this.secretInBase32}&period=${this.period}&digits=${this.digits}&algorithm=${this.algorithm.toUpperCase()}&issuer=${issuer}`;
  }

  generate(timestamp = Date.now()): string {
    const c = Math.floor(timestamp / (this.period * 1000));
    const code = dt(
      hmac(this.algorithm, this.secret, numberToByte(c)),
      this.digits,
    );

    return code.toString().padStart(this.digits, "0");
  }

  verify(code: string, timestamp = Date.now()): boolean {
    return code === this.generate(timestamp);
  }
}
