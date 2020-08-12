export class RawBinary extends Uint8Array {
  hex() {
    return [...this].map((x) => x.toString(16).padStart(2, "0")).join("");
  }

  binary(): Uint8Array {
    return this;
  }

  base64(): string {
    throw "Not implemented";
  }

  toString(): string {
    return new TextDecoder().decode(this);
  }
}
