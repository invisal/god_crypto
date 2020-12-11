import { sha1 } from "https://denopkg.com/chiefbiiko/sha1@v1.0.3/mod.ts";
import { sha256 } from "https://denopkg.com/chiefbiiko/sha256@v1.0.2/mod.ts";

export function createHash(algorithm: string) {
  return new class {
    protected m: Uint8Array = new Uint8Array();

    public update(b: Uint8Array) {
      this.m = b;
      return this;
    }

    public digest() {
      if (algorithm === "sha1") {
        return sha1(this.m) as Uint8Array;
      } else if (algorithm === "sha256") {
        return sha256(this.m) as Uint8Array;
      }

      throw "Unsupport hash algorithm";
    }
  }();
}

export function digest(
  algorithm: "sha1" | "sha256",
  m: Uint8Array,
): Uint8Array {
  if (algorithm === "sha1") {
    return sha1(m) as Uint8Array;
  } else if (algorithm === "sha256") {
    return sha256(m) as Uint8Array;
  }

  throw "Unsupport hash algorithm";
}

export function digestLength(algorithm: "sha1" | "sha256") {
  if (algorithm === "sha256") return 32;
  return 20;
}
