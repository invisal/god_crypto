import { Hash } from "https://deno.land/x/checksum@1.2.0/mod.ts";

export function createHash(algorithm: string) {
  return new class {
    protected m: Uint8Array = new Uint8Array();

    public update(b: Uint8Array) {
      this.m = b;
      return this;
    }

    public digest() {
      return new Hash(algorithm as any).digest(this.m).data;
    }
  }();
}
