import {
  assertEquals,
} from "https://deno.land/std@0.63.0/testing/asserts.ts";
import { AES } from "./../src/aes.ts";

Deno.test("AES ECB 128 bits key", () => {
  const key = new TextEncoder().encode("Hello World AES!");
  const plain = new TextEncoder().encode("This is AES-128-ECB. It works.");

  const aes = new AES(key, { mode: "ecb", bits: 128 });

  assertEquals(
    aes.encrypt(plain).hex(),
    "ce0052411ef0e2aa21211e70bc3ddb537b4a504ea7f4bb38ef8d88915343d674",
  );
});

Deno.test("AES CBC 128 bits key", () => {
  const key = new TextEncoder().encode("Hello World AES!");
  const plain = new TextEncoder().encode("This is AES-128-ECB. It works.");
  const iv = new TextEncoder().encode("random 16byte iv");

  const aes = new AES(key, { mode: "cbc", bits: 128, iv });

  assertEquals(
    aes.encrypt(plain).hex(),
    "41393374609eaee39fbe57c96b43a9dac13df02ff44e43cc0bd38ea7fcc6183e",
  );
});
