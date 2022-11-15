import { assertEquals } from "https://deno.land/std@0.63.0/testing/asserts.ts";
import { AES } from "./../../mod.ts";

Deno.test("AES - ECB 128 bits key (Encryption)", async () => {
  const key = "Hello World AES!";
  const plain = "This is AES-128-ECB. It works.";

  const aes = new AES(key, { mode: "ecb" });

  assertEquals(
    (await aes.encrypt(plain)).hex(),
    "ce0052411ef0e2aa21211e70bc3ddb537b4a504ea7f4bb38ef8d88915343d674",
  );
});

Deno.test("AES - ECB 128 bits key (Decryption)", async () => {
  const key = "Hello World AES!";
  const plain = "This is AES-128-ECB. It works.";

  const aes = new AES(key, { mode: "ecb" });

  assertEquals(
    (await aes.decrypt(await aes.encrypt(plain))).toString(),
    "This is AES-128-ECB. It works.",
  );
});

Deno.test("AES - CBC 128 bits key (Encryption)", async () => {
  const key = "Hello World AES!";
  const plain = "This is AES-128-ECB. It works.";
  const iv = "random 16byte iv";

  const aes = new AES(key, { mode: "cbc", iv });

  assertEquals(
    (await aes.encrypt(plain)).hex(),
    "41393374609eaee39fbe57c96b43a9dac13df02ff44e43cc0bd38ea7fcc6183e",
  );
});

Deno.test("AES - CBC 128 bits key (Decryption)", async () => {
  const key = "Hello World AES!";
  const plain = "This is AES-128-CBC. It works.";
  const iv = "random 16byte iv";

  const aes = new AES(key, { mode: "cbc", iv });

  assertEquals(
    (await aes.decrypt(await aes.encrypt(plain))).toString(),
    "This is AES-128-CBC. It works.",
  );
});

Deno.test("AES - CFB 128 bits key (Encryption)", async () => {
  const key = "Hello World AES!";
  const plain = "This is AES-128-ECB. It works.";
  const iv = new Uint8Array(16);

  const aes = new AES(key, { mode: "cfb", iv });

  assertEquals(
    (await aes.encrypt(plain)).base64(),
    "L9GTd247ICqw3pVp0rcFeAxG8O0SbI6SazHIuY65",
  );
});

Deno.test("AES - CFB 128 bits key (Decryption)", async () => {
  const key = "Hello World AES!";
  const plain = "This is AES-128-CFB. It works.";
  const iv = "random 16byte iv";

  const aes = new AES(key, { mode: "cfb", iv });

  assertEquals((await aes.decrypt(await aes.encrypt(plain))).toString(), plain);
});
