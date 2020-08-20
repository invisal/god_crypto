import {
  assertEquals,
} from "https://deno.land/std@0.63.0/testing/asserts.ts";
import { AES } from "./../../mod.ts";

Deno.test("AES - Decryption AES-128-CBC (OpenSSL)", async () => {
  // openssl enc -aes-128-cbc -in tests/aes/openssl_cleartext.txt -K 48656c6c6f20576f726c642041455321 -iv 72616e646f6d20313662797465206976 -out tests/aes/openssl_128_cbc.txt
  const encryptedText = await Deno.readFile("./tests/aes/openssl_128_cbc.txt");
  const clearText = await Deno.readTextFile(
    "./tests/aes/openssl_cleartext.txt",
  );

  const aes = new AES(
    "Hello World AES!",
    { iv: "random 16byte iv", mode: "cbc" },
  );

  assertEquals((await aes.decrypt(encryptedText)).toString(), clearText);
});

Deno.test("AES - Decryption AES-256-CBC (OpenSSL)", async () => {
  // openssl enc -aes-128-cbc -in tests/aes/openssl_cleartext.txt -K 5468697320697320323536206269747320414553206b65792e20506561636521 -iv 72616e646f6d20313662797465206976 -out tests/aes/openssl_128_cbc.txt
  const encryptedText = await Deno.readFile("./tests/aes/openssl_256_cbc.txt");
  const clearText = await Deno.readTextFile(
    "./tests/aes/openssl_cleartext.txt",
  );

  const aes = new AES(
    "This is 256 bits AES key. Peace!",
    { iv: "random 16byte iv", mode: "cbc" },
  );

  assertEquals((await aes.decrypt(encryptedText)).toString(), clearText);
});

Deno.test("AES - Decryption AES-128-CFB (OpenSSL)", async () => {
  // openssl enc -aes-128-cfb -in tests/aes/openssl_cleartext.txt -K 48656c6c6f20576f726c642041455321 -iv 72616e646f6d20313662797465206976 -out tests/aes/openssl_128_cfb.txt
  const encryptedText = await Deno.readFile("./tests/aes/openssl_128_cfb.txt");
  const clearText = await Deno.readTextFile(
    "./tests/aes/openssl_cleartext.txt",
  );

  const aes = new AES(
    "Hello World AES!",
    { iv: "random 16byte iv", mode: "cfb" },
  );

  assertEquals((await aes.decrypt(encryptedText)).toString(), clearText);
});
