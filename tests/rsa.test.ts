import {
  assertEquals,
} from "https://deno.land/std@0.63.0/testing/asserts.ts";
import { RSA } from './../mod.ts';

Deno.test("Decrypt RSA OAEP SHA1", () => {
  const privateKeyRaw = Deno.readTextFileSync("./tests/private.pem");
  const ciperText = Deno.readFileSync("./tests/ciper.txt");

  const privateKey = RSA.parseKey(privateKeyRaw);
  const plainText = new TextDecoder().decode(RSA.decrypt(ciperText, privateKey));

  assertEquals(plainText, "Hello World from RSA");
})

Deno.test("Encrypt RSA OAEP SHA1", () => {
  const privateKeyRaw = Deno.readTextFileSync("./tests/private.pem");
  const privateKey = RSA.parseKey(privateKeyRaw);

  const ciperText = RSA.encrypt("Hello World", privateKey);
  const plainText = new TextDecoder().decode(RSA.decrypt(ciperText, privateKey));

  assertEquals(plainText, "Hello World");
})