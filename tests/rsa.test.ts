import {
  assertEquals,
} from "https://deno.land/std@0.63.0/testing/asserts.ts";
import { RSA } from "./../mod.ts";

Deno.test("Decrypt RSA OAEP SHA1", () => {
  const privateKeyRaw = Deno.readTextFileSync("./tests/private.pem");
  const ciperText = Deno.readFileSync("./tests/ciper_oaep_sha1.txt");

  const privateKey = RSA.parseKey(privateKeyRaw);
  const plainText = RSA.decrypt(ciperText, privateKey).toString();

  assertEquals(plainText, "Hello World from RSA");
});

Deno.test("Encrypt RSA OAEP SHA1", () => {
  const privateKeyRaw = Deno.readTextFileSync("./tests/private.pem");
  const privateKey = RSA.parseKey(privateKeyRaw);

  const ciperText = RSA.encrypt("Hello World", privateKey);
  const plainText = RSA.decrypt(ciperText, privateKey).toString();

  assertEquals(plainText, "Hello World");
});

Deno.test("Decrypt RSA PKCS1 v1.5", () => {
  const privateKeyRaw = Deno.readTextFileSync("./tests/private.pem");
  const ciperText = Deno.readFileSync("./tests/ciper_pkcs1.txt");

  const privateKey = RSA.parseKey(privateKeyRaw);
  const plainText = RSA.decrypt(ciperText, privateKey, { padding: "pkcs1" })
    .toString();

  assertEquals(plainText, "Hello World");
});

Deno.test("Encrypt RSA PKCS1 v1.5", () => {
  const privateKeyRaw = Deno.readTextFileSync("./tests/private.pem");
  const privateKey = RSA.parseKey(privateKeyRaw);

  const ciperText = RSA.encrypt(
    "Hello World",
    privateKey,
    { padding: "pkcs1" },
  );
  const plainText = RSA.decrypt(ciperText, privateKey, { padding: "pkcs1" })
    .toString();

  assertEquals(plainText, "Hello World");
});
