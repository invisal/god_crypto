import {
  assertEquals,
} from "https://deno.land/std@0.63.0/testing/asserts.ts";
import { RSA } from "./../../mod.ts";

Deno.test("Decrypt RSA OAEP SHA1", async () => {
  const privateKeyRaw = Deno.readTextFileSync("./tests/rsa/private.pem");
  const ciperText = Deno.readFileSync("./tests/rsa/ciper_oaep_sha1.txt");

  const privateKey = RSA.parseKey(privateKeyRaw);
  const plainText = (await new RSA(privateKey).decrypt(ciperText)).toString();

  assertEquals(plainText, "Hello World from RSA");
});

Deno.test("Encrypt RSA OAEP SHA1", async () => {
  const privateKeyRaw = Deno.readTextFileSync("./tests/rsa/private.pem");
  const privateKey = RSA.parseKey(privateKeyRaw);
  const rsa = new RSA(privateKey);

  const ciperText = await rsa.encrypt("Hello World");
  const plainText = (await rsa.decrypt(ciperText)).toString();

  assertEquals(plainText, "Hello World");
});

Deno.test("Decrypt RSA PKCS1 v1.5", async () => {
  const privateKeyRaw = Deno.readTextFileSync("./tests/rsa/private.pem");
  const ciperText = Deno.readFileSync("./tests/rsa/ciper_pkcs1.txt");
  const privateKey = RSA.parseKey(privateKeyRaw);
  const rsa = new RSA(privateKey);

  const plainText = (await rsa.decrypt(ciperText, { padding: "pkcs1" }))
    .toString();
  assertEquals(plainText, "Hello World");
});

Deno.test("Encrypt RSA PKCS1 v1.5", async () => {
  const privateKeyRaw = Deno.readTextFileSync("./tests/rsa/private.pem");
  const privateKey = RSA.parseKey(privateKeyRaw);
  const rsa = new RSA(privateKey);

  const ciperText = await rsa.encrypt("Hello World", { padding: "pkcs1" });
  const plainText = (await rsa.decrypt(ciperText, { padding: "pkcs1" }))
    .toString();

  assertEquals(plainText, "Hello World");
});
