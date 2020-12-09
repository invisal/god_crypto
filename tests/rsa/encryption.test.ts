import { assertEquals } from "https://deno.land/std@0.63.0/testing/asserts.ts";
import { RSAKey } from "../../src/rsa/rsa_key.ts";
import { RSA } from "./../../mod.ts";

async function test(
  key: RSAKey,
  plain: string,
  alg: "pkcs1" | "oaep",
  hash?: "sha1" | "sha256",
) {
  const rsa = new RSA(key);
  const ciper = (await rsa.encrypt(plain, { padding: alg, hash: hash }));
  const text = (await rsa.decrypt(ciper, { padding: alg, hash: hash }));

  assertEquals(
    text.toString(),
    plain,
    `Paddng: ${alg}, Bits: ${key.length * 8}, Hash: ${hash}`,
  );
}

Deno.test("RSA - Encryption", async () => {
  const plain = "Lorem Ipsum is simply dummy text of the printing.";

  for (const bits of [1024, 2048, 4096]) {
    const key = RSA.importKey(Deno.readTextFileSync(
      `./tests/rsa/cases/${bits}bit_1_private.pem`,
    ));

    await test(key, plain, "pkcs1");
    await test(key, plain, "oaep", "sha1");
    await test(key, plain, "oaep", "sha256");
  }
});
