import { assertEquals } from "https://deno.land/std@0.63.0/testing/asserts.ts";
import { RSA } from "./../../mod.ts";

async function test(
  bits: number,
  n: number,
  alg: "pkcs1" | "oaep",
  hash?: "sha1" | "sha256",
) {
  const keyFilename = `./tests/rsa/cases/${bits}bit_${n}_private.pem`;
  const ciperFilename = `./tests/rsa/cases/${bits}bit_${n}_ciper_${alg}${
    hash ? "_" + hash : ""
  }.txt`;

  const raw = Deno.readTextFileSync(keyFilename);
  const key = RSA.parseKey(raw);

  const ciper = Deno.readFileSync(ciperFilename);

  const text = (await new RSA(key).decrypt(ciper, { padding: alg, hash: hash }))
    .toString();

  assertEquals(
    text,
    "Lorem Ipsum is simply dummy text of the printing.",
    `Paddng: ${alg}, Test Case: ${n}, Bits: ${bits}, Hash: ${hash}`,
  );
}

Deno.test("RSA - Decryption", async () => {
  for (const bits of [1024, 2048, 4096]) {
    for (const n of [1, 2]) {
      await test(bits, n, "oaep", "sha1");
      await test(bits, n, "oaep", "sha256");
      await test(bits, n, "pkcs1");
    }
  }
});
