import { assertEquals } from "https://deno.land/std@0.63.0/testing/asserts.ts";
import { hmac } from "./../../mod.ts";

Deno.test("Testing HMAC", async () => {
  assertEquals(
    (await hmac("sha1", "secret", "Hello World")).hex(),
    "858da8837b87f04b052c0f6e954c3f7bbe081164",
  );

  assertEquals(
    (await hmac("sha256", "secret", "Hello World")).hex(),
    "82ce0d2f821fa0ce5447b21306f214c99240fecc6387779d7515148bbdd0c415",
  );

  assertEquals(
    (await hmac("sha512", "secret", "Hello World")).hex(),
    "6d1d186ec481f3e7d1f604e7a74081140a713a8d8bac568e257ed1af9598f64f27f1f4bdaf0edfa1d316a1a7740647db38e7de82e77942cb98c4a08a4d17e89f",
  );
});
