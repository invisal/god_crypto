import { assertEquals } from "https://deno.land/std@0.63.0/testing/asserts.ts";
import { hmac } from "./../../mod.ts";

Deno.test("Testing HMAC", async () => {
  assertEquals(
    (await hmac("sha1", "secret", "Hello World")).hex(),
    "858da8837b87f04b052c0f6e954c3f7bbe081164",
  );
});
