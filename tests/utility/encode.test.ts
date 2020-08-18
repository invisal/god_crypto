import {
  assertEquals,
} from "https://deno.land/std@0.63.0/testing/asserts.ts";
import { encode } from "./../../mod.ts";

Deno.test("Encoding Utility", () => {
  assertEquals(
    encode.hex("676f645f63727970746f20726f636b7321").toString(),
    "god_crypto rocks!",
  );

  assertEquals(
    encode.string("god_crypto rocks!").hex(),
    "676f645f63727970746f20726f636b7321",
  );

  assertEquals(
    encode.base64("SGVsbG8gZ29kX2NyeXB0bw==").toString(),
    "Hello god_crypto",
  );

  assertEquals(
    encode.string("Hello god_crypto").base64(),
    "SGVsbG8gZ29kX2NyeXB0bw==",
  );
});
