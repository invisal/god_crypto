import { assertEquals } from "https://deno.land/std@0.63.0/testing/asserts.ts";
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

Deno.test("Encoding Base32", () => {
  assertEquals(
    encode.base32("GZ7QQLQXMAQB6NK3KZOF4MC2PBHQS3Z2DAGDY3LKHFIU4UCCEZJA").hex(),
    "367f082e1760201f355b565c5e305a784f096f3a180c3c6d6a39514e50422652",
  );

  assertEquals(
    encode.hex(
      "367f082e1760201f355b565c5e305a784f096f3a180c3c6d6a39514e50422652",
    ).base32(),
    "GZ7QQLQXMAQB6NK3KZOF4MC2PBHQS3Z2DAGDY3LKHFIU4UCCEZJA",
  );

  assertEquals(
    encode.hex("187f234b").base32(),
    "DB7SGSY",
  );

  assertEquals(
    encode.base32("DB7SGSY"),
    [24, 127, 35, 75],
  );
});
