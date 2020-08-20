import {
  assertEquals,
} from "https://deno.land/std@0.63.0/testing/asserts.ts";
import { TOTP } from "./../../src/otp/totp.ts";

Deno.test("Testing TOTP", () => {
  const secret = "UHLWJMGVVIYFT2AO63LAAMKXMCAKDJOK74KVR32P5C23NAJ52OBQ";

  const otp = new TOTP(secret);
  assertEquals(otp.generate(1597833364252), "621401");

  const otp_d8 = new TOTP(secret, 8);
  assertEquals(otp_d8.generate(1597833487842), "07648493");

  const otp_sha256 = new TOTP(secret, 6, "sha256");
  assertEquals(otp_sha256.generate(1597836104899), "454340");
  assertEquals(otp_sha256.verify("454340", 1597836104899), true);
});
