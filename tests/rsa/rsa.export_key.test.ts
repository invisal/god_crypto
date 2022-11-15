import { RSA } from "./../../mod.ts";
import { assertEquals } from "https://deno.land/std@0.63.0/testing/asserts.ts";

const privateKeyRaw = Deno.readTextFileSync("./tests/rsa/private.pem");
const publicKeyRaw = "-----BEGIN PUBLIC KEY-----\n" +
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArlKJ591/fYCKhdflQSNi\n" +
  "xBhWutUtW5y3l5vFzTxiKE4e9jykJ0Sr7U6GkwjmvplTV7Wgx4zhRr3tYrMqmQ+s\n" +
  "/byRK3f2bb+zXF9+fnKGuP7Fp2oYprW3MKxKgNxjRzmx2x7LaV11dHFQv6oigeV2\n" +
  "cyY5XB/GnEWUyHY7fCJIJIRdxuskt+77NAU0vrA/ntbWzFFsPP5xWJ8ns/ojTvwu\n" +
  "+LT++fpBD3X1nTUR/LzlRgGxGqPHYRCHvY8B2FSPL8ukqfXI3LkvCM77zeR5lwPq\n" +
  "IqDFVWcP6TNsOXccqDtBiA3+A6TS3nGmOu3NbZdefkzJlXq2D0xuW6ql0WqBM0Vu\n" +
  "bwIDAQAB\n" +
  "-----END PUBLIC KEY-----\n";

Deno.test("RSA - PKCS8 to PKCS8", () => {
  assertEquals(RSA.importKey(privateKeyRaw).pem(), privateKeyRaw);
  assertEquals(RSA.importKey(publicKeyRaw).pem(), publicKeyRaw);
});

Deno.test("RSA - JWK to PKCS8", () => {
  const jwk = {
    kty: "RSA",
    n: "rlKJ591_fYCKhdflQSNixBhWutUtW5y3l5vFzTxiKE4e9jykJ0Sr7U6GkwjmvplTV7Wgx4zhRr3tYrMqmQ-s_byRK3f2bb-zXF9-fnKGuP7Fp2oYprW3MKxKgNxjRzmx2x7LaV11dHFQv6oigeV2cyY5XB_GnEWUyHY7fCJIJIRdxuskt-77NAU0vrA_ntbWzFFsPP5xWJ8ns_ojTvwu-LT--fpBD3X1nTUR_LzlRgGxGqPHYRCHvY8B2FSPL8ukqfXI3LkvCM77zeR5lwPqIqDFVWcP6TNsOXccqDtBiA3-A6TS3nGmOu3NbZdefkzJlXq2D0xuW6ql0WqBM0Vubw",
    e: "AQAB",
  };

  assertEquals(RSA.importKey(jwk).pem(), publicKeyRaw);
});

Deno.test("RSA - PKCS8 to JWK", () => {
  const jwk = {
    kty: "RSA",
    n: "rlKJ591_fYCKhdflQSNixBhWutUtW5y3l5vFzTxiKE4e9jykJ0Sr7U6GkwjmvplTV7Wgx4zhRr3tYrMqmQ-s_byRK3f2bb-zXF9-fnKGuP7Fp2oYprW3MKxKgNxjRzmx2x7LaV11dHFQv6oigeV2cyY5XB_GnEWUyHY7fCJIJIRdxuskt-77NAU0vrA_ntbWzFFsPP5xWJ8ns_ojTvwu-LT--fpBD3X1nTUR_LzlRgGxGqPHYRCHvY8B2FSPL8ukqfXI3LkvCM77zeR5lwPqIqDFVWcP6TNsOXccqDtBiA3-A6TS3nGmOu3NbZdefkzJlXq2D0xuW6ql0WqBM0Vubw",
    e: "AQAB",
  };

  const actualJwk = RSA.importKey(publicKeyRaw).jwk();
  assertEquals(actualJwk.n, jwk.n);
  assertEquals(actualJwk.e, jwk.e);
});
