# God Crypto

![test](https://github.com/invisal/god-crypto/workflows/test//badge.svg)

A pure Javascript/Typescript cryptography implementation for Deno. We will try to use WebCrypto if available, then fallback to WebAssembly implementation if available, otherwise, we will use pure Javascript implementation.

|                                    | WebCrypto | WebAssembly | Javascript |
| ---------------------------------- | :-------: | :---------: | :--------: |
| **AES**                            |           |             |            |
| &nbsp;&nbsp;&nbsp;`AES-CBC`        |    ✔️     |     ❌      |     ✔️     |
| &nbsp;&nbsp;&nbsp;`AES-ECB`        |    ❌     |     ❌      |     ✔️     |
| **RSA**                            |           |             |            |
| &nbsp;&nbsp;&nbsp;`RSA-PKCS1 v1.5` |    ❌     |     ❌      |     ✔️     |
| &nbsp;&nbsp;&nbsp;`RSA-OAEP`       |    ❌     |     ❌      |     ✔️     |

More algorithm supports is one the way

---

## AES

**Example**

```typescript
import { AES } from "https://deno.land/x/god_crypto/mod.ts";

const aes = new AES("Hello World AES!", {
  mode: "cbc",
  iv: "random 16byte iv",
});

const ciper = await aes.encrypt("This is AES-128-CBC. It works.");
console.log(ciper.hex());
// 41393374609eaee39fbe57c96b43a9da0d547c290501be50f983ecaac6c5fd1c

const plain = await aes.decrypt(ciper);
console.log(plain.toString());
// This is AES-128-CBC. It works.
```

**Syntax**

```javascript
new AES(key, {
  mode: "cbc" | "ebc", // default cbc
  iv: string | UInt8Array, // default [0, 0, ...., 0]
  padding: "pkcs5", // default pkcs5
});
```

---

## RSA

```typescript
import { RSA } from "https://deno.land/x/god_crypto/mod.ts";

const publicKey = RSA.parseKey(Deno.readTextFileSync("./public.pem"));
RSA.encrypt("Hello World", publicKey); // Default OAEP SHA1
RSA.encrypt("Hello World", publicKey, { padding: "oaep", hash: "sha256" });
RSA.encrypt("Hello World", publicKey, { padding: "pkcs1" });

const privateKey = RSA.parseKey(Deno.readTextFileSync("./private.pem"));
RSA.decrypt(ciperText, privateKey);
```

---

## References

- [Announcing the Advanced Encryption Standard (AES)](https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf)
- [Public-Key Cryptography Standards (PKCS) #1: RSA Cryptography Specifications Version 2.1](https://tools.ietf.org/html/rfc3447)
