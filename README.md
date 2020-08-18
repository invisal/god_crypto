# God Crypto
<img src="https://repository-images.githubusercontent.com/285578879/a09a9880-e179-11ea-9b30-42d45ee638c1" width="500px">

![test](https://github.com/invisal/god-crypto/workflows/test//badge.svg)


A pure Javascript/Typescript cryptography implementation for Deno. We will try to use WebCrypto if available, then fallback to WebAssembly implementation if available, otherwise, we will use pure Javascript implementation.


|                                    | WebCrypto | WebAssembly | Javascript |
| ---------------------------------- | :-------: | :---------: | :--------: |
| **AES**                            |           |             |            |
| &nbsp;&nbsp;&nbsp;`AES-CBC`        |    ✔️     |     ❌      |     ✔️     |
| &nbsp;&nbsp;&nbsp;`AES-CFB`        |    ❌     |     ❌      |     ✔️     |
| &nbsp;&nbsp;&nbsp;`AES-ECB`        |    ❌     |     ❌      |     ✔️     |
| **RSA**                            |           |             |            |
| &nbsp;&nbsp;&nbsp;`RSA-PKCS1 v1.5` |    ❌     |     ❌      |     ✔️     |
| &nbsp;&nbsp;&nbsp;`RSA-OAEP`       |    ✔️     |     ❌      |     ✔️     |
| **HMAC**                           |    ❌     |     ❌      |     ✔️     |

More algorithm supports is one the way

---

## HMAC

**Example**

```typescript
import { hmac } from "https://deno.land/x/god_crypto@v.1.1.0/mod.ts";
hmac("sha1", "secret", "Hello World").hex(); // 858da8837b87f04b052c0f6e954c3f7bbe081164
```

## AES

**Example**

```typescript
import { AES } from "https://deno.land/x/god_crypto@v.1.1.0/mod.ts";

const aes = new AES("Hello World AES!", {
  mode: "cbc",
  iv: "random 16byte iv",
});

const cipher = await aes.encrypt("This is AES-128-CBC. It works.");
console.log(cipher.hex());
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
import { RSA } from "https://deno.land/x/god_crypto@v.1.1.0/mod.ts";

const publicKey = RSA.parseKey(Deno.readTextFileSync("./public.pem"));
const cipher = await new RSA(publicKey).encrypt("Hello World");
console.log(ciper.base64());

const privateKey = RSA.parseKey(Deno.readTextFileSync("./private.pem"));
const plain = await new RSA(privateKey).decrypt(cipher);
console.log(plain.toString());

// More examples:
new RSA(publicKey);
new RSA(publicKey, { padding: "oaep", hash: "sha256" });
new RSA(publicKey, { padding: "pkcs1" });
```

## Other Utility

We also provide encoding utility.

```typescript
import { encode } from "https://deno.land/x/god_crypto@v.1.1.0/mod.ts";

// Converting hex to string
encode.hex("676f645f63727970746f20726f636b7321").toString(); // "god_crypto rocks!"

// Converting hex to base64
encode.hex("676f645f63727970746f20726f636b7321").base64(); // Z29kX2NyeXB0byByb2NrcyE=

// Converting base64 to hex
encode.base64("Z29kX2NyeXB0byByb2NrcyE=").hex(); // 676f645f63727970746f20726f636b7321

// Convert hex/base64 to Uint8Array
encode.base64("Z29kX2NyeXB0byByb2NrcyE="); // Uint8Array object
encode.hex("676f645f63727970746f20726f636b7321"); // Uint8Array object
```
