# God Crypto

<img src="https://repository-images.githubusercontent.com/285578879/a09a9880-e179-11ea-9b30-42d45ee638c1" width="500px">

![test](https://github.com/invisal/god-crypto/workflows/test//badge.svg)

A pure Javascript/Typescript cryptography implementation for Deno. We will try to use WebCrypto if available, then fallback to WebAssembly implementation if available, otherwise, we will use pure Javascript implementation.

> **NOTE:** `god_crypto` is in very early stage of development. There will be a lot of change and it is not recommended for production.

## References

### [AES](https://github.com/invisal/god_crypto/wiki/AES) | [RSA](https://github.com/invisal/god_crypto/wiki/RSA) | [HMAC](https://github.com/invisal/god_crypto/wiki/HMAC) | [TOTP](https://github.com/invisal/god_crypto/wiki/TOTP)

Click here for complete document: [Complete Documents](https://github.com/invisal/god_crypto/wiki)

## Modules

You can choose to include the whole `god_crypto` implementation or just include module that you need.

```
// Load everything
import { AES, RSA, TOTP, hmac, encode } from "https://deno.land/x/god_crypto/mod.ts";

// Load what you need
import { AES }  from "https://deno.land/x/god_crypto/aes.ts";
import { RSA }  from "https://deno.land/x/god_crypto/rsa.ts";
import { TOTP } from "https://deno.land/x/god_crypto/otp.ts";
import { hmac } from "https://deno.land/x/god_crypto/hmac.ts";
```

---

## Support Algorithms

|                                    | WebCrypto | WebAssembly | Javascript |
| ---------------------------------- | :-------: | :---------: | :--------: |
| **AES**                            |           |             |            |
| &nbsp;&nbsp;&nbsp;`AES-CBC`        |    ✔️     |     ❌      |     ✔️     |
| &nbsp;&nbsp;&nbsp;`AES-CFB`        |    ❌     |     ❌      |     ✔️     |
| &nbsp;&nbsp;&nbsp;`AES-ECB`        |    ❌     |     ❌      |     ✔️     |
| **RSA**                            |           |             |            |
| &nbsp;&nbsp;&nbsp;`RSA-PKCS1 v1.5` |    ❌     |     ❌      |     ✔️     |
| &nbsp;&nbsp;&nbsp;`RSA-OAEP`       |    ✔️     |     ❌      |     ✔️     |
| **HMAC**                           |           |             |     ✔️     |
| **TOTP**                           |           |             |     ✔️     |

More algorithm supports is one the way
<br />
<br />

---

## Examples

```typescript
import { AES } from "https://deno.land/x/god_crypto/aes.ts";

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

```typescript
import { RSA } from "https://deno.land/x/god_crypto/rsa.ts";

// Parsing public/private key
const publicKey = RSA.parseKey(Deno.readTextFileSync("./public.pem"));
const privateKey = RSA.parseKey(Deno.readTextFileSync("./private.pem"));

const cipher = await new RSA(publicKey).encrypt("Hello World");
console.log(ciper.base64());

const plain = await new RSA(privateKey).decrypt(cipher);
console.log(plain.toString());
```
