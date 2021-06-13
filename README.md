# God Crypto

<img src="https://repository-images.githubusercontent.com/285578879/a09a9880-e179-11ea-9b30-42d45ee638c1" width="500px">

![test](https://github.com/invisal/god-crypto/workflows/test//badge.svg)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=invisal_god_crypto&metric=alert_status)](https://sonarcloud.io/dashboard?id=invisal_god_crypto)

A pure Javascript/Typescript cryptography implementation for Deno. We will try to use WebCrypto if available, then fallback pure Javascript implementation.

## References

### Supported Algorithms

- [**AES (Advanced Encryption Standard)**](https://github.com/invisal/god_crypto/wiki/AES)

  - Supports Block Ciper Mode: CBC, CFB, and ECB

- [**RSA (Rivest–Shamir–Adleman)**](https://github.com/invisal/god_crypto/wiki/RSA)

  - Supports RSA-PKCS1 v1.5 and RSA-OAEP padding
  - Supports RSASSA-PSS signature
  - Supports RSASSA-PKCS1-v1_5 signature

- [**HMAC**](https://github.com/invisal/god_crypto/wiki/HMAC)

### Applications

- [**HOTP (HMAC-based One-time Password)**](https://github.com/invisal/god_crypto/wiki/HOTP)
- [**TOTP (
  Time-based One-time Password)**](https://github.com/invisal/god_crypto/wiki/TOTP)

### Ultities

Some useful ultities that you can use

- [encode](https://github.com/invisal/god_crypto/wiki/encode)
- [BER Writer](https://github.com/invisal/god_crypto/wiki/BER)

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

const plain = await aes.decrypt(cipher);
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
