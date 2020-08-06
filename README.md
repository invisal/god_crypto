# God Crypto

A pure Javascript/Typescript cryptography implementation.

## Usage

```typescript
import { RSA } from "https://github.com/invisal/god-crypto/raw/master/rsa.ts";

const publicKey = RSA.parseKey(Deno.readTextFileSync('./public.pem'));
RSA.encrypt("Hello World", publicKey);
RSA.encrypt("Hello World", publicKey, { padding: "oaep", hash: "sha256" });
RSA.encrypt("Hello World", publicKey, { padding: "pkcs1" });
```