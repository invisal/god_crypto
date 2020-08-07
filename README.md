# God Crypto

A pure Javascript/Typescript cryptography implementation.

## Usage

```typescript
import { RSA } from "https://github.com/invisal/god-crypto/raw/master/rsa.ts";

const publicKey = RSA.parseKey(Deno.readTextFileSync('./public.pem'));
RSA.encrypt("Hello World", publicKey); // Default OAEP SHA1
RSA.encrypt("Hello World", publicKey, { padding: "oaep", hash: "sha256" });
RSA.encrypt("Hello World", publicKey, { padding: "pkcs1" });

const privateKey = RSA.parseKey(Deno.readTextFileSync('./private.pem'));
RSA.decrypt(ciperText, privateKey);
```

## References

- [Public-Key Cryptography Standards (PKCS) #1: RSA Cryptography Specifications Version 2.1](https://tools.ietf.org/html/rfc3447)