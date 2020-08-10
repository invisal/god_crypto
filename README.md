# God Crypto

![test](https://github.com/invisal/god-crypto/workflows/test//badge.svg)

A pure Javascript/Typescript cryptography implementation for Deno.

### Roadmap

**Symmetric Ciphesr**
  - [x] Support RSA
    - [ ] Generate RSA key
    - [x] PKCS1 v1.5 Padding
    - [x] OAEP Padding

**Asymmetric Ciphers**
  - [ ] Block Ciper Mode
     - [ ] CTR
     - [ ] CFB
     - [ ] OFB
     - [ ] ECB
  - [ ] AES (128/192/256 bits)

## Usage

```typescript
import { RSA } from "https://deno.land/x/god_crypto/mod.ts";

const publicKey = RSA.parseKey(Deno.readTextFileSync('./public.pem'));
RSA.encrypt("Hello World", publicKey); // Default OAEP SHA1
RSA.encrypt("Hello World", publicKey, { padding: "oaep", hash: "sha256" });
RSA.encrypt("Hello World", publicKey, { padding: "pkcs1" });

const privateKey = RSA.parseKey(Deno.readTextFileSync('./private.pem'));
RSA.decrypt(ciperText, privateKey);
```

## References

- [Public-Key Cryptography Standards (PKCS) #1: RSA Cryptography Specifications Version 2.1](https://tools.ietf.org/html/rfc3447)
