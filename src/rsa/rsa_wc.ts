import { RSABase } from "./rsa_base.ts";
import { RSAKey, RSAOption } from "./common.ts";

function big_base64(m: bigint) {
  const bytes = [];

  while (m > 0n) {
    bytes.push(Number(m & 255n));
    m = m >> 8n;
  }

  bytes.reverse();
  let a = btoa(String.fromCharCode.apply(null, bytes)).replace(/=/g, "");
  a = a.replace(/\+/g, "-");
  a = a.replace(/\//g, "_");
  return a;
}

export class WebCryptoRSA implements RSABase {
  key: RSAKey;
  options: RSAOption;
  encryptedKey: any = null;
  decryptedKey: any = null;

  constructor(key: RSAKey, options: RSAOption) {
    this.key = key;
    this.options = options;
  }

  protected getHashFunctionName() {
    if (this.options.hash === "sha1") return "SHA-1";
    if (this.options.hash === "sha256") return "SHA-256";
    return "";
  }

  protected async loadKeyForDecrypt() {
    if (!this.key.e) return null;
    if (!this.key.d) return null;

    if (this.decryptedKey === null) {
      const jwk = {
        kty: "RSA",
        n: big_base64(this.key.n),
        d: big_base64(this.key.d),
        e: big_base64(this.key.e),
        p: this.key.p ? big_base64(this.key.p) : undefined,
        q: this.key.q ? big_base64(this.key.q) : undefined,
        dp: this.key.dp ? big_base64(this.key.dp) : undefined,
        dq: this.key.dq ? big_base64(this.key.dq) : undefined,
        qi: this.key.qi ? big_base64(this.key.qi) : undefined,
        ext: true,
      };

      // @ts-ignore
      this.decryptedKey = await crypto.subtle.importKey(
        "jwk",
        jwk,
        {
          name: "RSA-OAEP",
          hash: { name: this.getHashFunctionName() },
        },
        false,
        ["decrypt"],
      );
    }

    return this.decryptedKey;
  }

  protected async loadKeyForEncrypt() {
    if (!this.key.e) return null;

    if (this.encryptedKey === null) {
      const jwk = {
        kty: "RSA",
        e: big_base64(this.key.e),
        n: big_base64(this.key.n),
        ext: true,
      };

      // @ts-ignore
      this.encryptedKey = await crypto.subtle.importKey(
        "jwk",
        jwk,
        {
          name: "RSA-OAEP",
          hash: { name: this.getHashFunctionName() },
        },
        false,
        ["encrypt"],
      );
    }

    return this.encryptedKey;
  }

  async encrypt(m: Uint8Array) {
    // @ts-ignore
    return await crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      await this.loadKeyForEncrypt(),
      m,
    );
  }

  async decrypt(m: Uint8Array) {
    // @ts-ignore
    return await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      await this.loadKeyForDecrypt(),
      m,
    );
  }
}
