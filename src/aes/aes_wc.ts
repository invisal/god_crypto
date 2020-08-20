import { AESBase } from "./aes_base.ts";
import { BlockCiperConfig } from "./common.ts";

function base64(m: Uint8Array) {
  return btoa(String.fromCharCode.apply(null, [...m])).replace(/=/g, "");
}

export class WebCryptoAES implements AESBase {
  protected key: Uint8Array;
  protected config: BlockCiperConfig;
  protected wkey: any = null; // WebCrypto Key

  constructor(
    key: Uint8Array,
    config: BlockCiperConfig,
  ) {
    this.key = key;
    this.config = config;
  }

  protected async loadKey() {
    if (this.wkey === null) {
      // @ts-ignore
      this.wkey = await crypto.subtle.importKey(
        "jwk",
        { kty: "oct", k: base64(this.key) },
        "AES-CBC",
        true,
        ["encrypt", "decrypt"],
      );
    }

    return this.wkey;
  }

  async encrypt(m: Uint8Array) {
    const key = await this.loadKey();
    const option = { name: "AES-CBC", iv: this.config.iv };

    // @ts-ignore
    const data = await crypto.subtle.encrypt(option, key, m);
    return new Uint8Array(data);
  }

  async decrypt(m: Uint8Array) {
    const key = await this.loadKey();
    const option = { name: "AES-CBC", iv: this.config.iv };

    // @ts-ignore
    const data = await crypto.subtle.decrypt(option, key, m);
    return new Uint8Array(data);
  }
}
