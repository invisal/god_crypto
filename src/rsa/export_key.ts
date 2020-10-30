import { RSAKeyParams } from "./common.ts";
import { bignum_to_byte } from "../helper.ts";
import { encode } from "./../../src/utility/encode.ts";
import { BER } from "../utility/asn1.ts";

function add_line_break(base64_str: string): string {
  const lines = [];
  for (let i = 0; i < base64_str.length; i += 64) {
    lines.push(base64_str.substr(i, 64));
  }

  return lines.join("\n");
}

export function rsa_export_pkcs8_public(key: RSAKeyParams) {
  const content = BER.createSequence([
    BER.createSequence([
      new Uint8Array([
        0x06,
        0x09,
        0x2a,
        0x86,
        0x48,
        0x86,
        0xf7,
        0x0d,
        0x01,
        0x01,
        0x01,
      ]),
      BER.createNull(),
    ]),
    BER.createBitString(
      BER.createSequence([
        BER.createInteger(key.n),
        BER.createInteger(key.e || 0n),
      ])
    ),
  ]);

  return (
    "-----BEGIN PUBLIC KEY-----\n" +
    add_line_break(encode.binary(content).base64()) +
    "\n-----END PUBLIC KEY-----\n"
  );
}

export function rsa_export_pkcs8_private(key: RSAKeyParams) {
  const content = BER.createSequence([
    BER.createInteger(0),
    BER.createInteger(key.n),
    BER.createInteger(key.e || 0n),
    BER.createInteger(key.d || 0n),
    BER.createInteger(key.p || 0n),
    BER.createInteger(key.q || 0n),
    BER.createInteger(key.dp || 0n),
    BER.createInteger(key.dq || 0n),
    BER.createInteger(key.qi || 0n),
  ]);

  const ber = encode.binary(content).base64();

  return (
    "-----BEGIN RSA PRIVATE KEY-----\n" +
    add_line_break(ber) +
    "\n-----END RSA PRIVATE KEY-----\n"
  );
}
