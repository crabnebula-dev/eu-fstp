/**
 * AES-256 security handler for PDF standard encryption.
 *
 * Used for R5-R6 encryption with AESV3 crypt filter (256-bit AES).
 * Unlike R2-R4, uses the file encryption key directly for all objects
 * (no per-object key derivation).
 *
 * Data format: [16-byte IV][ciphertext with PKCS#7 padding]
 *
 * @see PDF 2.0 Specification, Section 7.6.3.3 (AES-256 encryption)
 */

import { aesDecrypt, aesEncrypt } from "../ciphers/aes";
import { AbstractSecurityHandler } from "./abstract";

export class AES256Handler extends AbstractSecurityHandler {
  readonly algorithm = "AES-256" as const;

  protected encrypt(data: Uint8Array, _objNum: number, _genNum: number): Uint8Array {
    return aesEncrypt(this.fileKey, data);
  }

  protected decrypt(data: Uint8Array, _objNum: number, _genNum: number): Uint8Array {
    return aesDecrypt(this.fileKey, data);
  }
}
