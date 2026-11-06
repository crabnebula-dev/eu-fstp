/**
 * AES-128 security handler for PDF standard encryption.
 *
 * Used for R4 encryption with AESV2 crypt filter (128-bit AES).
 * Derives a per-object key using MD5 with "sAlT" suffix,
 * then encrypts/decrypts with AES-CBC.
 *
 * Data format: [16-byte IV][ciphertext with PKCS#7 padding]
 *
 * @see PDF 2.0 Specification, Section 7.6.2 (Algorithm 1)
 * @see PDF 2.0 Specification, Section 7.6.3.2 (AES encryption)
 */

import { aesDecrypt, aesEncrypt } from "../ciphers/aes";
import { deriveObjectKey } from "../key-derivation/md5-based";
import { AbstractSecurityHandler } from "./abstract";

export class AES128Handler extends AbstractSecurityHandler {
  readonly algorithm = "AES-128" as const;

  protected encrypt(data: Uint8Array, objNum: number, genNum: number): Uint8Array {
    const objectKey = deriveObjectKey(this.fileKey, objNum, genNum, true);

    return aesEncrypt(objectKey, data);
  }

  protected decrypt(data: Uint8Array, objNum: number, genNum: number): Uint8Array {
    const objectKey = deriveObjectKey(this.fileKey, objNum, genNum, true);

    return aesDecrypt(objectKey, data);
  }
}
