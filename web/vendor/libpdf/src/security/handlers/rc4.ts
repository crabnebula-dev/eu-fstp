/**
 * RC4 security handler for PDF standard encryption.
 *
 * Used for R2-R4 encryption (40-128 bit keys).
 * Derives a per-object key using MD5, then encrypts/decrypts with RC4.
 *
 * RC4 is a symmetric stream cipher, so encryption and decryption
 * are identical operations.
 *
 * @see PDF 2.0 Specification, Section 7.6.2 (Algorithm 1)
 */

import { rc4 } from "../ciphers/rc4";
import { deriveObjectKey } from "../key-derivation/md5-based";
import { AbstractSecurityHandler } from "./abstract";

export class RC4Handler extends AbstractSecurityHandler {
  readonly algorithm = "RC4" as const;

  protected encrypt(data: Uint8Array, objNum: number, genNum: number): Uint8Array {
    return this.process(data, objNum, genNum);
  }

  protected decrypt(data: Uint8Array, objNum: number, genNum: number): Uint8Array {
    return this.process(data, objNum, genNum);
  }

  /**
   * Process data through RC4 cipher with per-object key derivation.
   *
   * RC4 is symmetric - XORing plaintext with keystream produces ciphertext,
   * XORing ciphertext with same keystream recovers plaintext.
   */
  private process(data: Uint8Array, objNum: number, genNum: number): Uint8Array {
    const objectKey = deriveObjectKey(this.fileKey, objNum, genNum, false);

    return rc4(objectKey, data);
  }
}
