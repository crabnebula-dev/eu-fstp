/**
 * RC4 (Rivest Cipher 4) stream cipher implementation.
 *
 * RC4 is used in PDF encryption revisions R2-R4. While cryptographically
 * weak by modern standards, it's required for compatibility with older PDFs.
 *
 * The algorithm has two phases:
 * 1. Key Scheduling Algorithm (KSA) - initializes the permutation table from the key
 * 2. Pseudo-Random Generation Algorithm (PRGA) - generates keystream bytes
 *
 * RC4 is symmetric: the same operation encrypts and decrypts.
 *
 * @see PDF 1.7 Specification, Section 7.6.2
 * @see https://en.wikipedia.org/wiki/RC4
 */

import { SINGLE_BYTE_MASK } from "#src/helpers/chars";

/**
 * RC4 cipher for PDF encryption.
 *
 * Usage:
 * ```typescript
 * const cipher = new RC4Cipher(key);
 * const encrypted = cipher.process(plaintext);
 *
 * // Decrypt with fresh cipher (RC4 is stateful)
 * const cipher2 = new RC4Cipher(key);
 * const decrypted = cipher2.process(encrypted);
 * ```
 */
export class RC4Cipher {
  /** Permutation table (256 bytes) */
  private s: Uint8Array;
  /** State pointer i */
  private i: number = 0;
  /** State pointer j */
  private j: number = 0;

  /**
   * Create a new RC4 cipher with the given key.
   *
   * @param key - Encryption key (1-256 bytes, typically 5-16 for PDF)
   * @throws {Error} if key is empty or too long
   */
  constructor(key: Uint8Array) {
    if (key.length === 0) {
      throw new Error("RC4 key cannot be empty");
    }
    if (key.length > 256) {
      throw new Error("RC4 key cannot exceed 256 bytes");
    }

    // Key Scheduling Algorithm (KSA)
    // Initialize permutation table with identity permutation
    this.s = new Uint8Array(256);
    for (let i = 0; i < 256; i++) {
      this.s[i] = i;
    }

    // Mix the permutation table using the key
    let j = 0;

    for (let i = 0; i < 256; i++) {
      j = (j + this.s[i] + key[i % key.length]) & SINGLE_BYTE_MASK;
      // Swap s[i] and s[j]
      const tmp = this.s[i];
      this.s[i] = this.s[j];
      this.s[j] = tmp;
    }
  }

  /**
   * Process data through the cipher (encrypt or decrypt).
   *
   * RC4 is symmetric, so the same operation encrypts and decrypts.
   * The cipher is stateful - each call continues from where the last left off.
   *
   * @param data - Input bytes to process
   * @returns Processed bytes (same length as input)
   */
  process(data: Uint8Array): Uint8Array {
    const output = new Uint8Array(data.length);

    for (let k = 0; k < data.length; k++) {
      // Pseudo-Random Generation Algorithm (PRGA)
      this.i = (this.i + 1) & SINGLE_BYTE_MASK;
      this.j = (this.j + this.s[this.i]) & SINGLE_BYTE_MASK;

      // Swap s[i] and s[j]
      const tmp = this.s[this.i];
      this.s[this.i] = this.s[this.j];
      this.s[this.j] = tmp;

      // Generate keystream byte and XOR with input
      const keystreamByte = this.s[(this.s[this.i] + this.s[this.j]) & SINGLE_BYTE_MASK];
      output[k] = data[k] ^ keystreamByte;
    }

    return output;
  }

  /**
   * Reset the cipher to its initial state (after KSA).
   * This allows reusing the cipher for a new encryption/decryption.
   *
   * Note: This re-runs KSA, so it's equivalent to creating a new cipher.
   * Prefer creating a new RC4Cipher instance for clarity.
   */
  reset(key: Uint8Array): void {
    this.i = 0;
    this.j = 0;

    // Re-run KSA
    for (let i = 0; i < 256; i++) {
      this.s[i] = i;
    }

    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + this.s[i] + key[i % key.length]) & SINGLE_BYTE_MASK;
      const tmp = this.s[i];
      this.s[i] = this.s[j];
      this.s[j] = tmp;
    }
  }
}

/**
 * Convenience function to encrypt/decrypt data with RC4.
 *
 * Creates a new cipher instance for each call, which is the correct
 * pattern for PDF encryption (each object gets a fresh cipher).
 *
 * @param key - Encryption key
 * @param data - Data to process
 * @returns Processed data
 */
export function rc4(key: Uint8Array, data: Uint8Array): Uint8Array {
  return new RC4Cipher(key).process(data);
}
