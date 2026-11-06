/**
 * RC2 cipher implementation (RFC 2268).
 *
 * Pure JavaScript implementation of RC2 for decrypting legacy PKCS#12 files.
 * Web Crypto API doesn't support RC2, so we need this for compatibility
 * with older P12 files that use RC2-40 or RC2-128 encryption.
 *
 * @see RFC 2268 - A Description of the RC2(r) Encryption Algorithm
 */

// ─────────────────────────────────────────────────────────────────────────────
// RC2 Constants
// ─────────────────────────────────────────────────────────────────────────────

/** RC2 permutation table (PITABLE) */
const PITABLE = [
  0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
  0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
  0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
  0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
  0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
  0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
  0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
  0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
  0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
  0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
  0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
  0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
  0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
  0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
  0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
  0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
] as const;

// ─────────────────────────────────────────────────────────────────────────────
// Key Expansion
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Expand RC2 key to 64 16-bit words.
 *
 * @param key - Key bytes
 * @param effectiveBits - Effective key length in bits
 * @returns Expanded key schedule (64 16-bit words)
 */
function expandKey(key: Uint8Array, effectiveBits: number): Uint16Array {
  const L = new Uint8Array(128);

  L.set(key);

  const T = key.length;
  const T1 = effectiveBits;
  const T8 = Math.floor((T1 + 7) / 8);
  const TM = 0xff >> (8 * T8 - T1);

  // Expand key using PITABLE
  for (let i = T; i < 128; i++) {
    L[i] = PITABLE[(L[i - 1] + L[i - T]) & 0xff];
  }

  // Apply effective key bits mask
  L[128 - T8] = PITABLE[L[128 - T8] & TM];

  // Complete key expansion
  for (let i = 127 - T8; i >= 0; i--) {
    L[i] = PITABLE[L[i + 1] ^ L[i + T8]];
  }

  // Convert to 16-bit words (little-endian)
  const K = new Uint16Array(64);

  for (let i = 0; i < 64; i++) {
    K[i] = L[i * 2] | (L[i * 2 + 1] << 8);
  }

  return K;
}

// ─────────────────────────────────────────────────────────────────────────────
// Round Functions
// ─────────────────────────────────────────────────────────────────────────────

/** RC2 reverse mixing round (for decryption) */
function mixInverse(R: Uint16Array, K: Uint16Array, j: number): void {
  R[3] = ((R[3] >> 5) | (R[3] << 11)) & 0xffff;
  R[3] = (R[3] - K[j + 3] - (R[2] & R[1]) - (~R[2] & R[0])) & 0xffff;

  R[2] = ((R[2] >> 3) | (R[2] << 13)) & 0xffff;
  R[2] = (R[2] - K[j + 2] - (R[1] & R[0]) - (~R[1] & R[3])) & 0xffff;

  R[1] = ((R[1] >> 2) | (R[1] << 14)) & 0xffff;
  R[1] = (R[1] - K[j + 1] - (R[0] & R[3]) - (~R[0] & R[2])) & 0xffff;

  R[0] = ((R[0] >> 1) | (R[0] << 15)) & 0xffff;
  R[0] = (R[0] - K[j] - (R[3] & R[2]) - (~R[3] & R[1])) & 0xffff;
}

/** RC2 reverse mashing round (for decryption) */
function mashInverse(R: Uint16Array, K: Uint16Array): void {
  R[3] = (R[3] - K[R[2] & 63]) & 0xffff;
  R[2] = (R[2] - K[R[1] & 63]) & 0xffff;
  R[1] = (R[1] - K[R[0] & 63]) & 0xffff;
  R[0] = (R[0] - K[R[3] & 63]) & 0xffff;
}

// ─────────────────────────────────────────────────────────────────────────────
// Block Decryption
// ─────────────────────────────────────────────────────────────────────────────

/** Decrypt a single RC2 block */
function decryptBlock(block: Uint8Array, K: Uint16Array): Uint8Array {
  // Load block as 16-bit words (little-endian)
  const R = new Uint16Array(4);

  R[0] = block[0] | (block[1] << 8);
  R[1] = block[2] | (block[3] << 8);
  R[2] = block[4] | (block[5] << 8);
  R[3] = block[6] | (block[7] << 8);

  // Rounds 16-11 (reverse order)
  for (let j = 60; j >= 44; j -= 4) {
    mixInverse(R, K, j);
  }

  mashInverse(R, K);

  // Rounds 10-5
  for (let j = 40; j >= 20; j -= 4) {
    mixInverse(R, K, j);
  }

  mashInverse(R, K);

  // Rounds 4-1
  for (let j = 16; j >= 0; j -= 4) {
    mixInverse(R, K, j);
  }

  // Store result (little-endian)
  const result = new Uint8Array(8);

  result[0] = R[0] & 0xff;
  result[1] = (R[0] >> 8) & 0xff;
  result[2] = R[1] & 0xff;
  result[3] = (R[1] >> 8) & 0xff;
  result[4] = R[2] & 0xff;
  result[5] = (R[2] >> 8) & 0xff;
  result[6] = R[3] & 0xff;
  result[7] = (R[3] >> 8) & 0xff;

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/**
 * RC2 cipher implementation.
 *
 * Provides CBC mode decryption with configurable effective key bits.
 */
// biome-ignore lint/complexity/noStaticOnlyClass: utility class
export class RC2 {
  /** Block size in bytes */
  static readonly BLOCK_SIZE = 8;

  /** Common effective key sizes */
  static readonly EFFECTIVE_BITS_40 = 40;
  static readonly EFFECTIVE_BITS_64 = 64;
  static readonly EFFECTIVE_BITS_128 = 128;

  /**
   * Decrypt data using RC2 in CBC mode.
   *
   * @param data - Encrypted data (must be multiple of 8 bytes)
   * @param key - Key bytes
   * @param iv - 8-byte initialization vector
   * @param effectiveBits - Effective key bits (40, 64, or 128)
   * @param removePadding - Whether to remove PKCS#7 padding (default: true)
   * @returns Decrypted data
   * @throws {Error} if IV or data length is invalid
   */
  static decrypt(
    data: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array,
    effectiveBits: number,
    removePadding = true,
  ): Uint8Array {
    if (iv.length !== RC2.BLOCK_SIZE) {
      throw new Error(`Invalid IV length: ${iv.length}, expected ${RC2.BLOCK_SIZE}`);
    }

    if (data.length % RC2.BLOCK_SIZE !== 0) {
      throw new Error(`Invalid data length: ${data.length}, must be multiple of ${RC2.BLOCK_SIZE}`);
    }

    const K = expandKey(key, effectiveBits);
    const result = new Uint8Array(data.length);

    let prevBlock = iv;

    for (let i = 0; i < data.length; i += RC2.BLOCK_SIZE) {
      const block = data.subarray(i, i + RC2.BLOCK_SIZE);
      const decrypted = decryptBlock(block, K);

      // XOR with previous ciphertext block (CBC)
      for (let j = 0; j < RC2.BLOCK_SIZE; j++) {
        result[i + j] = decrypted[j] ^ prevBlock[j];
      }

      prevBlock = block;
    }

    if (removePadding) {
      return RC2.removePkcs7Padding(result);
    }

    return result;
  }

  /**
   * Remove PKCS#7 padding from decrypted data.
   */
  private static removePkcs7Padding(data: Uint8Array): Uint8Array {
    if (data.length === 0) {
      return data;
    }

    const padLen = data[data.length - 1];

    if (padLen > 0 && padLen <= RC2.BLOCK_SIZE) {
      // Verify padding is valid
      for (let i = data.length - padLen; i < data.length; i++) {
        if (data[i] !== padLen) {
          return data; // Invalid padding, return as-is
        }
      }

      return data.subarray(0, data.length - padLen);
    }

    return data;
  }
}
