/**
 * Triple DES (3DES-EDE-CBC) cipher implementation.
 *
 * Pure JavaScript implementation of Triple DES for decrypting legacy
 * PKCS#12 files. Web Crypto API doesn't support 3DES, so we need this
 * for compatibility with older P12 files.
 *
 * @see FIPS 46-3 for DES specification
 * @see NIST SP 800-67 for Triple DES specification
 */

// ─────────────────────────────────────────────────────────────────────────────
// DES Constants
// ─────────────────────────────────────────────────────────────────────────────

/** DES S-boxes for the Feistel function */
const SBOXES = [
  [
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11,
    9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5,
    11, 3, 14, 10, 0, 6, 13,
  ],
  [
    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10,
    6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2,
    11, 6, 7, 12, 0, 5, 14, 9,
  ],
  [
    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12,
    11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4,
    15, 14, 3, 11, 5, 2, 12,
  ],
  [
    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1,
    10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9,
    4, 5, 11, 12, 7, 2, 14,
  ],
  [
    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10,
    3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6,
    15, 0, 9, 10, 4, 5, 3,
  ],
  [
    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14,
    0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10,
    11, 14, 1, 7, 6, 0, 8, 13,
  ],
  [
    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12,
    2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9,
    5, 0, 15, 14, 2, 3, 12,
  ],
  [
    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11,
    0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13,
    15, 12, 9, 0, 3, 5, 6, 11,
  ],
];

/** Initial permutation table */
const IP = [
  58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64,
  56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53,
  45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

/** Final permutation table (inverse of IP) */
const IP_INV = [
  40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37,
  5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2,
  42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

/** Expansion permutation table (32 to 48 bits) */
const E = [
  32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19,
  20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

/** P-box permutation table */
const P = [
  16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13,
  30, 6, 22, 11, 4, 25,
];

/** Permuted choice 1 (key schedule) */
const PC1 = [
  57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
  52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
  13, 5, 28, 20, 12, 4,
];

/** Permuted choice 2 (key schedule) */
const PC2 = [
  14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
  31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

/** Left shift schedule for key generation */
const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

// ─────────────────────────────────────────────────────────────────────────────
// Helper Functions
// ─────────────────────────────────────────────────────────────────────────────

/** Get bit at position from byte array (1-indexed) */
function getBit(data: Uint8Array, pos: number): number {
  const byteIdx = Math.floor((pos - 1) / 8);
  const bitIdx = 7 - ((pos - 1) % 8);

  return (data[byteIdx] >> bitIdx) & 1;
}

/** Apply permutation to byte array */
function permute(data: Uint8Array, table: readonly number[]): Uint8Array {
  const result = new Uint8Array(Math.ceil(table.length / 8));

  for (let i = 0; i < table.length; i++) {
    const bit = getBit(data, table[i]);
    const byteIdx = Math.floor(i / 8);
    const bitIdx = 7 - (i % 8);

    result[byteIdx] |= bit << bitIdx;
  }

  return result;
}

/** Left rotate 28-bit value */
function rotateLeft28(val: number, shifts: number): number {
  return ((val << shifts) | (val >> (28 - shifts))) & 0x0fffffff;
}

// ─────────────────────────────────────────────────────────────────────────────
// DES Implementation
// ─────────────────────────────────────────────────────────────────────────────

/** Generate DES subkeys from 8-byte key */
function generateSubkeys(key: Uint8Array): Uint8Array[] {
  const pc1 = permute(key, PC1);

  let C = ((pc1[0] << 20) | (pc1[1] << 12) | (pc1[2] << 4) | (pc1[3] >> 4)) & 0x0fffffff;
  let D = (((pc1[3] & 0x0f) << 24) | (pc1[4] << 16) | (pc1[5] << 8) | pc1[6]) & 0x0fffffff;

  const subkeys: Uint8Array[] = [];

  for (let i = 0; i < 16; i++) {
    C = rotateLeft28(C, SHIFTS[i]);
    D = rotateLeft28(D, SHIFTS[i]);

    const CD = new Uint8Array(7);

    CD[0] = (C >> 20) & 0xff;
    CD[1] = (C >> 12) & 0xff;
    CD[2] = (C >> 4) & 0xff;
    CD[3] = ((C << 4) | (D >> 24)) & 0xff;
    CD[4] = (D >> 16) & 0xff;
    CD[5] = (D >> 8) & 0xff;
    CD[6] = D & 0xff;

    subkeys.push(permute(CD, PC2));
  }

  return subkeys;
}

/** DES Feistel function */
function feistel(R: Uint8Array, K: Uint8Array): Uint8Array {
  const expanded = permute(R, E);

  for (let i = 0; i < 6; i++) {
    expanded[i] ^= K[i];
  }

  const sboxOut = new Uint8Array(4);

  for (let i = 0; i < 8; i++) {
    const bitOffset = i * 6;
    const byteOffset = Math.floor(bitOffset / 8);
    const bitShift = bitOffset % 8;

    let sixBits: number;

    if (bitShift <= 2) {
      sixBits = (expanded[byteOffset] >> (2 - bitShift)) & 0x3f;
    } else {
      sixBits =
        ((expanded[byteOffset] << (bitShift - 2)) | (expanded[byteOffset + 1] >> (10 - bitShift))) &
        0x3f;
    }

    const row = ((sixBits >> 4) & 2) | (sixBits & 1);
    const col = (sixBits >> 1) & 0x0f;
    const sboxVal = SBOXES[i][row * 16 + col];

    const outByteIdx = Math.floor(i / 2);
    const outBitIdx = (i % 2) * 4;

    sboxOut[outByteIdx] |= sboxVal << (4 - outBitIdx);
  }

  return permute(sboxOut, P);
}

/** Single DES block encryption/decryption */
function desBlock(block: Uint8Array, subkeys: Uint8Array[], decrypt: boolean): Uint8Array {
  const ip = permute(block, IP);

  let L = ip.slice(0, 4);
  let R = ip.slice(4, 8);

  const keys = decrypt ? [...subkeys].reverse() : subkeys;

  for (let i = 0; i < 16; i++) {
    const f = feistel(R, keys[i]);
    const newR = new Uint8Array(4);

    for (let j = 0; j < 4; j++) {
      newR[j] = L[j] ^ f[j];
    }

    L = R;
    R = newR;
  }

  const RL = new Uint8Array(8);

  RL.set(R, 0);
  RL.set(L, 4);

  return permute(RL, IP_INV);
}

/** Triple DES (EDE) block operation */
function tripleDesBlock(block: Uint8Array, keys: Uint8Array[][], decrypt: boolean): Uint8Array {
  if (decrypt) {
    const single = desBlock(block, keys[2], true);
    const double = desBlock(single, keys[1], false);
    const triple = desBlock(double, keys[0], true);

    return triple;
  } else {
    const single = desBlock(block, keys[0], false);
    const double = desBlock(single, keys[1], true);
    const triple = desBlock(double, keys[2], false);

    return triple;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Triple DES cipher implementation.
 *
 * Provides CBC mode decryption for 3-key Triple DES (EDE).
 */
// biome-ignore lint/complexity/noStaticOnlyClass: utility class
export class TripleDES {
  /** Block size in bytes */
  static readonly BLOCK_SIZE = 8;

  /** Key size in bytes (3 x 8-byte DES keys) */
  static readonly KEY_SIZE = 24;

  /**
   * Decrypt data using Triple DES in CBC mode.
   *
   * @param data - Encrypted data (must be multiple of 8 bytes)
   * @param key - 24-byte key (3 x 8-byte DES keys)
   * @param iv - 8-byte initialization vector
   * @param removePadding - Whether to remove PKCS#7 padding (default: true)
   * @returns Decrypted data
   * @throws {Error} if key, IV, or data length is invalid
   */
  static decrypt(
    data: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array,
    removePadding = true,
  ): Uint8Array {
    if (key.length !== TripleDES.KEY_SIZE) {
      throw new Error(`Invalid 3DES key length: ${key.length}, expected ${TripleDES.KEY_SIZE}`);
    }

    if (iv.length !== TripleDES.BLOCK_SIZE) {
      throw new Error(`Invalid IV length: ${iv.length}, expected ${TripleDES.BLOCK_SIZE}`);
    }

    if (data.length % TripleDES.BLOCK_SIZE !== 0) {
      throw new Error(
        `Invalid data length: ${data.length}, must be multiple of ${TripleDES.BLOCK_SIZE}`,
      );
    }

    // Generate subkeys for each DES key
    const subkeys = [
      generateSubkeys(key.subarray(0, 8)),
      generateSubkeys(key.subarray(8, 16)),
      generateSubkeys(key.subarray(16, 24)),
    ];

    const result = new Uint8Array(data.length);
    let prevBlock = iv;

    for (let i = 0; i < data.length; i += TripleDES.BLOCK_SIZE) {
      const block = data.subarray(i, i + TripleDES.BLOCK_SIZE);
      const decrypted = tripleDesBlock(block, subkeys, true);

      // XOR with previous ciphertext block (CBC)
      for (let j = 0; j < TripleDES.BLOCK_SIZE; j++) {
        result[i + j] = decrypted[j] ^ prevBlock[j];
      }

      prevBlock = block;
    }

    if (removePadding) {
      return TripleDES.removePkcs7Padding(result);
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

    if (padLen > 0 && padLen <= TripleDES.BLOCK_SIZE) {
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
