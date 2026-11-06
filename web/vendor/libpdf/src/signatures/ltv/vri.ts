/**
 * VRI (Validation-Related Information) key computation utilities.
 *
 * The VRI dictionary in a DSS uses uppercase hex SHA-1 hashes of signature
 * /Contents values as keys to associate validation data with specific signatures.
 *
 * PDF 2.0: Section 12.8.4.3 - Document Security Store dictionary
 */

import { bytesToHex, toArrayBuffer } from "#src/helpers/buffer.ts";

/**
 * Compute SHA-1 hash for VRI key (uppercase).
 *
 * The VRI key is uppercase hex SHA-1 of the signature's /Contents value,
 * including any zero-padding. This matches how the bytes appear in the PDF.
 *
 * @param cmsBytes - CMS bytes (may be zero-padded from PDF /Contents)
 * @returns Uppercase hex-encoded SHA-1 hash
 */
export async function computeVriKey(cmsBytes: Uint8Array): Promise<string> {
  const hex = await computeSha1Hex(cmsBytes);

  return hex.toUpperCase();
}

/**
 * Compute SHA-1 hash of data (for deduplication and VRI keys).
 *
 * Uses Web Crypto for SHA-1 since @noble/hashes focuses on SHA-2.
 *
 * @param data - Data to hash
 * @returns Lowercase hex-encoded SHA-1 hash
 */
export async function computeSha1Hex(data: Uint8Array): Promise<string> {
  const buffer = toArrayBuffer(data);
  const hash = await crypto.subtle.digest("SHA-1", buffer);

  return bytesToHex(new Uint8Array(hash)).toLowerCase();
}
