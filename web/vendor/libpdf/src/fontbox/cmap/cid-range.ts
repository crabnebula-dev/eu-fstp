/**
 * CIDRange - a range of continuous CID mappings.
 *
 * Used to efficiently represent ranges like:
 *   <0000> <00FF> 0    -> codes 0x0000-0x00FF map to CIDs 0-255
 *   <8000> <8FFF> 1000 -> codes 0x8000-0x8FFF map to CIDs 1000-5095
 */

import { bytesToInt } from "./utils.ts";

/**
 * A range mapping character codes to CIDs.
 */
export class CIDRange {
  /** Start of the character code range */
  private from: number;
  /** End of the character code range (mutable for extension) */
  private to: number;
  /** Starting CID value */
  private readonly cid: number;
  /** Byte length of character codes in this range */
  private readonly codeLength: number;

  /**
   * Create a CID range.
   * @param from Start value of code range
   * @param to End value of code range
   * @param cid Starting CID value
   * @param codeLength Byte length of codes
   */
  constructor(from: number, to: number, cid: number, codeLength: number) {
    this.from = from;
    this.to = to;
    this.cid = cid;
    this.codeLength = codeLength;
  }

  /**
   * Get the byte length of codes in this range.
   */
  getCodeLength(): number {
    return this.codeLength;
  }

  /**
   * Map a character code (as bytes) to a CID.
   * @param bytes Character code bytes
   * @returns CID, or -1 if the code is out of range
   */
  mapBytes(bytes: Uint8Array): number {
    if (bytes.length === this.codeLength) {
      const code = bytesToInt(bytes);

      if (code >= this.from && code <= this.to) {
        return this.cid + (code - this.from);
      }
    }

    return -1;
  }

  /**
   * Map a character code to a CID.
   * @param code Character code value
   * @param length Original byte length of the code
   * @returns CID, or -1 if the code is out of range
   */
  map(code: number, length: number): number {
    if (length === this.codeLength && code >= this.from && code <= this.to) {
      return this.cid + (code - this.from);
    }

    return -1;
  }

  /**
   * Reverse map a CID to a character code.
   * @param cidValue CID to look up
   * @returns Character code, or -1 if the CID is out of range
   */
  unmap(cidValue: number): number {
    const maxCid = this.cid + (this.to - this.from);

    if (cidValue >= this.cid && cidValue <= maxCid) {
      return this.from + (cidValue - this.cid);
    }

    return -1;
  }

  /**
   * Try to extend this range with consecutive values.
   *
   * If the new range is consecutive with this range (same code length,
   * next code value, next CID value), extends this range instead of
   * requiring a new range object.
   *
   * @param newFrom Start of new range
   * @param newTo End of new range
   * @param newCid Starting CID of new range
   * @param length Byte length of new codes
   * @returns true if this range was extended
   */
  extend(newFrom: number, newTo: number, newCid: number, length: number): boolean {
    // Check if this is a consecutive extension
    const expectedCid = this.cid + (this.to - this.from) + 1;

    if (this.codeLength === length && newFrom === this.to + 1 && newCid === expectedCid) {
      this.to = newTo;

      return true;
    }

    return false;
  }
}
