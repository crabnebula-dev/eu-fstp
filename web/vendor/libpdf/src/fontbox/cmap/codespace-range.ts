/**
 * CodespaceRange - defines valid ranges of character codes in a CMap.
 *
 * A codespace range specifies the valid byte sequences that can be used
 * as character codes. For multi-byte encodings, it defines both the number
 * of bytes and valid ranges for each byte position.
 *
 * Examples:
 * - <00> <FF> defines a single-byte range from 0x00 to 0xFF
 * - <8140> <9FFC> defines a two-byte range where:
 *   - First byte: 0x81 to 0x9F
 *   - Second byte: 0x40 to 0xFC
 */

/**
 * A codespace range that defines valid character code sequences.
 */
export class CodespaceRange {
  /** Start values for each byte position */
  readonly start: readonly number[];
  /** End values for each byte position */
  readonly end: readonly number[];
  /** Number of bytes in codes in this range */
  readonly codeLength: number;

  /**
   * Create a codespace range.
   * @param startBytes Start of the range
   * @param endBytes End of the range
   */
  constructor(startBytes: Uint8Array, endBytes: Uint8Array) {
    let correctedStart = startBytes;

    // Handle special case: <00> to <XXXX> - extend start to match end length
    if (startBytes.length !== endBytes.length && startBytes.length === 1 && startBytes[0] === 0) {
      correctedStart = new Uint8Array(endBytes.length);
    } else if (startBytes.length !== endBytes.length) {
      throw new Error("The start and the end values must not have different lengths.");
    }

    const start: number[] = [];
    const end: number[] = [];

    for (let i = 0; i < correctedStart.length; i++) {
      start.push(correctedStart[i]);
      end.push(endBytes[i]);
    }

    this.start = start;
    this.end = end;
    this.codeLength = endBytes.length;
  }

  /**
   * Check if the given code bytes match this codespace range.
   * @param code The code bytes to check
   * @returns true if the code matches this range
   */
  matches(code: Uint8Array): boolean {
    return this.isFullMatch(code, code.length);
  }

  /**
   * Check if the given number of code bytes match this codespace range.
   * @param code The code bytes to check
   * @param codeLen Number of bytes to check
   * @returns true if the bytes match this range
   */
  isFullMatch(code: Uint8Array, codeLen: number): boolean {
    if (this.codeLength !== codeLen) {
      return false;
    }

    for (let i = 0; i < this.codeLength; i++) {
      const byte = code[i];

      if (byte < this.start[i] || byte > this.end[i]) {
        return false;
      }
    }

    return true;
  }
}
