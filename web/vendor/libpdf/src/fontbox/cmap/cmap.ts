/**
 * CMap - Character Map for PDF fonts.
 *
 * A CMap defines mappings between character codes and:
 * - Unicode characters (ToUnicode CMaps)
 * - CIDs (CID-keyed font CMaps)
 *
 * CMaps support variable-length character codes (1-4 bytes) and can map
 * codes to single characters, character sequences (ligatures), or CIDs.
 */

import { CIDRange } from "./cid-range.ts";
import type { CodespaceRange } from "./codespace-range.ts";
import { bytesToInt, bytesToIntN } from "./utils.ts";

/**
 * A CMap that maps character codes to Unicode strings or CIDs.
 */
export class CMap {
  // CMap metadata
  private _wmode = 0;
  private _name: string | undefined;
  private _version: string | undefined;
  private _type = -1;

  // CIDSystemInfo
  private _registry: string | undefined;
  private _ordering: string | undefined;
  private _supplement = 0;

  // Code length bounds
  private _minCodeLength = 4;
  private _maxCodeLength = 0;
  private _minCidLength = 4;
  private _maxCidLength = 0;

  // Codespace ranges
  private readonly codespaceRanges: CodespaceRange[] = [];

  // Unicode mappings by byte length
  private readonly charToUnicodeOneByte = new Map<number, string>();
  private readonly charToUnicodeTwoBytes = new Map<number, string>();
  private readonly charToUnicodeMoreBytes = new Map<number, string>();

  // CID mappings: byteLength -> (code -> cid)
  private readonly codeToCid = new Map<number, Map<number, number>>();
  private readonly codeToCidRanges: CIDRange[] = [];

  // Reverse mapping: unicode -> code bytes
  private readonly unicodeToByteCodes = new Map<string, Uint8Array>();

  // Space character code (cached for convenience)
  private _spaceMapping = -1;

  // =========================================================================
  // Public API - Queries
  // =========================================================================

  /**
   * Check if this CMap has any CID mappings.
   */
  hasCIDMappings(): boolean {
    return this.codeToCid.size > 0 || this.codeToCidRanges.length > 0;
  }

  /**
   * Check if this CMap has any Unicode mappings.
   */
  hasUnicodeMappings(): boolean {
    return (
      this.charToUnicodeOneByte.size > 0 ||
      this.charToUnicodeTwoBytes.size > 0 ||
      this.charToUnicodeMoreBytes.size > 0
    );
  }

  /**
   * Map a character code to Unicode.
   *
   * This convenience method tries to determine the code length automatically.
   * For more accurate results, use toUnicodeWithLength.
   *
   * @param code Character code value
   * @returns Unicode string, or undefined if not mapped
   */
  toUnicode(code: number): string | undefined {
    // Try one byte first for small values
    if (code < 256) {
      const result = this.toUnicodeWithLength(code, 1);

      if (result !== undefined) {
        return result;
      }
    }

    // Try two bytes
    if (code <= 0xffff) {
      return this.toUnicodeWithLength(code, 2);
    }

    // Try three bytes
    if (code <= 0xffffff) {
      return this.toUnicodeWithLength(code, 3);
    }

    // Try four bytes
    return this.toUnicodeWithLength(code, 4);
  }

  /**
   * Map a character code to Unicode with explicit length.
   * @param code Character code value
   * @param length Original byte length of the code
   * @returns Unicode string, or undefined if not mapped
   */
  toUnicodeWithLength(code: number, length: number): string | undefined {
    switch (length) {
      case 1:
        return this.charToUnicodeOneByte.get(code);
      case 2:
        return this.charToUnicodeTwoBytes.get(code);
      default:
        return this.charToUnicodeMoreBytes.get(code);
    }
  }

  /**
   * Map character code bytes to Unicode.
   * @param code Character code bytes
   * @returns Unicode string, or undefined if not mapped
   */
  toUnicodeBytes(code: Uint8Array): string | undefined {
    return this.toUnicodeWithLength(bytesToInt(code), code.length);
  }

  /**
   * Map a character code to a CID.
   *
   * This convenience method tries to determine the code length automatically.
   * For more accurate results, use toCIDWithLength.
   *
   * @param code Character code value
   * @returns CID, or 0 if not mapped
   */
  toCID(code: number): number {
    if (!this.hasCIDMappings()) {
      return 0;
    }

    let cid = 0;
    let length = this._minCidLength;

    while (cid === 0 && length <= this._maxCidLength) {
      cid = this.toCIDWithLength(code, length);

      length++;
    }

    return cid;
  }

  /**
   * Map a character code to a CID with explicit length.
   * @param code Character code value
   * @param length Original byte length of the code
   * @returns CID, or 0 if not mapped
   */
  toCIDWithLength(code: number, length: number): number {
    if (!this.hasCIDMappings() || length < this._minCidLength || length > this._maxCidLength) {
      return 0;
    }

    // Check direct mappings first
    const codeToCidMap = this.codeToCid.get(length);
    if (codeToCidMap) {
      const cid = codeToCidMap.get(code);

      if (cid !== undefined) {
        return cid;
      }
    }

    // Check ranges
    return this.toCIDFromRanges(code, length);
  }

  /**
   * Map character code bytes to a CID.
   * @param code Character code bytes
   * @returns CID, or 0 if not mapped
   */
  toCIDBytes(code: Uint8Array): number {
    if (
      !this.hasCIDMappings() ||
      code.length < this._minCidLength ||
      code.length > this._maxCidLength
    ) {
      return 0;
    }

    const codeInt = bytesToInt(code);

    // Check direct mappings
    const codeToCidMap = this.codeToCid.get(code.length);

    if (codeToCidMap) {
      const cid = codeToCidMap.get(codeInt);

      if (cid !== undefined) {
        return cid;
      }
    }

    // Check ranges
    return this.toCIDFromRangesBytes(code);
  }

  /**
   * Get the byte codes for a Unicode string.
   * @param unicode Unicode string
   * @returns Code bytes, or undefined if not mapped
   */
  getCodesFromUnicode(unicode: string): Uint8Array | undefined {
    return this.unicodeToByteCodes.get(unicode);
  }

  /**
   * Read a character code from a byte stream.
   *
   * Reads the minimum number of bytes needed to match a codespace range,
   * up to the maximum code length.
   *
   * @param bytes Byte array to read from
   * @param offset Starting offset
   * @returns [code, bytesConsumed] tuple
   */
  readCode(bytes: Uint8Array, offset: number): [number, number] {
    const maxLen = Math.min(this._maxCodeLength, bytes.length - offset);

    // Read minimum bytes first
    const buffer = new Uint8Array(this._maxCodeLength);
    for (let i = 0; i < this._minCodeLength && offset + i < bytes.length; i++) {
      buffer[i] = bytes[offset + i];
    }

    // Try to match a codespace range
    for (let i = this._minCodeLength - 1; i < maxLen; i++) {
      const byteCount = i + 1;

      // Check if any codespace range matches
      for (const range of this.codespaceRanges) {
        if (range.isFullMatch(buffer, byteCount)) {
          return [bytesToIntN(buffer, byteCount), byteCount];
        }
      }

      // Read next byte if available
      if (byteCount < maxLen) {
        buffer[byteCount] = bytes[offset + byteCount];
      }
    }

    // No match found - return minimum code length (Adobe Reader behavior)
    return [bytesToIntN(buffer, this._minCodeLength), this._minCodeLength];
  }

  // =========================================================================
  // Public API - Metadata
  // =========================================================================

  /** Writing mode: 0 = horizontal, 1 = vertical */
  get wmode(): number {
    return this._wmode;
  }
  set wmode(value: number) {
    this._wmode = value;
  }

  /** CMap name */
  get name(): string | undefined {
    return this._name;
  }
  set name(value: string | undefined) {
    this._name = value;
  }

  /** CMap version */
  get version(): string | undefined {
    return this._version;
  }
  set version(value: string | undefined) {
    this._version = value;
  }

  /** CMap type */
  get type(): number {
    return this._type;
  }

  set type(value: number) {
    this._type = value;
  }

  /** CIDSystemInfo registry */
  get registry(): string | undefined {
    return this._registry;
  }

  set registry(value: string | undefined) {
    this._registry = value;
  }

  /** CIDSystemInfo ordering */
  get ordering(): string | undefined {
    return this._ordering;
  }

  set ordering(value: string | undefined) {
    this._ordering = value;
  }

  /** CIDSystemInfo supplement */
  get supplement(): number {
    return this._supplement;
  }

  set supplement(value: number) {
    this._supplement = value;
  }

  /** Character code for space character, or -1 if unknown */
  get spaceMapping(): number {
    return this._spaceMapping;
  }

  // =========================================================================
  // Internal - Building the CMap
  // =========================================================================

  /**
   * Add a codespace range.
   */
  addCodespaceRange(range: CodespaceRange): void {
    this.codespaceRanges.push(range);
    this._maxCodeLength = Math.max(this._maxCodeLength, range.codeLength);
    this._minCodeLength = Math.min(this._minCodeLength, range.codeLength);
  }

  /**
   * Add a character code to Unicode mapping.
   */
  addCharMapping(codes: Uint8Array, unicode: string): void {
    const codeInt = bytesToInt(codes);

    switch (codes.length) {
      case 1:
        this.charToUnicodeOneByte.set(codeInt, unicode);
        break;
      case 2:
        this.charToUnicodeTwoBytes.set(codeInt, unicode);
        break;
      default:
        this.charToUnicodeMoreBytes.set(codeInt, unicode);
        break;
    }

    // Store reverse mapping
    this.unicodeToByteCodes.set(unicode, codes.slice());

    // Track space character
    if (unicode === " ") {
      this._spaceMapping = codeInt;
    }
  }

  /**
   * Add a CID mapping.
   */
  addCIDMapping(code: Uint8Array, cid: number): void {
    let codeToCidMap = this.codeToCid.get(code.length);

    if (!codeToCidMap) {
      codeToCidMap = new Map();

      this.codeToCid.set(code.length, codeToCidMap);

      this._minCidLength = Math.min(this._minCidLength, code.length);
      this._maxCidLength = Math.max(this._maxCidLength, code.length);
    }

    codeToCidMap.set(bytesToInt(code), cid);
  }

  /**
   * Add a CID range mapping.
   */
  addCIDRange(from: Uint8Array, to: Uint8Array, cid: number): void {
    const fromInt = bytesToInt(from);
    const toInt = bytesToInt(to);
    const length = from.length;

    // Try to extend the last range
    if (this.codeToCidRanges.length > 0) {
      const lastRange = this.codeToCidRanges[this.codeToCidRanges.length - 1];

      if (lastRange.extend(fromInt, toInt, cid, length)) {
        return;
      }
    }

    // Create new range
    this.codeToCidRanges.push(new CIDRange(fromInt, toInt, cid, length));

    this._minCidLength = Math.min(this._minCidLength, length);
    this._maxCidLength = Math.max(this._maxCidLength, length);
  }

  /**
   * Copy all mappings from another CMap (usecmap operator).
   */
  useCmap(cmap: CMap): void {
    // Copy codespace ranges
    for (const range of cmap.codespaceRanges) {
      this.addCodespaceRange(range);
    }

    // Copy Unicode mappings
    for (const [code, unicode] of cmap.charToUnicodeOneByte) {
      this.charToUnicodeOneByte.set(code, unicode);
      this.unicodeToByteCodes.set(unicode, new Uint8Array([code]));
    }

    for (const [code, unicode] of cmap.charToUnicodeTwoBytes) {
      this.charToUnicodeTwoBytes.set(code, unicode);
      this.unicodeToByteCodes.set(unicode, new Uint8Array([(code >>> 8) & 0xff, code & 0xff]));
    }

    for (const [code, unicode] of cmap.charToUnicodeMoreBytes) {
      this.charToUnicodeMoreBytes.set(code, unicode);
      // Convert code to bytes
      const bytes =
        code <= 0xffffff
          ? new Uint8Array([(code >>> 16) & 0xff, (code >>> 8) & 0xff, code & 0xff])
          : new Uint8Array([
              (code >>> 24) & 0xff,
              (code >>> 16) & 0xff,
              (code >>> 8) & 0xff,
              code & 0xff,
            ]);

      this.unicodeToByteCodes.set(unicode, bytes);
    }

    // Copy CID mappings
    for (const [length, srcMap] of cmap.codeToCid) {
      let dstMap = this.codeToCid.get(length);

      if (!dstMap) {
        dstMap = new Map();
        this.codeToCid.set(length, dstMap);
      }

      for (const [code, cid] of srcMap) {
        dstMap.set(code, cid);
      }
    }

    // Copy CID ranges
    this.codeToCidRanges.push(...cmap.codeToCidRanges);

    // Update bounds
    this._maxCodeLength = Math.max(this._maxCodeLength, cmap._maxCodeLength);
    this._minCodeLength = Math.min(this._minCodeLength, cmap._minCodeLength);
    this._maxCidLength = Math.max(this._maxCidLength, cmap._maxCidLength);
    this._minCidLength = Math.min(this._minCidLength, cmap._minCidLength);
  }

  // =========================================================================
  // Private helpers
  // =========================================================================

  private toCIDFromRanges(code: number, length: number): number {
    for (const range of this.codeToCidRanges) {
      const cid = range.map(code, length);

      if (cid !== -1) {
        return cid;
      }
    }

    return 0;
  }

  private toCIDFromRangesBytes(code: Uint8Array): number {
    for (const range of this.codeToCidRanges) {
      const cid = range.mapBytes(code);

      if (cid !== -1) {
        return cid;
      }
    }

    return 0;
  }

  toString(): string {
    return this._name ?? "CMap";
  }
}
