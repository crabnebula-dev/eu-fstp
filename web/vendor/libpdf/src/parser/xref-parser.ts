import { CR, DIGIT_0, DIGIT_9, isWhitespace, LF, SPACE, TAB } from "../helpers/chars.js";
import type { Scanner } from "../io/scanner.js";
import type { PdfDict } from "../objects/pdf-dict.js";

import { RefusedError, XRefParseError } from "./errors.js";
import { checkLimit, LIMITS } from "./limits.js";
import { ObjectParser } from "./object-parser.js";
import { TokenReader } from "./token-reader.js";

/**
 * Entry in the cross-reference table.
 */
export type XRefEntry =
  | { type: "free"; nextFree: number; generation: number }
  | { type: "uncompressed"; offset: number; generation: number }
  | { type: "compressed"; streamObjNum: number; indexInStream: number };

/**
 * Parsed cross-reference data.
 */
export interface XRefData {
  entries: Map<number, XRefEntry>;
  trailer: PdfDict;
  prev?: number;
}

// ASCII codes for xref-specific parsing
const CHAR_f = 0x66;
const CHAR_n = 0x6e;

/**
 * Parser for PDF cross-reference tables and streams.
 *
 * Supports both traditional table format and stream format (PDF 1.5+).
 * Handles incremental updates via /Prev chain.
 */
export class XRefParser {
  constructor(private scanner: Scanner) {}

  /**
   * Find the startxref offset by scanning backwards from end of file.
   * Returns the byte offset where xref starts.
   */
  findStartXRef(): number {
    const bytes = this.scanner.bytes;
    const len = bytes.length;

    // Skip trailing whitespace/null bytes to find the effective end of file.
    // Some systems pad PDFs with null bytes to block boundaries, which can
    // push the actual %%EOF / startxref beyond the normal 1024-byte window.
    let effectiveEnd = len;

    while (effectiveEnd > 0 && isWhitespace(bytes[effectiveEnd - 1])) {
      effectiveEnd--;
    }

    // Search backwards from effective end, looking for "startxref"
    const searchStart = Math.max(0, effectiveEnd - 1024);

    let startxrefPos = -1;

    for (let i = effectiveEnd - 9; i >= searchStart; i--) {
      if (this.matchesAt(i, "startxref")) {
        startxrefPos = i;
        break;
      }
    }

    if (startxrefPos === -1) {
      throw new XRefParseError("Could not find startxref marker");
    }

    // Skip "startxref" and whitespace to get the offset number
    let pos = startxrefPos + 9;
    pos = this.skipWhitespace(pos);

    // FSTP (ADR-016): strict tail. One to ten digits, whitespace, "%%EOF",
    // then nothing but spaces, tabs and line ends to the end of the file.
    let end = pos;

    while (end < len && bytes[end] >= DIGIT_0 && bytes[end] <= DIGIT_9) {
      end++;
    }

    if (end === pos || end - pos > 10) {
      throw new XRefParseError("Invalid startxref offset");
    }

    const offset = this.readIntegerAt(pos);

    if (offset === null) {
      throw new XRefParseError("Invalid startxref offset");
    }

    let tail = this.skipWhitespace(end);

    if (tail === end || !this.matchesAt(tail, "%%EOF")) {
      throw new XRefParseError("startxref is not followed by %%EOF");
    }

    tail += 5;

    tail = this.skipWhitespace(tail);

    if (tail !== len) {
      throw new XRefParseError("Bytes follow %%EOF");
    }

    return offset;
  }

  /**
   * Parse xref at given byte offset.
   * Auto-detects table vs stream format.
   */
  parseAt(offset: number): XRefData {
    this.scanner.moveTo(offset);

    // Peek to detect format
    const firstByte = this.scanner.peek();

    // 'x' = 0x78 starts "xref"
    if (firstByte === 0x78) {
      return this.parseTable();
    }

    // Digit starts "N M obj" (stream format)
    // FSTP (ADR-016): xref streams are refused; the server writes tables.
    if (firstByte >= DIGIT_0 && firstByte <= DIGIT_9) {
      throw new RefusedError("xref-stream", `an xref stream at offset ${offset}`);
    }

    throw new XRefParseError(`Unknown xref format at offset ${offset}`);
  }

  /**
   * Detect the XRef format at a given offset without fully parsing.
   *
   * @returns true if XRef stream, false if table, null if cannot detect
   */
  detectXRefFormat(offset: number): boolean | null {
    this.scanner.moveTo(offset);

    const firstByte = this.scanner.peek();

    // 'x' = 0x78 starts "xref" (table format)
    if (firstByte === 0x78) {
      return false;
    }

    // Digit starts "N M obj" (stream format)
    if (firstByte >= DIGIT_0 && firstByte <= DIGIT_9) {
      return true;
    }

    return null;
  }

  /**
   * Parse traditional xref table format.
   * Scanner must be positioned at "xref" keyword.
   */
  parseTable(): XRefData {
    const entries = new Map<number, XRefEntry>();

    // Consume "xref" keyword
    this.expectKeyword("xref");
    this.skipWhitespaceFromCurrent();

    // Read subsections until we hit "trailer"
    // Skip whitespace before each check (some PDFs have extra newlines between entries and trailer)
    while (true) {
      this.skipWhitespaceFromCurrent();

      if (this.peekKeyword("trailer")) {
        break;
      }

      this.parseSubsection(entries);
    }

    // Consume "trailer" keyword
    this.expectKeyword("trailer");
    this.skipWhitespaceFromCurrent();

    // Parse trailer dictionary
    const reader = new TokenReader(this.scanner);
    const parser = new ObjectParser(reader);
    const result = parser.parseObject();

    if (result === null || result.object.type !== "dict") {
      throw new XRefParseError("Invalid trailer dictionary");
    }

    const trailer = result.object;

    // Extract /Prev if present
    const prevNum = trailer.getNumber("Prev");
    const prev = prevNum?.value;

    return {
      entries,
      trailer,
      prev,
    };
  }

  /**
   * Parse a single subsection of the xref table.
   */
  private parseSubsection(entries: Map<number, XRefEntry>): void {
    // Read first object number and count
    const firstObjNum = this.readIntegerFromCurrent();

    if (firstObjNum === null) {
      throw new XRefParseError("Expected subsection start object number");
    }

    this.skipWhitespaceFromCurrent();

    const count = this.readIntegerFromCurrent();

    if (count === null) {
      throw new XRefParseError("Expected subsection entry count");
    }

    this.skipWhitespaceFromCurrent();

    // FSTP (ADR-016): object numbers stay below the hard object limit.
    checkLimit("an xref subsection ending at object", firstObjNum + count, LIMITS.maxObjects);

    // Read entries
    const parsedEntries: XRefEntry[] = [];

    for (let i = 0; i < count; i++) {
      parsedEntries.push(this.parseEntry());
    }

    // FSTP (ADR-016): strict parse. No off-by-one correction, and an
    // object number given twice in one section is refused.
    for (let i = 0; i < parsedEntries.length; i++) {
      if (entries.has(firstObjNum + i)) {
        throw new XRefParseError(`Object ${firstObjNum + i} appears twice in one xref section`);
      }

      entries.set(firstObjNum + i, parsedEntries[i]);
    }
  }

  /**
   * Parse a single xref entry.
   * Format: OOOOOOOOOO GGGGG T (10-digit offset, 5-digit gen, type)
   */
  private parseEntry(): XRefEntry {
    // Read 10-digit offset
    const offset = this.readFixedDigits(10);
    this.skipSpaces();

    // Read 5-digit generation
    const generation = this.readFixedDigits(5);
    this.skipSpaces();

    // Read type: 'n' or 'f'
    const typeByte = this.scanner.advance();

    // Skip to end of entry (EOL)
    this.skipToEOL();
    this.skipEOL();

    if (typeByte === CHAR_n) {
      return {
        type: "uncompressed",
        offset,
        generation,
      };
    } else if (typeByte === CHAR_f) {
      return {
        type: "free",
        nextFree: offset, // For free entries, offset field is next free object
        generation,
      };
    } else {
      throw new XRefParseError(`Invalid xref entry type: ${String.fromCharCode(typeByte)}`);
    }
  }

  /**
   * Read a fixed number of digits as an integer.
   */
  private readFixedDigits(count: number): number {
    let value = 0;

    for (let i = 0; i < count; i++) {
      const byte = this.scanner.peek();

      if (byte < DIGIT_0 || byte > DIGIT_9) {
        throw new XRefParseError(`Expected digit, got ${String.fromCharCode(byte)}`);
      }

      value = value * 10 + (byte - DIGIT_0);
      this.scanner.advance();
    }

    return value;
  }

  /**
   * Skip space characters (not newlines).
   */
  private skipSpaces(): void {
    while (this.scanner.peek() === SPACE) {
      this.scanner.advance();
    }
  }

  /**
   * Skip to the end of line (but don't consume EOL).
   */
  private skipToEOL(): void {
    while (true) {
      const byte = this.scanner.peek();

      if (byte === -1 || byte === LF || byte === CR) {
        break;
      }

      this.scanner.advance();
    }
  }

  /**
   * Skip EOL characters (CR, LF, or CRLF).
   */
  private skipEOL(): void {
    const byte = this.scanner.peek();

    if (byte === CR) {
      this.scanner.advance();

      if (this.scanner.peek() === LF) {
        this.scanner.advance();
      }
    } else if (byte === LF) {
      this.scanner.advance();
    }
  }

  /**
   * Skip whitespace from current scanner position.
   */
  private skipWhitespaceFromCurrent(): void {
    while (true) {
      const byte = this.scanner.peek();

      if (byte === -1) {
        break;
      }

      if (byte === SPACE || byte === LF || byte === CR || byte === TAB) {
        this.scanner.advance();
      } else {
        break;
      }
    }
  }

  /**
   * Check if bytes at position match a string.
   */
  private matchesAt(pos: number, str: string): boolean {
    const bytes = this.scanner.bytes;

    for (let i = 0; i < str.length; i++) {
      if (pos + i >= bytes.length || bytes[pos + i] !== str.charCodeAt(i)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Skip whitespace at given position, return new position.
   */
  private skipWhitespace(pos: number): number {
    const bytes = this.scanner.bytes;

    while (pos < bytes.length) {
      const byte = bytes[pos];

      if (byte === SPACE || byte === LF || byte === CR || byte === TAB) {
        pos++;
      } else {
        break;
      }
    }

    return pos;
  }

  /**
   * Read an integer at given position.
   */
  private readIntegerAt(pos: number): number | null {
    const bytes = this.scanner.bytes;
    let value = 0;
    let hasDigits = false;

    while (pos < bytes.length) {
      const byte = bytes[pos];

      if (byte >= DIGIT_0 && byte <= DIGIT_9) {
        value = value * 10 + (byte - DIGIT_0);
        hasDigits = true;
        pos++;
      } else {
        break;
      }
    }

    return hasDigits ? value : null;
  }

  /**
   * Read an integer from current scanner position.
   */
  private readIntegerFromCurrent(): number | null {
    let value = 0;
    let hasDigits = false;

    while (true) {
      const byte = this.scanner.peek();

      if (byte >= DIGIT_0 && byte <= DIGIT_9) {
        value = value * 10 + (byte - DIGIT_0);
        hasDigits = true;
        this.scanner.advance();
      } else {
        break;
      }
    }

    return hasDigits ? value : null;
  }

  /**
   * Expect and consume a keyword at current position.
   */
  private expectKeyword(keyword: string): void {
    for (let i = 0; i < keyword.length; i++) {
      const byte = this.scanner.peek();

      if (byte !== keyword.charCodeAt(i)) {
        throw new XRefParseError(`Expected keyword "${keyword}"`);
      }

      this.scanner.advance();
    }
  }

  /**
   * Check if current position starts with a keyword (without consuming).
   */
  private peekKeyword(keyword: string): boolean {
    const startPos = this.scanner.position;

    for (let i = 0; i < keyword.length; i++) {
      if (this.scanner.peekAt(startPos + i) !== keyword.charCodeAt(i)) {
        return false;
      }
    }

    return true;
  }
}
