import { CR, isWhitespace, LF } from "../helpers/chars.js";
import type { Scanner } from "../io/scanner.js";
import type { PdfDict } from "../objects/pdf-dict.js";
import type { PdfObject } from "../objects/pdf-object.js";
import type { PdfRef } from "../objects/pdf-ref.js";
import { PdfStream } from "../objects/pdf-stream.js";

import { ObjectParseError } from "./errors.js";
import { ObjectParser, type WarningCallback } from "./object-parser.js";
import { TokenReader } from "./token-reader.js";

/**
 * Parsed indirect object.
 */
export interface IndirectObject {
  objNum: number;
  genNum: number;
  value: PdfObject;
}

/**
 * Callback to resolve indirect /Length references.
 * Returns the length value, or null if not resolvable.
 */
export type LengthResolver = (ref: PdfRef) => number | null;

/**
 * Options for IndirectObjectParser.
 */
export interface IndirectObjectParserOptions {
  /**
   * Enable recovery mode for lenient parsing of object contents.
   * Malformed dicts/arrays produce partial results instead of throwing.
   */
  recoveryMode?: boolean;

  /** Callback for warnings emitted during lenient parsing. */
  onWarning?: WarningCallback;
}

/**
 * Parser for indirect object definitions.
 *
 * Handles the `N M obj ... endobj` syntax and stream binary data.
 * Uses ObjectParser for the actual object content.
 */
export class IndirectObjectParser {
  constructor(
    private scanner: Scanner,
    private lengthResolver?: LengthResolver,
    private options: IndirectObjectParserOptions = {},
  ) {}

  private warn(message: string, position: number): void {
    this.options.onWarning?.(message, position);
  }

  /**
   * Parse indirect object at current scanner position.
   */
  parseObject(): IndirectObject {
    const reader = new TokenReader(this.scanner);

    // Read object number
    const objNumToken = reader.nextToken();

    if (objNumToken.type !== "number" || !objNumToken.isInteger) {
      throw new ObjectParseError("Expected integer object number");
    }

    const objNum = objNumToken.value;

    // Read generation number
    const genNumToken = reader.nextToken();

    if (genNumToken.type !== "number" || !genNumToken.isInteger) {
      throw new ObjectParseError("Expected integer generation number");
    }

    const genNum = genNumToken.value;

    // Read "obj" keyword
    const objKeyword = reader.nextToken();

    if (objKeyword.type !== "keyword" || objKeyword.value !== "obj") {
      throw new ObjectParseError(`Expected 'obj' keyword, got ${objKeyword.type}`);
    }

    // Parse the object value
    const objectParser = new ObjectParser(reader);

    objectParser.recoveryMode = this.options.recoveryMode ?? false;
    objectParser.onWarning = this.options.onWarning ?? null;

    const result = objectParser.parseObject();

    if (result === null) {
      throw new ObjectParseError("Expected object value");
    }

    let value: PdfObject;

    if (result.hasStream) {
      // It's a stream object - read the stream data
      // Position scanner right after "stream" keyword
      this.scanner.moveTo(result.streamKeywordPosition + 6); // 6 = length of "stream"

      // After this, scanner position is right after "endstream"
      value = this.readStream(result.object);

      // Consume "endobj" directly from scanner (reader state is out of sync)
      // FSTP (ADR-016): strict parse, a missing endobj is refused.
      this.expectKeyword("endobj");
    } else {
      value = result.object;

      // Consume "endobj" keyword via reader
      // FSTP (ADR-016): the object parser has already read it into its
      // lookahead buffer, so it is taken from there.
      const endObjToken = objectParser.peekBuffered();
      if (endObjToken === null || endObjToken.type !== "keyword" || endObjToken.value !== "endobj") {
        // FSTP (ADR-016): strict parse, a missing endobj is refused.
        throw new ObjectParseError("Expected 'endobj' keyword");
      }
    }

    return {
      objNum,
      genNum,
      value,
    };
  }

  /**
   * Parse indirect object at given byte offset.
   */
  parseObjectAt(offset: number): IndirectObject {
    this.scanner.moveTo(offset);

    return this.parseObject();
  }

  /**
   * Read stream data after the dict has been parsed.
   * The "stream" keyword has been detected by ObjectParser's lookahead,
   * and the scanner is positioned right after "stream".
   */
  private readStream(dict: PdfDict): PdfStream {
    // The scanner is positioned right after "stream" keyword
    // (ObjectParser consumed it during lookahead but didn't use it)

    // Skip EOL after "stream" (required: LF or CRLF)
    this.skipStreamEOL();

    const startPos = this.scanner.position;

    // FSTP (ADR-016): strict parse. /Length is a direct integer and the
    // "endstream" keyword follows the data; nothing scans for it.
    const length = this.resolveLength(dict);

    if (!Number.isSafeInteger(length) || length < 0 || !this.isEndstreamAt(startPos + length)) {
      throw new ObjectParseError(`Stream /Length ${length} does not point at endstream`);
    }

    // Read exactly `length` bytes.
    // Use subarray (zero-copy view) since the underlying PDF bytes
    // are kept alive by the PDF object for the document's lifetime.
    const data = this.scanner.bytes.subarray(startPos, startPos + length);

    this.scanner.moveTo(startPos + length);

    // Skip optional EOL before "endstream"
    this.skipOptionalEOL();

    // Consume "endstream" keyword directly from scanner
    this.expectKeyword("endstream");

    return new PdfStream(dict, data);
  }

  /**
   * Check whether the "endstream" keyword appears at the given position,
   * allowing optional whitespace before it.
   */
  private isEndstreamAt(pos: number): boolean {
    const bytes = this.scanner.bytes;

    if (pos > bytes.length) {
      return false;
    }

    let i = pos;

    while (i < bytes.length && isWhitespace(bytes[i])) {
      i++;
    }

    const keyword = "endstream";

    if (i + keyword.length > bytes.length) {
      return false;
    }

    for (let j = 0; j < keyword.length; j++) {
      if (bytes[i + j] !== keyword.charCodeAt(j)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Expect and consume a keyword at current scanner position.
   */
  private expectKeyword(keyword: string): void {
    // Skip any whitespace first
    this.skipWhitespace();

    for (let i = 0; i < keyword.length; i++) {
      const byte = this.scanner.peek();

      if (byte !== keyword.charCodeAt(i)) {
        throw new ObjectParseError(`Expected keyword "${keyword}"`);
      }

      this.scanner.advance();
    }
  }

  /**
   * Skip whitespace characters.
   */
  private skipWhitespace(): void {
    while (true) {
      const byte = this.scanner.peek();

      if (byte === -1) {
        break;
      }
      if (isWhitespace(byte)) {
        this.scanner.advance();
      } else {
        break;
      }
    }
  }

  /**
   * Skip the EOL after "stream" keyword.
   * Per PDF spec: single EOL (LF or CRLF) after "stream"
   */
  private skipStreamEOL(): void {
    const byte = this.scanner.peek();

    if (byte === CR) {
      this.scanner.advance();
      // CRLF
      if (this.scanner.peek() === LF) {
        this.scanner.advance();
      }
    } else if (byte === LF) {
      this.scanner.advance();
    }
    // If no EOL, be lenient and continue anyway
  }

  /**
   * Skip optional EOL before "endstream".
   */
  private skipOptionalEOL(): void {
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
   * Resolve the /Length value from the stream dict.
   * FSTP (ADR-016): direct values only.
   */
  private resolveLength(dict: PdfDict): number {
    const lengthObj = dict.get("Length");

    if (lengthObj === undefined) {
      throw new ObjectParseError("Stream missing required /Length entry");
    }

    // Direct number
    if (lengthObj.type === "number") {
      return lengthObj.value;
    }

    // FSTP (ADR-016): an indirect /Length is refused. The server writes
    // direct lengths, and resolving one could re-enter this parser.
    if (lengthObj.type === "ref") {
      throw new ObjectParseError("Indirect stream /Length is refused");
    }

    throw new ObjectParseError(`Invalid /Length type: ${lengthObj.type}`);
  }
}
