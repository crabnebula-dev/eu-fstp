/**
 * Parser for PFB (Printer Font Binary) files.
 *
 * PFB is a binary wrapper format for Type 1 fonts. It consists of:
 * - Header (6 bytes per segment): start marker, type, size (4 bytes little-endian)
 * - Segment data
 *
 * Segment types:
 * - 0x01: ASCII text
 * - 0x02: Binary data
 * - 0x03: EOF marker
 *
 * @see "Adobe Type 1 Font Format, Adobe Systems (1999)"
 */

import type { Type1Font } from "./font.ts";
import { parseType1 } from "./parser.ts";

/** Start marker byte for PFB segments */
const START_MARKER = 0x80;

/** ASCII segment type */
const ASCII_MARKER = 0x01;

/** Binary segment type */
const BINARY_MARKER = 0x02;

/** End of file marker */
const EOF_MARKER = 0x03;

/** Minimum PFB header length (3 segments * 6 bytes each) */
const PFB_HEADER_LENGTH = 18;

/**
 * Parse a PFB file and return a Type1Font.
 * @param bytes PFB file bytes
 * @returns Parsed Type1Font
 */
export function parsePfb(bytes: Uint8Array): Type1Font {
  const parser = new PfbParser(bytes);
  return parseType1(parser.segment1, parser.segment2);
}

/**
 * Parsed PFB segments.
 */
export interface PfbSegments {
  /** ASCII segment (segment 1) */
  segment1: Uint8Array;
  /** Binary segment (segment 2) */
  segment2: Uint8Array;
  /** Segment lengths [ascii, binary, trailer] */
  lengths: [number, number, number];
}

/**
 * Parser for PFB (Printer Font Binary) format.
 */
export class PfbParser {
  private readonly _pfbdata: Uint8Array;
  private readonly _lengths: [number, number, number] = [0, 0, 0];

  /**
   * Create a new PFB parser.
   * @param bytes PFB file bytes
   */
  constructor(bytes: Uint8Array) {
    if (bytes.length < PFB_HEADER_LENGTH) {
      throw new Error("PFB header missing");
    }

    // Parse segments
    const segments = this.parseSegments(bytes);

    // Arrange segments: ASCII first, then binary, then cleartomark trailer
    const result = this.arrangeSegments(segments);
    this._pfbdata = result.data;
    this._lengths = result.lengths;
  }

  /**
   * Parse all segments from PFB data.
   */
  private parseSegments(bytes: Uint8Array): Array<{ type: number; data: Uint8Array }> {
    const segments: Array<{ type: number; data: Uint8Array }> = [];
    let position = 0;

    while (position < bytes.length) {
      // Read start marker
      if (bytes[position] !== START_MARKER) {
        if (segments.length > 0) {
          // EOF without marker
          break;
        }
        throw new Error("Start marker missing");
      }
      position++;

      // Read record type
      const recordType = bytes[position++];
      if (recordType === EOF_MARKER) {
        break;
      }
      if (recordType !== ASCII_MARKER && recordType !== BINARY_MARKER) {
        throw new Error(`Incorrect record type: ${recordType}`);
      }

      // Read size (little-endian 4 bytes)
      const size =
        bytes[position] |
        (bytes[position + 1] << 8) |
        (bytes[position + 2] << 16) |
        (bytes[position + 3] << 24);
      position += 4;

      if (size > bytes.length) {
        throw new Error(`Record size ${size} would be larger than the input`);
      }

      // Read segment data
      if (position + size > bytes.length) {
        throw new Error("EOF while reading PFB font");
      }

      segments.push({
        type: recordType,
        data: bytes.slice(position, position + size),
      });
      position += size;
    }

    return segments;
  }

  /**
   * Arrange segments into ASCII-first, binary, trailer order.
   */
  private arrangeSegments(segments: Array<{ type: number; data: Uint8Array }>): {
    data: Uint8Array;
    lengths: [number, number, number];
  } {
    // Calculate total size
    let total = 0;
    for (const seg of segments) {
      total += seg.data.length;
    }

    if (total > segments.reduce((sum, s) => sum + s.data.length, 0)) {
      throw new Error(`Total record size ${total} would be larger than the input`);
    }

    const pfbdata = new Uint8Array(total);
    let cleartomarkSegment: Uint8Array | null = null;
    let dstPos = 0;

    // Copy the ASCII segments
    for (let i = 0; i < segments.length; i++) {
      const seg = segments[i];
      if (seg.type !== ASCII_MARKER) {
        continue;
      }

      // Check if this is the cleartomark trailer
      if (
        i === segments.length - 1 &&
        seg.data.length < 600 &&
        this.containsCleartomark(seg.data)
      ) {
        cleartomarkSegment = seg.data;
        continue;
      }

      pfbdata.set(seg.data, dstPos);
      dstPos += seg.data.length;
    }
    const asciiLength = dstPos;

    // Copy the binary segments
    for (const seg of segments) {
      if (seg.type !== BINARY_MARKER) {
        continue;
      }
      pfbdata.set(seg.data, dstPos);
      dstPos += seg.data.length;
    }
    const binaryLength = dstPos - asciiLength;

    // Copy cleartomark segment if present
    let trailerLength = 0;
    if (cleartomarkSegment !== null) {
      pfbdata.set(cleartomarkSegment, dstPos);
      trailerLength = cleartomarkSegment.length;
    }

    return {
      data: pfbdata,
      lengths: [asciiLength, binaryLength, trailerLength],
    };
  }

  /**
   * Check if data contains "cleartomark" text.
   */
  private containsCleartomark(data: Uint8Array): boolean {
    // Search for "cleartomark" in the ASCII data
    const needle = [0x63, 0x6c, 0x65, 0x61, 0x72, 0x74, 0x6f, 0x6d, 0x61, 0x72, 0x6b]; // "cleartomark"
    outer: for (let i = 0; i <= data.length - needle.length; i++) {
      for (let j = 0; j < needle.length; j++) {
        if (data[i + j] !== needle[j]) {
          continue outer;
        }
      }
      return true;
    }
    return false;
  }

  /** Get segment lengths [ascii, binary, trailer]. */
  get lengths(): [number, number, number] {
    return this._lengths;
  }

  /** Get the complete PFB data (all segments combined). */
  get pfbdata(): Uint8Array {
    return this._pfbdata;
  }

  /** Get the size of the pfb data. */
  get size(): number {
    return this._pfbdata.length;
  }

  /** Get the first segment (ASCII). */
  get segment1(): Uint8Array {
    return this._pfbdata.slice(0, this._lengths[0]);
  }

  /** Get the second segment (binary). */
  get segment2(): Uint8Array {
    return this._pfbdata.slice(this._lengths[0], this._lengths[0] + this._lengths[1]);
  }
}
