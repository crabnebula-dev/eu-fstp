/**
 * The 'head' table - Font Header Table.
 *
 * This table contains global information about the font.
 * Required in all TrueType fonts.
 *
 * Based on Apache PDFBox fontbox HeaderTable.java
 * @see https://learn.microsoft.com/en-us/typography/opentype/spec/head
 */

import type { TableParseContext, TTFTable } from "../types.ts";

/** Bold macStyle flag */
export const MAC_STYLE_BOLD = 1;
/** Italic macStyle flag */
export const MAC_STYLE_ITALIC = 2;

/**
 * Parsed 'head' table data.
 */
export interface HeadTable extends TTFTable {
  readonly tag: "head";

  /** Table version (typically 1.0) */
  readonly version: number;
  /** Font revision set by manufacturer */
  readonly fontRevision: number;
  /** Checksum adjustment for entire font */
  readonly checkSumAdjustment: number;
  /** Magic number (should be 0x5F0F3CF5) */
  readonly magicNumber: number;
  /** Font flags */
  readonly flags: number;
  /** Units per em (typically 1000-2048) */
  readonly unitsPerEm: number;
  /** Created date */
  readonly created: Date;
  /** Modified date */
  readonly modified: Date;
  /** Minimum x coordinate across all glyphs */
  readonly xMin: number;
  /** Minimum y coordinate across all glyphs */
  readonly yMin: number;
  /** Maximum x coordinate across all glyphs */
  readonly xMax: number;
  /** Maximum y coordinate across all glyphs */
  readonly yMax: number;
  /** Mac style flags (bold, italic, etc.) */
  readonly macStyle: number;
  /** Smallest readable size in pixels */
  readonly lowestRecPPEM: number;
  /** Font direction hint (deprecated, should be 2) */
  readonly fontDirectionHint: number;
  /** Index to location format: 0 = short offsets, 1 = long offsets */
  readonly indexToLocFormat: number;
  /** Glyph data format (should be 0) */
  readonly glyphDataFormat: number;
}

/**
 * Parse the 'head' table.
 */
export function parseHeadTable(ctx: TableParseContext): HeadTable {
  const { data } = ctx;

  const version = data.readFixed();
  const fontRevision = data.readFixed();
  const checkSumAdjustment = data.readUint32();
  const magicNumber = data.readUint32();
  const flags = data.readUint16();
  const unitsPerEm = data.readUint16();
  const created = data.readLongDateTime();
  const modified = data.readLongDateTime();
  const xMin = data.readInt16();
  const yMin = data.readInt16();
  const xMax = data.readInt16();
  const yMax = data.readInt16();
  const macStyle = data.readUint16();
  const lowestRecPPEM = data.readUint16();
  const fontDirectionHint = data.readInt16();
  const indexToLocFormat = data.readInt16();
  const glyphDataFormat = data.readInt16();

  return {
    tag: "head",
    version,
    fontRevision,
    checkSumAdjustment,
    magicNumber,
    flags,
    unitsPerEm,
    created,
    modified,
    xMin,
    yMin,
    xMax,
    yMax,
    macStyle,
    lowestRecPPEM,
    fontDirectionHint,
    indexToLocFormat,
    glyphDataFormat,
  };
}
