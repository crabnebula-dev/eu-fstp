/**
 * The 'OS/2' table - OS/2 and Windows Metrics Table.
 *
 * Contains metrics and font classification information.
 * Optional but recommended in TrueType fonts.
 *
 * Based on Apache PDFBox fontbox OS2WindowsMetricsTable.java
 * @see https://learn.microsoft.com/en-us/typography/opentype/spec/os2
 */

import type { TableParseContext, TTFTable } from "../types.ts";

// Weight class constants
export const WEIGHT_CLASS_THIN = 100;
export const WEIGHT_CLASS_EXTRA_LIGHT = 200;
export const WEIGHT_CLASS_LIGHT = 300;
export const WEIGHT_CLASS_NORMAL = 400;
export const WEIGHT_CLASS_MEDIUM = 500;
export const WEIGHT_CLASS_SEMI_BOLD = 600;
export const WEIGHT_CLASS_BOLD = 700;
export const WEIGHT_CLASS_EXTRA_BOLD = 800;
export const WEIGHT_CLASS_BLACK = 900;

// Width class constants
export const WIDTH_CLASS_ULTRA_CONDENSED = 1;
export const WIDTH_CLASS_EXTRA_CONDENSED = 2;
export const WIDTH_CLASS_CONDENSED = 3;
export const WIDTH_CLASS_SEMI_CONDENSED = 4;
export const WIDTH_CLASS_MEDIUM = 5;
export const WIDTH_CLASS_SEMI_EXPANDED = 6;
export const WIDTH_CLASS_EXPANDED = 7;
export const WIDTH_CLASS_EXTRA_EXPANDED = 8;
export const WIDTH_CLASS_ULTRA_EXPANDED = 9;

// Family class constants
export const FAMILY_CLASS_NO_CLASSIFICATION = 0;
export const FAMILY_CLASS_OLDSTYLE_SERIFS = 1;
export const FAMILY_CLASS_TRANSITIONAL_SERIFS = 2;
export const FAMILY_CLASS_MODERN_SERIFS = 3;
export const FAMILY_CLASS_CLAREDON_SERIFS = 4;
export const FAMILY_CLASS_SLAB_SERIFS = 5;
export const FAMILY_CLASS_FREEFORM_SERIFS = 7;
export const FAMILY_CLASS_SANS_SERIF = 8;
export const FAMILY_CLASS_ORNAMENTALS = 9;
export const FAMILY_CLASS_SCRIPTS = 10;
export const FAMILY_CLASS_SYMBOLIC = 12;

// fsType flags
/** Restricted License embedding */
export const FSTYPE_RESTRICTED = 0x0002;
/** Preview & Print embedding */
export const FSTYPE_PREVIEW_AND_PRINT = 0x0004;
/** Editable embedding */
export const FSTYPE_EDITABLE = 0x0008;
/** No subsetting allowed */
export const FSTYPE_NO_SUBSETTING = 0x0100;
/** Bitmap embedding only */
export const FSTYPE_BITMAP_ONLY = 0x0200;

// fsSelection flags
/** Font is italic */
export const FSSELECTION_ITALIC = 0x0001;
/** Font is bold */
export const FSSELECTION_BOLD = 0x0020;
/** Font is regular */
export const FSSELECTION_REGULAR = 0x0040;
/** Use typographic metrics */
export const FSSELECTION_USE_TYPO_METRICS = 0x0080;

/**
 * Parsed 'OS/2' table data.
 */
export interface OS2Table extends TTFTable {
  readonly tag: "OS/2";

  /** Table version (0-5) */
  readonly version: number;
  /** Average weighted width of lower case letters and space */
  readonly averageCharWidth: number;
  /** Weight class (100-900) */
  readonly weightClass: number;
  /** Width class (1-9) */
  readonly widthClass: number;
  /** Embedding permissions */
  readonly fsType: number;
  /** Subscript horizontal size */
  readonly subscriptXSize: number;
  /** Subscript vertical size */
  readonly subscriptYSize: number;
  /** Subscript horizontal offset */
  readonly subscriptXOffset: number;
  /** Subscript vertical offset */
  readonly subscriptYOffset: number;
  /** Superscript horizontal size */
  readonly superscriptXSize: number;
  /** Superscript vertical size */
  readonly superscriptYSize: number;
  /** Superscript horizontal offset */
  readonly superscriptXOffset: number;
  /** Superscript vertical offset */
  readonly superscriptYOffset: number;
  /** Strikeout line thickness */
  readonly strikeoutSize: number;
  /** Strikeout line position */
  readonly strikeoutPosition: number;
  /** Font family class and subclass (IBM) */
  readonly familyClass: number;
  /** PANOSE classification (10 bytes) */
  readonly panose: Uint8Array;
  /** Unicode range bits 0-31 */
  readonly unicodeRange1: number;
  /** Unicode range bits 32-63 */
  readonly unicodeRange2: number;
  /** Unicode range bits 64-95 */
  readonly unicodeRange3: number;
  /** Unicode range bits 96-127 */
  readonly unicodeRange4: number;
  /** Font vendor ID (4 chars) */
  readonly achVendId: string;
  /** Font selection flags */
  readonly fsSelection: number;
  /** Minimum Unicode code point */
  readonly firstCharIndex: number;
  /** Maximum Unicode code point */
  readonly lastCharIndex: number;
  /** Typographic ascender */
  readonly typoAscender: number;
  /** Typographic descender (negative) */
  readonly typoDescender: number;
  /** Typographic line gap */
  readonly typoLineGap: number;
  /** Windows ascender */
  readonly winAscent: number;
  /** Windows descender */
  readonly winDescent: number;
  /** Code page range bits 0-31 (version >= 1) */
  readonly codePageRange1?: number;
  /** Code page range bits 32-63 (version >= 1) */
  readonly codePageRange2?: number;
  /** x-height (version >= 2) */
  readonly sxHeight?: number;
  /** Cap height (version >= 2) */
  readonly sCapHeight?: number;
  /** Default character (version >= 2) */
  readonly usDefaultChar?: number;
  /** Break character (version >= 2) */
  readonly usBreakChar?: number;
  /** Max context length (version >= 2) */
  readonly usMaxContext?: number;
}

/**
 * Parse the 'OS/2' table.
 */
export function parseOS2Table(ctx: TableParseContext): OS2Table {
  const { data, record } = ctx;
  const tableEnd = record.length;

  const version = data.readUint16();
  const averageCharWidth = data.readInt16();
  const weightClass = data.readUint16();
  const widthClass = data.readUint16();
  const fsType = data.readInt16();
  const subscriptXSize = data.readInt16();
  const subscriptYSize = data.readInt16();
  const subscriptXOffset = data.readInt16();
  const subscriptYOffset = data.readInt16();
  const superscriptXSize = data.readInt16();
  const superscriptYSize = data.readInt16();
  const superscriptXOffset = data.readInt16();
  const superscriptYOffset = data.readInt16();
  const strikeoutSize = data.readInt16();
  const strikeoutPosition = data.readInt16();
  const familyClass = data.readInt16();

  // Read PANOSE (10 bytes)
  const panose = new Uint8Array(10);

  for (let i = 0; i < 10; i++) {
    panose[i] = data.readUint8();
  }

  const unicodeRange1 = data.readUint32();
  const unicodeRange2 = data.readUint32();
  const unicodeRange3 = data.readUint32();
  const unicodeRange4 = data.readUint32();

  // Read vendor ID (4 chars)
  const vendorBytes = new Uint8Array(4);

  for (let i = 0; i < 4; i++) {
    vendorBytes[i] = data.readUint8();
  }

  const achVendId = String.fromCharCode(...vendorBytes);

  const fsSelection = data.readUint16();
  const firstCharIndex = data.readUint16();
  const lastCharIndex = data.readUint16();

  // These fields may not be present in legacy fonts
  let typoAscender = 0;
  let typoDescender = 0;
  let typoLineGap = 0;
  let winAscent = 0;
  let winDescent = 0;

  const bytesRead = data.position;

  if (bytesRead + 10 <= tableEnd) {
    typoAscender = data.readInt16();
    typoDescender = data.readInt16();
    typoLineGap = data.readInt16();
    winAscent = data.readUint16();
    winDescent = data.readUint16();
  }

  // Version 1+ fields
  let codePageRange1: number | undefined;
  let codePageRange2: number | undefined;

  if (version >= 1 && data.position + 8 <= tableEnd) {
    codePageRange1 = data.readUint32();
    codePageRange2 = data.readUint32();
  }

  // Version 2+ fields
  let sxHeight: number | undefined;
  let sCapHeight: number | undefined;
  let usDefaultChar: number | undefined;
  let usBreakChar: number | undefined;
  let usMaxContext: number | undefined;

  if (version >= 2 && data.position + 10 <= tableEnd) {
    sxHeight = data.readInt16();
    sCapHeight = data.readInt16();
    usDefaultChar = data.readUint16();
    usBreakChar = data.readUint16();
    usMaxContext = data.readUint16();
  }

  return {
    tag: "OS/2",
    version,
    averageCharWidth,
    weightClass,
    widthClass,
    fsType,
    subscriptXSize,
    subscriptYSize,
    subscriptXOffset,
    subscriptYOffset,
    superscriptXSize,
    superscriptYSize,
    superscriptXOffset,
    superscriptYOffset,
    strikeoutSize,
    strikeoutPosition,
    familyClass,
    panose,
    unicodeRange1,
    unicodeRange2,
    unicodeRange3,
    unicodeRange4,
    achVendId,
    fsSelection,
    firstCharIndex,
    lastCharIndex,
    typoAscender,
    typoDescender,
    typoLineGap,
    winAscent,
    winDescent,
    codePageRange1,
    codePageRange2,
    sxHeight,
    sCapHeight,
    usDefaultChar,
    usBreakChar,
    usMaxContext,
  };
}
