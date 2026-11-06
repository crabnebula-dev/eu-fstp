/**
 * TTF/OTF type definitions.
 *
 * Based on Apache PDFBox fontbox TTFTable and related classes.
 */

import type { BinaryScanner } from "#src/io/binary-scanner.ts";

/**
 * Table record from the font's offset table (table directory).
 * This is the metadata about where a table lives in the file.
 */
export interface TableRecord {
  /** 4-byte table tag (e.g., "head", "cmap") */
  readonly tag: string;
  /** Checksum for the table */
  readonly checksum: number;
  /** Offset from beginning of font file */
  readonly offset: number;
  /** Length of the table in bytes */
  readonly length: number;
}

/**
 * Known table tags as constants.
 */
export const TableTag = {
  HEAD: "head",
  HHEA: "hhea",
  HMTX: "hmtx",
  MAXP: "maxp",
  LOCA: "loca",
  GLYF: "glyf",
  CMAP: "cmap",
  NAME: "name",
  POST: "post",
  OS2: "OS/2",
  KERN: "kern",
  VHEA: "vhea",
  VMTX: "vmtx",
  VORG: "VORG",
  CFF: "CFF ",
  CFF2: "CFF2",
  GSUB: "GSUB",
  GPOS: "GPOS",
  GDEF: "GDEF",
  DSIG: "DSIG",
  // Variable font tables
  FVAR: "fvar",
  AVAR: "avar",
  GVAR: "gvar",
  STAT: "STAT",
  HVAR: "HVAR",
  VVAR: "VVAR",
  MVAR: "MVAR",
} as const;

export type TableTagValue = (typeof TableTag)[keyof typeof TableTag];

/**
 * Interface that all parsed tables implement.
 */
export interface TTFTable {
  /** The table tag */
  readonly tag: string;
}

/**
 * Context passed to table parsers, providing access to the font and data.
 */
export interface TableParseContext {
  /** Scanner positioned at the start of the table data */
  readonly data: BinaryScanner;
  /** The font being parsed (for accessing other tables) */
  readonly font: TrueTypeFontAccess;
  /** The table record for this table */
  readonly record: TableRecord;
}

/**
 * Interface for accessing font data during table parsing.
 * Tables may need to reference other tables (e.g., hmtx needs hhea and maxp).
 */
export interface TrueTypeFontAccess {
  /** Get a table by tag. May trigger lazy parsing. */
  getTable<T extends TTFTable>(tag: string): T | undefined;
  /** Get a raw table record by tag */
  getTableRecord(tag: string): TableRecord | undefined;
  /** Get the raw font data */
  readonly data: BinaryScanner;
  /** Number of glyphs in the font */
  readonly numGlyphs: number;
}

/**
 * Function type for table parsers.
 */
export type TableParser<T extends TTFTable> = (ctx: TableParseContext) => T;
