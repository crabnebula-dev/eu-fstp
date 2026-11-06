/**
 * The 'maxp' table - Maximum Profile Table.
 *
 * Contains the number of glyphs and memory requirements.
 * Required in all TrueType fonts.
 *
 * Based on Apache PDFBox fontbox MaximumProfileTable.java
 * @see https://learn.microsoft.com/en-us/typography/opentype/spec/maxp
 */

import type { TableParseContext, TTFTable } from "../types.ts";

/**
 * Parsed 'maxp' table data.
 */
export interface MaxpTable extends TTFTable {
  readonly tag: "maxp";

  /** Table version (0.5 for CFF, 1.0 for TrueType) */
  readonly version: number;
  /** Number of glyphs in the font */
  readonly numGlyphs: number;
  /** Maximum points in a non-composite glyph (version 1.0 only) */
  readonly maxPoints?: number;
  /** Maximum contours in a non-composite glyph (version 1.0 only) */
  readonly maxContours?: number;
  /** Maximum points in a composite glyph (version 1.0 only) */
  readonly maxCompositePoints?: number;
  /** Maximum contours in a composite glyph (version 1.0 only) */
  readonly maxCompositeContours?: number;
  /** Maximum zones (version 1.0 only) */
  readonly maxZones?: number;
  /** Maximum twilight points (version 1.0 only) */
  readonly maxTwilightPoints?: number;
  /** Maximum storage area locations (version 1.0 only) */
  readonly maxStorage?: number;
  /** Maximum function definitions (version 1.0 only) */
  readonly maxFunctionDefs?: number;
  /** Maximum instruction definitions (version 1.0 only) */
  readonly maxInstructionDefs?: number;
  /** Maximum stack depth (version 1.0 only) */
  readonly maxStackElements?: number;
  /** Maximum byte count for glyph instructions (version 1.0 only) */
  readonly maxSizeOfInstructions?: number;
  /** Maximum number of components (version 1.0 only) */
  readonly maxComponentElements?: number;
  /** Maximum levels of recursion (version 1.0 only) */
  readonly maxComponentDepth?: number;
}

/**
 * Parse the 'maxp' table.
 */
export function parseMaxpTable(ctx: TableParseContext): MaxpTable {
  const { data } = ctx;

  const version = data.readFixed();
  const numGlyphs = data.readUint16();

  // Version 0.5 (CFF fonts) only has version and numGlyphs
  if (version < 1.0) {
    return {
      tag: "maxp",
      version,
      numGlyphs,
    };
  }

  // Version 1.0 has additional TrueType-specific fields
  const maxPoints = data.readUint16();
  const maxContours = data.readUint16();
  const maxCompositePoints = data.readUint16();
  const maxCompositeContours = data.readUint16();
  const maxZones = data.readUint16();
  const maxTwilightPoints = data.readUint16();
  const maxStorage = data.readUint16();
  const maxFunctionDefs = data.readUint16();
  const maxInstructionDefs = data.readUint16();
  const maxStackElements = data.readUint16();
  const maxSizeOfInstructions = data.readUint16();
  const maxComponentElements = data.readUint16();
  let maxComponentDepth = data.readUint16();

  // PDFBOX-6105: ensure maxComponentDepth is at least 1
  if (maxComponentDepth === 0) {
    maxComponentDepth = 1;
  }

  return {
    tag: "maxp",
    version,
    numGlyphs,
    maxPoints,
    maxContours,
    maxCompositePoints,
    maxCompositeContours,
    maxZones,
    maxTwilightPoints,
    maxStorage,
    maxFunctionDefs,
    maxInstructionDefs,
    maxStackElements,
    maxSizeOfInstructions,
    maxComponentElements,
    maxComponentDepth,
  };
}
