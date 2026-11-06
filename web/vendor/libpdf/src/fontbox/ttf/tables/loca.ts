/**
 * The 'loca' table - Index to Location Table.
 *
 * Maps glyph IDs to byte offsets within the 'glyf' table.
 * Required in TrueType fonts (not CFF).
 *
 * Based on Apache PDFBox fontbox IndexToLocationTable.java
 * @see https://learn.microsoft.com/en-us/typography/opentype/spec/loca
 */

import type { TableParseContext, TTFTable } from "../types.ts";
import type { HeadTable } from "./head.ts";

/** Short offset format (offsets are uint16, multiplied by 2) */
const SHORT_OFFSETS = 0;
/** Long offset format (offsets are uint32) */
const LONG_OFFSETS = 1;

/**
 * Parsed 'loca' table data.
 */
export interface LocaTable extends TTFTable {
  readonly tag: "loca";

  /**
   * Byte offsets into the glyf table.
   * Length is numGlyphs + 1 (extra entry to compute last glyph's length).
   */
  readonly offsets: Uint32Array;

  /**
   * Get the byte offset for a glyph in the glyf table.
   */
  getOffset(glyphId: number): number;

  /**
   * Get the byte length of a glyph's data.
   */
  getLength(glyphId: number): number;
}

/**
 * Parse the 'loca' table.
 */
export function parseLocaTable(ctx: TableParseContext): LocaTable {
  const { data, font } = ctx;

  // Need head to know the offset format
  const head = font.getTable<HeadTable>("head");

  if (!head) {
    throw new Error("Cannot parse loca without head table");
  }

  const numGlyphs = font.numGlyphs;
  const format = head.indexToLocFormat;

  // loca has numGlyphs + 1 entries
  const offsets = new Uint32Array(numGlyphs + 1);

  for (let i = 0; i <= numGlyphs; i++) {
    if (format === SHORT_OFFSETS) {
      // Short format: offset is uint16, actual offset is value * 2
      offsets[i] = data.readUint16() * 2;
    } else if (format === LONG_OFFSETS) {
      // Long format: offset is uint32
      offsets[i] = data.readUint32();
    } else {
      throw new Error(`Unknown loca offset format: ${format}`);
    }
  }

  // PDFBOX-5794: Check for empty font
  if (numGlyphs === 1 && offsets[0] === 0 && offsets[1] === 0) {
    throw new Error("The font has no glyphs");
  }

  return {
    tag: "loca",
    offsets,

    getOffset(glyphId: number): number {
      if (glyphId < 0 || glyphId >= numGlyphs) {
        return 0;
      }

      return offsets[glyphId];
    },

    getLength(glyphId: number): number {
      if (glyphId < 0 || glyphId >= numGlyphs) {
        return 0;
      }
      return offsets[glyphId + 1] - offsets[glyphId];
    },
  };
}
