/**
 * The 'hmtx' table - Horizontal Metrics Table.
 *
 * Contains the horizontal metrics (advance widths and left side bearings).
 * Required in all TrueType fonts.
 *
 * Based on Apache PDFBox fontbox HorizontalMetricsTable.java
 * @see https://learn.microsoft.com/en-us/typography/opentype/spec/hmtx
 */

import type { TableParseContext, TTFTable } from "../types.ts";
import type { HheaTable } from "./hhea.ts";

/**
 * Parsed 'hmtx' table data.
 */
export interface HmtxTable extends TTFTable {
  readonly tag: "hmtx";

  /** Advance widths for glyphs (length = numberOfHMetrics from hhea) */
  readonly advanceWidths: Uint16Array;
  /** Left side bearings for glyphs with explicit metrics */
  readonly leftSideBearings: Int16Array;
  /** Left side bearings for glyphs using the last advance width */
  readonly nonHorizontalLeftSideBearings: Int16Array;
  /** Number of horizontal metrics (from hhea) */
  readonly numHMetrics: number;

  /** Get advance width for a glyph ID */
  getAdvanceWidth(glyphId: number): number;
  /** Get left side bearing for a glyph ID */
  getLeftSideBearing(glyphId: number): number;
}

/**
 * Parse the 'hmtx' table.
 */
export function parseHmtxTable(ctx: TableParseContext): HmtxTable {
  const { data, font, record } = ctx;

  // Need hhea to know numberOfHMetrics
  const hhea = font.getTable<HheaTable>("hhea");

  if (!hhea) {
    throw new Error("Cannot parse hmtx without hhea table");
  }

  const numHMetrics = hhea.numberOfHMetrics;
  const numGlyphs = font.numGlyphs;

  // Read longHorMetric array
  const advanceWidths = new Uint16Array(numHMetrics);
  const leftSideBearings = new Int16Array(numHMetrics);

  let bytesRead = 0;

  for (let i = 0; i < numHMetrics; i++) {
    advanceWidths[i] = data.readUint16();
    leftSideBearings[i] = data.readInt16();

    bytesRead += 4;
  }

  // Remaining glyphs share the last advance width but have their own LSB
  let numNonHorizontal = numGlyphs - numHMetrics;

  // Handle bad fonts with too many hmetrics
  if (numNonHorizontal < 0) {
    numNonHorizontal = numGlyphs;
  }

  const nonHorizontalLeftSideBearings = new Int16Array(numNonHorizontal);

  // Only read if there's data remaining
  if (bytesRead < record.length) {
    for (let i = 0; i < numNonHorizontal; i++) {
      if (bytesRead < record.length) {
        nonHorizontalLeftSideBearings[i] = data.readInt16();

        bytesRead += 2;
      }
    }
  }

  return {
    tag: "hmtx",
    advanceWidths,
    leftSideBearings,
    nonHorizontalLeftSideBearings,
    numHMetrics,

    getAdvanceWidth(glyphId: number): number {
      if (advanceWidths.length === 0) {
        return 250; // Fallback
      }

      if (glyphId < numHMetrics) {
        return advanceWidths[glyphId];
      }

      // Monospaced fonts use the last width for all subsequent glyphs
      return advanceWidths[advanceWidths.length - 1];
    },

    getLeftSideBearing(glyphId: number): number {
      if (leftSideBearings.length === 0) {
        return 0;
      }

      if (glyphId < numHMetrics) {
        return leftSideBearings[glyphId];
      }

      const index = glyphId - numHMetrics;

      if (index < nonHorizontalLeftSideBearings.length) {
        return nonHorizontalLeftSideBearings[index];
      }

      return 0;
    },
  };
}
