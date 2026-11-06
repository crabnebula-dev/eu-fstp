/**
 * The 'hhea' table - Horizontal Header Table.
 *
 * Contains information for horizontal layout.
 * Required in all TrueType fonts.
 *
 * Based on Apache PDFBox fontbox HorizontalHeaderTable.java
 * @see https://learn.microsoft.com/en-us/typography/opentype/spec/hhea
 */

import type { TableParseContext, TTFTable } from "../types.ts";

/**
 * Parsed 'hhea' table data.
 */
export interface HheaTable extends TTFTable {
  readonly tag: "hhea";

  /** Table version (typically 1.0) */
  readonly version: number;
  /** Typographic ascent */
  readonly ascender: number;
  /** Typographic descent (negative) */
  readonly descender: number;
  /** Typographic line gap */
  readonly lineGap: number;
  /** Maximum advance width */
  readonly advanceWidthMax: number;
  /** Minimum left sidebearing */
  readonly minLeftSideBearing: number;
  /** Minimum right sidebearing */
  readonly minRightSideBearing: number;
  /** Maximum x extent */
  readonly xMaxExtent: number;
  /** Caret slope rise (for italic) */
  readonly caretSlopeRise: number;
  /** Caret slope run (for italic) */
  readonly caretSlopeRun: number;
  /** Caret offset */
  readonly caretOffset: number;
  /** Metric data format (should be 0) */
  readonly metricDataFormat: number;
  /** Number of horizontal metrics in hmtx */
  readonly numberOfHMetrics: number;
}

/**
 * Parse the 'hhea' table.
 */
export function parseHheaTable(ctx: TableParseContext): HheaTable {
  const { data } = ctx;

  const version = data.readFixed();
  const ascender = data.readInt16();
  const descender = data.readInt16();
  const lineGap = data.readInt16();
  const advanceWidthMax = data.readUint16();
  const minLeftSideBearing = data.readInt16();
  const minRightSideBearing = data.readInt16();
  const xMaxExtent = data.readInt16();
  const caretSlopeRise = data.readInt16();
  const caretSlopeRun = data.readInt16();
  const caretOffset = data.readInt16();
  // Skip 4 reserved int16 values
  data.skip(8);
  const metricDataFormat = data.readInt16();
  const numberOfHMetrics = data.readUint16();

  return {
    tag: "hhea",
    version,
    ascender,
    descender,
    lineGap,
    advanceWidthMax,
    minLeftSideBearing,
    minRightSideBearing,
    xMaxExtent,
    caretSlopeRise,
    caretSlopeRun,
    caretOffset,
    metricDataFormat,
    numberOfHMetrics,
  };
}
