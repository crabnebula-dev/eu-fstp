/**
 * The 'glyf' table - Glyph Data Table.
 *
 * Contains the glyph outlines for TrueType fonts.
 * Required in TrueType fonts (not CFF).
 *
 * Based on Apache PDFBox fontbox GlyphTable.java, GlyphData.java,
 * GlyfDescript.java, GlyfSimpleDescript.java, GlyfCompositeDescript.java
 * @see https://learn.microsoft.com/en-us/typography/opentype/spec/glyf
 */

import type { TableParseContext, TTFTable } from "../types.ts";
import type { HmtxTable } from "./hmtx.ts";
import type { LocaTable } from "./loca.ts";
import type { MaxpTable } from "./maxp.ts";

// Glyph point flags
/** Point is on the curve (vs. off-curve control point) */
export const ON_CURVE = 0x01;
/** X coordinate is 1 byte (vs 2 bytes) */
export const X_SHORT_VECTOR = 0x02;
/** Y coordinate is 1 byte (vs 2 bytes) */
export const Y_SHORT_VECTOR = 0x04;
/** Next byte specifies repeat count for this flag */
export const REPEAT = 0x08;
/** If X_SHORT_VECTOR: positive value. Otherwise: same as previous X */
export const X_DUAL = 0x10;
/** If Y_SHORT_VECTOR: positive value. Otherwise: same as previous Y */
export const Y_DUAL = 0x20;

// Composite glyph flags
/** Arguments are 16-bit words (vs 8-bit bytes) */
export const ARG_1_AND_2_ARE_WORDS = 0x0001;
/** Arguments are signed xy values (vs unsigned point indices) */
export const ARGS_ARE_XY_VALUES = 0x0002;
/** Round xy values to grid */
export const ROUND_XY_TO_GRID = 0x0004;
/** Uniform scale for component */
export const WE_HAVE_A_SCALE = 0x0008;
/** More components follow */
export const MORE_COMPONENTS = 0x0020;
/** Separate x and y scale */
export const WE_HAVE_AN_X_AND_Y_SCALE = 0x0040;
/** 2x2 transformation matrix */
export const WE_HAVE_A_TWO_BY_TWO = 0x0080;
/** Instructions follow last component */
export const WE_HAVE_INSTRUCTIONS = 0x0100;
/** Use this glyph's metrics */
export const USE_MY_METRICS = 0x0200;

/**
 * Bounding box for a glyph.
 */
export interface GlyphBounds {
  readonly xMin: number;
  readonly yMin: number;
  readonly xMax: number;
  readonly yMax: number;
}

/**
 * A component of a composite glyph.
 */
export interface CompositeComponent {
  /** Flags for this component */
  readonly flags: number;
  /** Glyph index of the component */
  readonly glyphIndex: number;
  /** X translation */
  readonly xTranslate: number;
  /** Y translation */
  readonly yTranslate: number;
  /** X scale factor (default 1.0) */
  readonly xScale: number;
  /** Y scale factor (default 1.0) */
  readonly yScale: number;
  /** Scale01 for 2x2 matrix */
  readonly scale01: number;
  /** Scale10 for 2x2 matrix */
  readonly scale10: number;
}

/**
 * Description of a glyph's outline.
 */
export interface GlyphDescription {
  /** True if this is a composite glyph */
  readonly isComposite: boolean;
  /** Number of contours (-1 for composite) */
  readonly numberOfContours: number;
  /** Number of points in the glyph */
  readonly pointCount: number;
  /** Number of contours in the resolved glyph */
  readonly contourCount: number;
  /** Hinting instructions */
  readonly instructions: Uint8Array;

  // Simple glyph data (undefined for composite)
  /** End point indices for each contour */
  readonly endPtsOfContours?: Uint16Array;
  /** Point flags */
  readonly flags?: Uint8Array;
  /** X coordinates (absolute, not delta) */
  readonly xCoordinates?: Int16Array;
  /** Y coordinates (absolute, not delta) */
  readonly yCoordinates?: Int16Array;

  // Composite glyph data (undefined for simple)
  /** Component references */
  readonly components?: CompositeComponent[];
}

/**
 * Data for a single glyph.
 */
export interface GlyphData {
  /** Glyph ID */
  readonly glyphId: number;
  /** Bounding box */
  readonly bounds: GlyphBounds;
  /** Glyph description (outlines) */
  readonly description: GlyphDescription;
}

/**
 * Parsed 'glyf' table data.
 */
export interface GlyfTable extends TTFTable {
  readonly tag: "glyf";

  /**
   * Get glyph data by glyph ID.
   * Returns undefined for glyphs with no outline (e.g., space).
   */
  getGlyph(glyphId: number): GlyphData | undefined;

  /**
   * Get all component glyph IDs referenced by a composite glyph.
   * Recursively resolves nested composites.
   */
  getCompositeGlyphIds(glyphId: number): Set<number>;
}

/**
 * Parse the 'glyf' table.
 */
export function parseGlyfTable(ctx: TableParseContext): GlyfTable {
  const { data, font } = ctx;

  // Get dependencies
  const loca = font.getTable<LocaTable>("loca");

  if (!loca) {
    throw new Error("Cannot parse glyf without loca table");
  }

  const maxp = font.getTable<MaxpTable>("maxp");
  const hmtx = font.getTable<HmtxTable>("hmtx");
  const numGlyphs = font.numGlyphs;
  const maxComponentDepth = maxp?.maxComponentDepth ?? 10;

  // Cache for parsed glyphs
  const glyphCache = new Map<number, GlyphData | null>();

  // The raw glyf table data
  const tableData = data.bytes;

  function getGlyph(glyphId: number, level = 0): GlyphData | undefined {
    if (glyphId < 0 || glyphId >= numGlyphs || !loca) {
      return undefined;
    }

    // Check cache
    if (glyphCache.has(glyphId)) {
      const cached = glyphCache.get(glyphId);

      return cached ?? undefined;
    }

    const offset = loca.getOffset(glyphId);
    const length = loca.getLength(glyphId);

    // Empty glyph (no outline)
    if (length === 0) {
      const emptyGlyph: GlyphData = {
        glyphId,
        bounds: { xMin: 0, yMin: 0, xMax: 0, yMax: 0 },
        description: createEmptyDescription(),
      };

      glyphCache.set(glyphId, emptyGlyph);

      return emptyGlyph;
    }

    // Check bounds
    if (offset + length > tableData.length) {
      glyphCache.set(glyphId, null);

      return undefined;
    }

    // Parse glyph data
    const glyphData = parseGlyphData(
      tableData.subarray(offset, offset + length),
      glyphId,
      level,
      maxComponentDepth,
      hmtx?.getLeftSideBearing(glyphId) ?? 0,
      getGlyph,
    );

    glyphCache.set(glyphId, glyphData);

    return glyphData;
  }

  function getCompositeGlyphIds(glyphId: number): Set<number> {
    const result = new Set<number>();
    const visited = new Set<number>();

    function collect(gid: number) {
      if (visited.has(gid)) {
        return;
      }

      visited.add(gid);

      const glyph = getGlyph(gid);

      if (glyph?.description.isComposite && glyph.description.components) {
        for (const comp of glyph.description.components) {
          result.add(comp.glyphIndex);
          collect(comp.glyphIndex);
        }
      }
    }

    collect(glyphId);

    return result;
  }

  return {
    tag: "glyf",
    getGlyph,
    getCompositeGlyphIds,
  };
}

/**
 * Create an empty glyph description.
 */
function createEmptyDescription(): GlyphDescription {
  return {
    isComposite: false,
    numberOfContours: 0,
    pointCount: 0,
    contourCount: 0,
    instructions: new Uint8Array(0),
    endPtsOfContours: new Uint16Array(0),
    flags: new Uint8Array(0),
    xCoordinates: new Int16Array(0),
    yCoordinates: new Int16Array(0),
  };
}

/**
 * Parse glyph data from bytes.
 */
function parseGlyphData(
  bytes: Uint8Array,
  glyphId: number,
  level: number,
  maxLevel: number,
  leftSideBearing: number,
  getGlyph: (gid: number, level?: number) => GlyphData | undefined,
): GlyphData {
  if (level > maxLevel) {
    throw new Error(`Composite glyph maximum level (${maxLevel}) reached`);
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 0;

  // Read glyph header
  const numberOfContours = view.getInt16(offset);
  offset += 2;
  const xMin = view.getInt16(offset);
  offset += 2;
  const yMin = view.getInt16(offset);
  offset += 2;
  const xMax = view.getInt16(offset);
  offset += 2;
  const yMax = view.getInt16(offset);
  offset += 2;

  const bounds: GlyphBounds = { xMin, yMin, xMax, yMax };

  let description: GlyphDescription;

  if (numberOfContours >= 0) {
    // Simple glyph
    description = parseSimpleGlyph(view, offset, numberOfContours, xMin, leftSideBearing);
  } else {
    // Composite glyph (numberOfContours == -1)
    description = parseCompositeGlyph(view, offset, getGlyph, level);
  }

  return { glyphId, bounds, description };
}

/**
 * Parse a simple (non-composite) glyph.
 */
function parseSimpleGlyph(
  view: DataView,
  offset: number,
  numberOfContours: number,
  xMin: number,
  leftSideBearing: number,
): GlyphDescription {
  // Handle empty glyph (0 contours)
  if (numberOfContours === 0) {
    return createEmptyDescription();
  }

  // Read end points of contours
  const endPtsOfContours = new Uint16Array(numberOfContours);
  for (let i = 0; i < numberOfContours; i++) {
    endPtsOfContours[i] = view.getUint16(offset);
    offset += 2;
  }

  // PDFBOX-2939: handle invalid end point
  const lastEndPt = endPtsOfContours[numberOfContours - 1];

  if (numberOfContours === 1 && lastEndPt === 65535) {
    return createEmptyDescription();
  }

  const pointCount = lastEndPt + 1;

  // Read instructions
  const instructionLength = view.getUint16(offset);
  offset += 2;

  const instructions = new Uint8Array(view.buffer, view.byteOffset + offset, instructionLength);
  offset += instructionLength;

  // Read flags (run-length encoded)
  const flags = new Uint8Array(pointCount);
  let flagIndex = 0;

  while (flagIndex < pointCount) {
    const flag = view.getUint8(offset);
    offset += 1;
    flags[flagIndex++] = flag;

    if ((flag & REPEAT) !== 0) {
      const repeatCount = view.getUint8(offset);
      offset += 1;

      for (let r = 0; r < repeatCount && flagIndex < pointCount; r++) {
        flags[flagIndex++] = flag;
      }
    }
  }

  // Read X coordinates (stored as relative values, convert to absolute)
  const xCoordinates = new Int16Array(pointCount);
  // Start from leftSideBearing - xMin as in PDFBox
  let x = leftSideBearing - xMin;

  for (let i = 0; i < pointCount; i++) {
    const flag = flags[i];

    if ((flag & X_DUAL) !== 0) {
      if ((flag & X_SHORT_VECTOR) !== 0) {
        // 1-byte positive value
        x += view.getUint8(offset);
        offset += 1;
      }
      // else: same as previous (x unchanged)
    } else {
      if ((flag & X_SHORT_VECTOR) !== 0) {
        // 1-byte negative value
        x -= view.getUint8(offset);
        offset += 1;
      } else {
        // 2-byte signed value
        x += view.getInt16(offset);
        offset += 2;
      }
    }

    xCoordinates[i] = x;
  }

  // Read Y coordinates
  const yCoordinates = new Int16Array(pointCount);

  let y = 0;

  for (let i = 0; i < pointCount; i++) {
    const flag = flags[i];

    if ((flag & Y_DUAL) !== 0) {
      if ((flag & Y_SHORT_VECTOR) !== 0) {
        // 1-byte positive value
        y += view.getUint8(offset);
        offset += 1;
      }
      // else: same as previous (y unchanged)
    } else {
      if ((flag & Y_SHORT_VECTOR) !== 0) {
        // 1-byte negative value
        y -= view.getUint8(offset);
        offset += 1;
      } else {
        // 2-byte signed value
        y += view.getInt16(offset);
        offset += 2;
      }
    }

    yCoordinates[i] = y;
  }

  return {
    isComposite: false,
    numberOfContours,
    pointCount,
    contourCount: numberOfContours,
    instructions,
    endPtsOfContours,
    flags,
    xCoordinates,
    yCoordinates,
  };
}

/**
 * Parse a composite glyph.
 */
function parseCompositeGlyph(
  view: DataView,
  offset: number,
  getGlyph: (gid: number, level?: number) => GlyphData | undefined,
  level: number,
): GlyphDescription {
  const components: CompositeComponent[] = [];
  let flags: number;

  // Read all components
  do {
    flags = view.getUint16(offset);
    offset += 2;

    const glyphIndex = view.getUint16(offset);
    offset += 2;

    let argument1: number;
    let argument2: number;

    if ((flags & ARG_1_AND_2_ARE_WORDS) !== 0) {
      argument1 = view.getInt16(offset);
      offset += 2;
      argument2 = view.getInt16(offset);
      offset += 2;
    } else {
      argument1 = view.getInt8(offset);
      offset += 1;
      argument2 = view.getInt8(offset);
      offset += 1;
    }

    let xTranslate = 0;
    let yTranslate = 0;

    if ((flags & ARGS_ARE_XY_VALUES) !== 0) {
      xTranslate = argument1;
      yTranslate = argument2;
    }
    // else: point matching (not implementing transforms for point matching)

    let xScale = 1.0;
    let yScale = 1.0;
    let scale01 = 0.0;
    let scale10 = 0.0;

    if ((flags & WE_HAVE_A_SCALE) !== 0) {
      const scale = view.getInt16(offset) / 0x4000;
      offset += 2;
      xScale = yScale = scale;
    } else if ((flags & WE_HAVE_AN_X_AND_Y_SCALE) !== 0) {
      xScale = view.getInt16(offset) / 0x4000;
      offset += 2;
      yScale = view.getInt16(offset) / 0x4000;
      offset += 2;
    } else if ((flags & WE_HAVE_A_TWO_BY_TWO) !== 0) {
      xScale = view.getInt16(offset) / 0x4000;
      offset += 2;
      scale01 = view.getInt16(offset) / 0x4000;
      offset += 2;
      scale10 = view.getInt16(offset) / 0x4000;
      offset += 2;
      yScale = view.getInt16(offset) / 0x4000;
      offset += 2;
    }

    components.push({
      flags,
      glyphIndex,
      xTranslate,
      yTranslate,
      xScale,
      yScale,
      scale01,
      scale10,
    });
  } while ((flags & MORE_COMPONENTS) !== 0);

  // Read instructions if present
  let instructions = new Uint8Array(0);

  if ((flags & WE_HAVE_INSTRUCTIONS) !== 0) {
    const instructionLength = view.getUint16(offset);
    offset += 2;

    // Copy instruction bytes to avoid shared buffer issues
    instructions = new Uint8Array(instructionLength);

    for (let i = 0; i < instructionLength; i++) {
      instructions[i] = view.getUint8(offset + i);
    }
  }

  // Calculate total point and contour count by resolving components
  let pointCount = 0;
  let contourCount = 0;

  for (const comp of components) {
    const componentGlyph = getGlyph(comp.glyphIndex, level + 1);

    if (componentGlyph) {
      pointCount += componentGlyph.description.pointCount;
      contourCount += componentGlyph.description.contourCount;
    }
  }

  return {
    isComposite: true,
    numberOfContours: -1,
    pointCount,
    contourCount,
    instructions,
    components,
  };
}
