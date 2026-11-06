/**
 * AFM (Adobe Font Metrics) type definitions.
 *
 * Ported from Apache PDFBox's fontbox/afm module.
 */

/**
 * Bounding box for glyphs and fonts.
 */
export interface BoundingBox {
  /** Lower left X coordinate */
  readonly lowerLeftX: number;
  /** Lower left Y coordinate */
  readonly lowerLeftY: number;
  /** Upper right X coordinate */
  readonly upperRightX: number;
  /** Upper right Y coordinate */
  readonly upperRightY: number;
}

/**
 * Create a bounding box with computed width and height.
 */
export function createBoundingBox(
  lowerLeftX: number,
  lowerLeftY: number,
  upperRightX: number,
  upperRightY: number,
): BoundingBox {
  return { lowerLeftX, lowerLeftY, upperRightX, upperRightY };
}

/**
 * Get the width of a bounding box.
 */
export function getBoundingBoxWidth(box: BoundingBox): number {
  return box.upperRightX - box.lowerLeftX;
}

/**
 * Get the height of a bounding box.
 */
export function getBoundingBoxHeight(box: BoundingBox): number {
  return box.upperRightY - box.lowerLeftY;
}

/**
 * A ligature entry in character metrics.
 * When this character is followed by the successor, they should be replaced
 * with the ligature character.
 */
export interface Ligature {
  /** The character that follows to trigger the ligature */
  readonly successor: string;
  /** The ligature character to use instead */
  readonly ligature: string;
}

/**
 * Create a ligature.
 */
export function createLigature(successor: string, ligature: string): Ligature {
  return { successor, ligature };
}

/**
 * Kerning pair data.
 * Specifies the adjustment when the first character is followed by the second.
 */
export interface KernPair {
  /** First character name */
  readonly firstKernCharacter: string;
  /** Second character name */
  readonly secondKernCharacter: string;
  /** X adjustment in character space units */
  readonly x: number;
  /** Y adjustment in character space units */
  readonly y: number;
}

/**
 * Create a kern pair.
 */
export function createKernPair(
  firstKernCharacter: string,
  secondKernCharacter: string,
  x: number,
  y: number,
): KernPair {
  return { firstKernCharacter, secondKernCharacter, x, y };
}

/**
 * Track kerning data.
 * Specifies kerning that varies with point size.
 */
export interface TrackKern {
  /** Degree of track kerning (-2 to 2, 0 = none) */
  readonly degree: number;
  /** Minimum point size */
  readonly minPointSize: number;
  /** Kerning at minimum point size */
  readonly minKern: number;
  /** Maximum point size */
  readonly maxPointSize: number;
  /** Kerning at maximum point size */
  readonly maxKern: number;
}

/**
 * Create a track kern entry.
 */
export function createTrackKern(
  degree: number,
  minPointSize: number,
  minKern: number,
  maxPointSize: number,
  maxKern: number,
): TrackKern {
  return { degree, minPointSize, minKern, maxPointSize, maxKern };
}

/**
 * A part of a composite character.
 */
export interface CompositePart {
  /** Name of the component character */
  readonly name: string;
  /** X displacement from origin */
  readonly xDisplacement: number;
  /** Y displacement from origin */
  readonly yDisplacement: number;
}

/**
 * Create a composite part.
 */
export function createCompositePart(
  name: string,
  xDisplacement: number,
  yDisplacement: number,
): CompositePart {
  return { name, xDisplacement, yDisplacement };
}

/**
 * Composite character data.
 * Describes how a character is composed of other characters.
 */
export interface Composite {
  /** Name of the composite character */
  readonly name: string;
  /** Parts that make up this composite */
  readonly parts: readonly CompositePart[];
}

/**
 * Create a composite (mutable parts array for building).
 */
export function createComposite(name: string): { name: string; parts: CompositePart[] } {
  return { name, parts: [] };
}

/**
 * Metrics for a single character.
 */
export interface CharMetric {
  /** Character code (-1 if not encoded) */
  readonly characterCode: number;

  /** Character name (e.g., "A", "space", "Aacute") */
  readonly name: string;

  /** Width vector X component (writing direction 0) */
  readonly wx: number;
  /** Width vector Y component (writing direction 0) */
  readonly wy: number;

  /** Width X component for writing direction 0 */
  readonly w0x: number;
  /** Width Y component for writing direction 0 */
  readonly w0y: number;

  /** Width X component for writing direction 1 */
  readonly w1x: number;
  /** Width Y component for writing direction 1 */
  readonly w1y: number;

  /** Width vector [x, y] for writing direction 0+1 */
  readonly w: readonly [number, number] | null;
  /** Width vector [x, y] for writing direction 0 */
  readonly w0: readonly [number, number] | null;
  /** Width vector [x, y] for writing direction 1 */
  readonly w1: readonly [number, number] | null;

  /** V vector [x, y] for writing direction 1 origin */
  readonly vv: readonly [number, number] | null;

  /** Bounding box of the character */
  readonly boundingBox: BoundingBox | null;

  /** Ligatures for this character */
  readonly ligatures: readonly Ligature[];
}

/**
 * Mutable character metric builder for parsing.
 */
export interface CharMetricBuilder {
  characterCode: number;
  name: string;
  wx: number;
  wy: number;
  w0x: number;
  w0y: number;
  w1x: number;
  w1y: number;
  w: [number, number] | null;
  w0: [number, number] | null;
  w1: [number, number] | null;
  vv: [number, number] | null;
  boundingBox: BoundingBox | null;
  ligatures: Ligature[];
}

/**
 * Create a default character metric builder.
 */
export function createCharMetricBuilder(): CharMetricBuilder {
  return {
    characterCode: -1,
    name: "",
    wx: 0,
    wy: 0,
    w0x: 0,
    w0y: 0,
    w1x: 0,
    w1y: 0,
    w: null,
    w0: null,
    w1: null,
    vv: null,
    boundingBox: null,
    ligatures: [],
  };
}

/**
 * Freeze a character metric builder into an immutable CharMetric.
 */
export function freezeCharMetric(builder: CharMetricBuilder): CharMetric {
  return {
    characterCode: builder.characterCode,
    name: builder.name,
    wx: builder.wx,
    wy: builder.wy,
    w0x: builder.w0x,
    w0y: builder.w0y,
    w1x: builder.w1x,
    w1y: builder.w1y,
    w: builder.w ? [builder.w[0], builder.w[1]] : null,
    w0: builder.w0 ? [builder.w0[0], builder.w0[1]] : null,
    w1: builder.w1 ? [builder.w1[0], builder.w1[1]] : null,
    vv: builder.vv ? [builder.vv[0], builder.vv[1]] : null,
    boundingBox: builder.boundingBox,
    ligatures: [...builder.ligatures],
  };
}
