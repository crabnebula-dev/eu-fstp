/**
 * FontMetrics - the outermost AFM type containing all font data.
 *
 * Ported from Apache PDFBox's fontbox/afm/FontMetrics.java
 */

import type { BoundingBox, CharMetric, Composite, KernPair, TrackKern } from "./types.ts";
import { getBoundingBoxHeight } from "./types.ts";

/**
 * Complete font metrics from an AFM file.
 */
export interface FontMetrics {
  /** AFM version number */
  readonly afmVersion: number;

  /** Metric sets (0 = writing direction 0, 1 = direction 1, 2 = both) */
  readonly metricSets: number;

  /** PostScript font name */
  readonly fontName: string;

  /** Full name of the font */
  readonly fullName: string;

  /** Font family name */
  readonly familyName: string;

  /** Weight (e.g., "Medium", "Bold") */
  readonly weight: string;

  /** Font bounding box */
  readonly fontBBox: BoundingBox | null;

  /** Font version */
  readonly fontVersion: string;

  /** Copyright notice */
  readonly notice: string;

  /** Encoding scheme name */
  readonly encodingScheme: string;

  /** Mapping scheme */
  readonly mappingScheme: number;

  /** Escape character code */
  readonly escChar: number;

  /** Character set name */
  readonly characterSet: string;

  /** Number of characters */
  readonly characters: number;

  /** Whether this is a base font */
  readonly isBaseFont: boolean;

  /** V vector [x, y] for writing direction 1 */
  readonly vVector: readonly [number, number] | null;

  /** Whether V vector is fixed for all glyphs */
  readonly isFixedV: boolean | null;

  /** Cap height */
  readonly capHeight: number;

  /** X height */
  readonly xHeight: number;

  /** Ascender */
  readonly ascender: number;

  /** Descender (typically negative) */
  readonly descender: number;

  /** Comments from the AFM file */
  readonly comments: readonly string[];

  /** Underline position */
  readonly underlinePosition: number;

  /** Underline thickness */
  readonly underlineThickness: number;

  /** Italic angle */
  readonly italicAngle: number;

  /** Character width [x, y] if fixed */
  readonly charWidth: readonly [number, number] | null;

  /** Whether this is a fixed-pitch (monospace) font */
  readonly isFixedPitch: boolean;

  /** Standard horizontal width */
  readonly standardHorizontalWidth: number;

  /** Standard vertical width */
  readonly standardVerticalWidth: number;

  /** Character metrics */
  readonly charMetrics: readonly CharMetric[];

  /** Track kerning data */
  readonly trackKern: readonly TrackKern[];

  /** Composite character definitions */
  readonly composites: readonly Composite[];

  /** Kerning pairs (default) */
  readonly kernPairs: readonly KernPair[];

  /** Kerning pairs for writing direction 0 */
  readonly kernPairs0: readonly KernPair[];

  /** Kerning pairs for writing direction 1 */
  readonly kernPairs1: readonly KernPair[];
}

/**
 * Mutable builder for FontMetrics during parsing.
 */
export interface FontMetricsBuilder {
  afmVersion: number;
  metricSets: number;
  fontName: string;
  fullName: string;
  familyName: string;
  weight: string;
  fontBBox: BoundingBox | null;
  fontVersion: string;
  notice: string;
  encodingScheme: string;
  mappingScheme: number;
  escChar: number;
  characterSet: string;
  characters: number;
  isBaseFont: boolean;
  vVector: [number, number] | null;
  isFixedV: boolean | null;
  capHeight: number;
  xHeight: number;
  ascender: number;
  descender: number;
  comments: string[];
  underlinePosition: number;
  underlineThickness: number;
  italicAngle: number;
  charWidth: [number, number] | null;
  isFixedPitch: boolean;
  standardHorizontalWidth: number;
  standardVerticalWidth: number;
  charMetrics: CharMetric[];
  charMetricsMap: Map<string, CharMetric>;
  trackKern: TrackKern[];
  composites: Composite[];
  kernPairs: KernPair[];
  kernPairs0: KernPair[];
  kernPairs1: KernPair[];
}

/**
 * Create a default FontMetrics builder.
 */
export function createFontMetricsBuilder(): FontMetricsBuilder {
  return {
    afmVersion: 0,
    metricSets: 0,
    fontName: "",
    fullName: "",
    familyName: "",
    weight: "",
    fontBBox: null,
    fontVersion: "",
    notice: "",
    encodingScheme: "",
    mappingScheme: 0,
    escChar: 0,
    characterSet: "",
    characters: 0,
    isBaseFont: true,
    vVector: null,
    isFixedV: null,
    capHeight: 0,
    xHeight: 0,
    ascender: 0,
    descender: 0,
    comments: [],
    underlinePosition: 0,
    underlineThickness: 0,
    italicAngle: 0,
    charWidth: null,
    isFixedPitch: false,
    standardHorizontalWidth: 0,
    standardVerticalWidth: 0,
    charMetrics: [],
    charMetricsMap: new Map(),
    trackKern: [],
    composites: [],
    kernPairs: [],
    kernPairs0: [],
    kernPairs1: [],
  };
}

/**
 * Add a character metric to the builder.
 */
export function addCharMetric(builder: FontMetricsBuilder, metric: CharMetric): void {
  builder.charMetrics.push(metric);
  builder.charMetricsMap.set(metric.name, metric);
}

/**
 * Freeze a FontMetrics builder into an immutable FontMetrics.
 */
export function freezeFontMetrics(builder: FontMetricsBuilder): FontMetrics {
  // If isFixedV was not explicitly set, default based on vVector presence
  const isFixedV = builder.isFixedV ?? builder.vVector !== null;

  return {
    afmVersion: builder.afmVersion,
    metricSets: builder.metricSets,
    fontName: builder.fontName,
    fullName: builder.fullName,
    familyName: builder.familyName,
    weight: builder.weight,
    fontBBox: builder.fontBBox,
    fontVersion: builder.fontVersion,
    notice: builder.notice,
    encodingScheme: builder.encodingScheme,
    mappingScheme: builder.mappingScheme,
    escChar: builder.escChar,
    characterSet: builder.characterSet,
    characters: builder.characters,
    isBaseFont: builder.isBaseFont,
    vVector: builder.vVector ? [builder.vVector[0], builder.vVector[1]] : null,
    isFixedV,
    capHeight: builder.capHeight,
    xHeight: builder.xHeight,
    ascender: builder.ascender,
    descender: builder.descender,
    comments: [...builder.comments],
    underlinePosition: builder.underlinePosition,
    underlineThickness: builder.underlineThickness,
    italicAngle: builder.italicAngle,
    charWidth: builder.charWidth ? [builder.charWidth[0], builder.charWidth[1]] : null,
    isFixedPitch: builder.isFixedPitch,
    standardHorizontalWidth: builder.standardHorizontalWidth,
    standardVerticalWidth: builder.standardVerticalWidth,
    charMetrics: [...builder.charMetrics],
    trackKern: [...builder.trackKern],
    composites: [...builder.composites],
    kernPairs: [...builder.kernPairs],
    kernPairs0: [...builder.kernPairs0],
    kernPairs1: [...builder.kernPairs1],
  };
}

/**
 * Get the width of a character by name.
 */
export function getCharacterWidth(metrics: FontMetrics | FontMetricsBuilder, name: string): number {
  const charMetricsMap =
    "charMetricsMap" in metrics
      ? metrics.charMetricsMap
      : new Map(metrics.charMetrics.map(m => [m.name, m]));

  const metric = charMetricsMap.get(name);
  return metric?.wx ?? 0;
}

/**
 * Get the height of a character by name.
 */
export function getCharacterHeight(
  metrics: FontMetrics | FontMetricsBuilder,
  name: string,
): number {
  const charMetricsMap =
    "charMetricsMap" in metrics
      ? metrics.charMetricsMap
      : new Map(metrics.charMetrics.map(m => [m.name, m]));

  const metric = charMetricsMap.get(name);

  if (!metric) {
    return 0;
  }

  if (metric.wy !== 0) {
    return metric.wy;
  }

  if (metric.boundingBox) {
    return getBoundingBoxHeight(metric.boundingBox);
  }

  return 0;
}

/**
 * Get the average character width.
 */
export function getAverageCharacterWidth(metrics: FontMetrics): number {
  let totalWidths = 0;
  let characterCount = 0;

  for (const metric of metrics.charMetrics) {
    if (metric.wx > 0) {
      totalWidths += metric.wx;
      characterCount += 1;
    }
  }

  return totalWidths > 0 ? totalWidths / characterCount : 0;
}
