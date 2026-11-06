/**
 * AFM (Adobe Font Metrics) module.
 *
 * Ported from Apache PDFBox's fontbox/afm module.
 */

/** biome-ignore-all assist/source/organizeImports: api file */

export { parseAFM, type AFMParserOptions } from "./parser.ts";

export {
  type FontMetrics,
  getCharacterWidth,
  getCharacterHeight,
  getAverageCharacterWidth,
} from "./font-metrics.ts";

export {
  type BoundingBox,
  type CharMetric,
  type Composite,
  type CompositePart,
  type KernPair,
  type Ligature,
  type TrackKern,
  getBoundingBoxWidth,
  getBoundingBoxHeight,
} from "./types.ts";
