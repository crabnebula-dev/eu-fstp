/**
 * Drawing resources - types and classes.
 *
 * This module provides the core resource types for low-level PDF drawing:
 * - Shadings (gradients)
 * - Patterns (tiling and shading)
 * - Extended graphics state (opacity, blend modes)
 * - Form XObjects (reusable content)
 */

// Types
export type { BBox, BlendMode, PatternMatrix } from "./types.js";

// Shading
export type {
  AxialCoords,
  AxialShadingOptions,
  ColorStop,
  LinearGradientOptions,
  RadialCoords,
  RadialShadingOptions,
} from "./shading.js";
export { PDFShading } from "./shading.js";

// Pattern
export type { ImagePatternOptions, ShadingPatternOptions, TilingPatternOptions } from "./pattern.js";
export { PDFShadingPattern, PDFTilingPattern, type PDFPattern } from "./pattern.js";

// ExtGState
export type { ExtGStateOptions } from "./extgstate.js";
export { PDFExtGState } from "./extgstate.js";

// Form XObject
export type { FormXObjectOptions } from "./form-xobject.js";
export { PDFFormXObject } from "./form-xobject.js";
