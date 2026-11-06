/**
 * Drawing API exports.
 *
 * Re-exports all public drawing types and utilities for use
 * by consumers of the library.
 */

// Operations (for advanced users building custom content streams)
export { drawCircleOps, drawEllipseOps, drawLineOps, drawRectangleOps } from "./operations.js";
// Path builder
export { PathBuilder } from "./path-builder.js";
// Serialization
export { serializeOperators } from "./serialize.js";
export type { LayoutResult, PositionedWord, TextLine } from "./text-layout.js";

// Text layout utilities
export { layoutJustifiedLine, layoutText, measureText } from "./text-layout.js";
// Types
export type {
  BoundingBox,
  DrawCircleOptions,
  DrawEllipseOptions,
  DrawImageOptions,
  DrawLineOptions,
  DrawRectangleOptions,
  DrawSvgPathOptions,
  DrawTextOptions,
  FontInput,
  LineCap,
  LineJoin,
  PathOptions,
  Rotation,
  RotationOrigin,
  RotationOriginName,
  TextAlignment,
} from "./types.js";
export { lineCapToNumber, lineJoinToNumber, resolveRotationOrigin } from "./types.js";
