/**
 * Annotation module - PDF annotation support.
 *
 * This module provides classes for reading, creating, and manipulating
 * PDF annotations including text markup, links, shapes, stamps, and more.
 */

// Base classes
export { PDFAnnotation, parseColorArray, rectToArray } from "./base.js";
// Flattening
export { AnnotationFlattener } from "./flattener.js";
// Annotation types
export { type CaretSymbol, PDFCaretAnnotation } from "./caret.js";
// Factory
export {
  createAnnotation,
  isPopupAnnotation,
  isWidgetAnnotation,
  PDFUnknownAnnotation,
} from "./factory.js";
export { PDFFileAttachmentAnnotation } from "./file-attachment.js";
export { type FreeTextJustification, PDFFreeTextAnnotation } from "./free-text.js";
export { PDFInkAnnotation } from "./ink.js";
export { PDFLineAnnotation } from "./line.js";
export { type HighlightMode, type LinkAction, PDFLinkAnnotation } from "./link.js";
export { PDFMarkupAnnotation } from "./markup.js";
export { PDFPolygonAnnotation, PDFPolylineAnnotation } from "./polygon.js";
export { PDFPopupAnnotation } from "./popup.js";
export { PDFCircleAnnotation, PDFSquareAnnotation } from "./square-circle.js";
export { PDFStampAnnotation, STANDARD_STAMPS } from "./stamp.js";
export { PDFTextAnnotation, type TextAnnotationState, type TextAnnotationStateModel } from "./text.js";
export {
  PDFHighlightAnnotation,
  PDFSquigglyAnnotation,
  PDFStrikeOutAnnotation,
  PDFTextMarkupAnnotation,
  PDFUnderlineAnnotation,
  rectsToQuadPoints,
  rectToQuadPoints,
} from "./text-markup.js";

// Types
export {
  AnnotationFlags,
  type AnnotationSubtype,
  type BorderStyle,
  type BorderStyleType,
  type CaretAnnotationOptions,
  type CircleAnnotationOptions,
  type DestinationType,
  type FileAttachmentIcon,
  type FlattenAnnotationsOptions,
  type FreeTextAnnotationOptions,
  type InkAnnotationOptions,
  type LineAnnotationOptions,
  type LineEndingStyle,
  type LinkAnnotationOptions,
  type LinkDestination,
  type Point,
  type PolygonAnnotationOptions,
  type PolylineAnnotationOptions,
  type PopupOptions,
  type Rect,
  type RemoveAnnotationsOptions,
  type SquareAnnotationOptions,
  type StampAnnotationOptions,
  type StampName,
  type TextAnnotationIcon,
  type TextAnnotationOptions,
  type TextMarkupAnnotationOptions,
} from "./types.js";
