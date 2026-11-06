/**
 * AnnotationFactory - Creates annotation objects from PDF dictionaries.
 *
 * Dispatches to the appropriate annotation class based on /Subtype.
 * Handles unknown annotation types gracefully.
 */

import type { ObjectRegistry } from "../document/object-registry.js";
import type { PdfDict } from "../objects/pdf-dict.js";
import type { PdfRef } from "../objects/pdf-ref.js";

import { PDFAnnotation } from "./base.js";
import { PDFCaretAnnotation } from "./caret.js";
import { PDFFileAttachmentAnnotation } from "./file-attachment.js";
import { PDFFreeTextAnnotation } from "./free-text.js";
import { PDFInkAnnotation } from "./ink.js";
import { PDFLineAnnotation } from "./line.js";
import { PDFLinkAnnotation } from "./link.js";
import { PDFPolygonAnnotation, PDFPolylineAnnotation } from "./polygon.js";
import { PDFPopupAnnotation } from "./popup.js";
import { PDFCircleAnnotation, PDFSquareAnnotation } from "./square-circle.js";
import { PDFStampAnnotation } from "./stamp.js";
import { PDFTextAnnotation } from "./text.js";
import {
  PDFHighlightAnnotation,
  PDFSquigglyAnnotation,
  PDFStrikeOutAnnotation,
  PDFUnderlineAnnotation,
} from "./text-markup.js";
import { isAnnotationSubtype, type AnnotationSubtype } from "./types.js";

/**
 * Unknown annotation - fallback for unsupported types.
 */
export class PDFUnknownAnnotation extends PDFAnnotation {}

/**
 * Create an annotation object from a PDF dictionary.
 *
 * @param dict - The annotation dictionary
 * @param ref - The reference to the annotation object
 * @param registry - The object registry for resolving references
 * @returns The appropriate annotation class instance
 */
export function createAnnotation(
  dict: PdfDict,
  ref: PdfRef | null,
  registry: ObjectRegistry,
): PDFAnnotation {
  const subtypeName = dict.getName("Subtype", registry.resolve.bind(registry))?.value;

  const subtype = isAnnotationSubtype(subtypeName) ? subtypeName : "Text";

  switch (subtype) {
    case "Text":
      return new PDFTextAnnotation(dict, ref, registry);

    case "Link":
      return new PDFLinkAnnotation(dict, ref, registry);

    case "FreeText":
      return new PDFFreeTextAnnotation(dict, ref, registry);

    case "Line":
      return new PDFLineAnnotation(dict, ref, registry);

    case "Square":
      return new PDFSquareAnnotation(dict, ref, registry);

    case "Circle":
      return new PDFCircleAnnotation(dict, ref, registry);

    case "Polygon":
      return new PDFPolygonAnnotation(dict, ref, registry);

    case "PolyLine":
      return new PDFPolylineAnnotation(dict, ref, registry);

    case "Highlight":
      return new PDFHighlightAnnotation(dict, ref, registry);

    case "Underline":
      return new PDFUnderlineAnnotation(dict, ref, registry);

    case "Squiggly":
      return new PDFSquigglyAnnotation(dict, ref, registry);

    case "StrikeOut":
      return new PDFStrikeOutAnnotation(dict, ref, registry);

    case "Stamp":
      return new PDFStampAnnotation(dict, ref, registry);

    case "Caret":
      return new PDFCaretAnnotation(dict, ref, registry);

    case "Ink":
      return new PDFInkAnnotation(dict, ref, registry);

    case "Popup":
      return new PDFPopupAnnotation(dict, ref, registry);

    case "FileAttachment":
      return new PDFFileAttachmentAnnotation(dict, ref, registry);

    case "Widget":
      // Widget annotations are handled by the forms subsystem
      // Return as unknown annotation if encountered here
      return new PDFUnknownAnnotation(dict, ref, registry);

    default:
      // Unknown annotation type - return generic
      return new PDFUnknownAnnotation(dict, ref, registry);
  }
}

/**
 * Check if an annotation is a Widget (form field).
 */
export function isWidgetAnnotation(dict: PdfDict, registry?: ObjectRegistry): boolean {
  return dict.getName("Subtype", registry?.resolve.bind(registry))?.value === "Widget";
}

/**
 * Check if an annotation is a Popup.
 */
export function isPopupAnnotation(dict: PdfDict, registry?: ObjectRegistry): boolean {
  return dict.getName("Subtype", registry?.resolve.bind(registry))?.value === "Popup";
}
