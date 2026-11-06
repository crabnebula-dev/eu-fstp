/**
 * PDFStampAnnotation - Rubber stamp annotations.
 *
 * Stamp annotations display a rubber stamp-like image on the page.
 * Standard stamps include Approved, Rejected, Draft, etc.
 *
 * PDF Reference: Section 12.5.6.12 "Rubber Stamp Annotations"
 */

import { PdfArray } from "../objects/pdf-array.js";
import { PdfDict } from "../objects/pdf-dict.js";
import { PdfName } from "../objects/pdf-name.js";
import { PdfNumber } from "../objects/pdf-number.js";
import { PdfString } from "../objects/pdf-string.js";

import { rectToArray } from "./base.js";
import { PDFMarkupAnnotation } from "./markup.js";
import type { StampAnnotationOptions, StampName } from "./types.js";

/**
 * Standard stamp names as defined in PDF spec.
 */
export const STANDARD_STAMPS: StampName[] = [
  "Approved",
  "Experimental",
  "NotApproved",
  "AsIs",
  "Expired",
  "NotForPublicRelease",
  "Confidential",
  "Final",
  "Sold",
  "Departmental",
  "ForComment",
  "TopSecret",
  "Draft",
  "ForPublicRelease",
];

/**
 * Stamp annotation - rubber stamp.
 */
export class PDFStampAnnotation extends PDFMarkupAnnotation {
  /**
   * Create a new stamp annotation dictionary.
   */
  static create(options: StampAnnotationOptions): PdfDict {
    const { rect } = options;

    const annotDict = PdfDict.of({
      Type: PdfName.of("Annot"),
      Subtype: PdfName.of("Stamp"),
      Rect: new PdfArray(rectToArray(rect)),
      Name: PdfName.of(options.name ?? "Draft"),
      F: PdfNumber.of(4), // Print flag
    });

    if (options.contents) {
      annotDict.set("Contents", PdfString.fromString(options.contents));
    }

    return annotDict;
  }

  /**
   * Stamp name/type.
   */
  get stampName(): string {
    const name = this.dict.getName("Name");

    return name?.value ?? "Draft";
  }

  /**
   * Set the stamp name.
   */
  setStampName(name: StampName | (string & {})): void {
    this.dict.set("Name", PdfName.of(name));
    this.markModified();
  }

  /**
   * Check if this is a standard stamp.
   */
  isStandardStamp(): boolean {
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion
    return STANDARD_STAMPS.includes(this.stampName as StampName);
  }
}
