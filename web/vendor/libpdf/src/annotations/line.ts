/**
 * PDFLineAnnotation - Line annotations.
 *
 * Line annotations display a line on the page with optional
 * arrow endings.
 *
 * PDF Reference: Section 12.5.6.7 "Line Annotations"
 */

import { type Color, colorToArray, rgb } from "#src/helpers/colors";
import { PdfArray } from "#src/objects/pdf-array";
import { PdfDict } from "#src/objects/pdf-dict";
import { PdfName } from "#src/objects/pdf-name";
import { PdfNumber } from "#src/objects/pdf-number";
import { PdfString } from "#src/objects/pdf-string";

import { parseColorArray } from "./base";
import { PDFMarkupAnnotation } from "./markup";
import type { LineAnnotationOptions, LineEndingStyle, Point } from "./types";

/**
 * Line annotation - a line with optional arrow endings.
 */
export class PDFLineAnnotation extends PDFMarkupAnnotation {
  /**
   * Create a new line annotation dictionary.
   */
  static create(options: LineAnnotationOptions): PdfDict {
    const { start, end } = options;
    const color = options.color ?? rgb(0, 0, 0);
    const colorComponents = colorToArray(color);

    // Calculate bounding rect
    const minX = Math.min(start.x, end.x);
    const minY = Math.min(start.y, end.y);
    const maxX = Math.max(start.x, end.x);
    const maxY = Math.max(start.y, end.y);

    const annotDict = PdfDict.of({
      Type: PdfName.of("Annot"),
      Subtype: PdfName.of("Line"),
      Rect: new PdfArray([
        PdfNumber.of(minX),
        PdfNumber.of(minY),
        PdfNumber.of(maxX),
        PdfNumber.of(maxY),
      ]),
      L: new PdfArray([
        PdfNumber.of(start.x),
        PdfNumber.of(start.y),
        PdfNumber.of(end.x),
        PdfNumber.of(end.y),
      ]),
      C: new PdfArray(colorComponents.map(n => PdfNumber.of(n))),
      F: PdfNumber.of(4), // Print flag
    });

    // Border style for line width
    if (options.width !== undefined) {
      const bs = new PdfDict();
      bs.set("W", PdfNumber.of(options.width));
      bs.set("S", PdfName.of("S"));
      annotDict.set("BS", bs);
    }

    // Line endings
    if (options.startStyle || options.endStyle) {
      annotDict.set(
        "LE",
        new PdfArray([
          PdfName.of(options.startStyle ?? "None"),
          PdfName.of(options.endStyle ?? "None"),
        ]),
      );
    }

    // Interior color for closed arrows
    if (options.interiorColor) {
      const icComponents = colorToArray(options.interiorColor);
      annotDict.set("IC", new PdfArray(icComponents.map(n => PdfNumber.of(n))));
    }

    if (options.contents) {
      annotDict.set("Contents", PdfString.fromString(options.contents));
    }

    return annotDict;
  }

  /**
   * Get the line endpoints.
   */
  get lineEndpoints(): { start: Point; end: Point } {
    const l = this.dict.getArray("L", this.registry.resolve.bind(this.registry));

    if (!l || l.length < 4) {
      return {
        start: { x: 0, y: 0 },
        end: { x: 0, y: 0 },
      };
    }

    const [x1, y1, x2, y2] = l.toArray().map(item => (item instanceof PdfNumber ? item.value : 0));

    return {
      start: {
        x: x1 ?? 0,
        y: y1 ?? 0,
      },
      end: {
        x: x2 ?? 0,
        y: y2 ?? 0,
      },
    };
  }

  /**
   * Set the line endpoints.
   */
  setLineEndpoints(start: Point, end: Point): void {
    const arr = this.dict.getArray("L", this.registry.resolve.bind(this.registry));

    if (arr && arr.length >= 4) {
      arr.set(0, PdfNumber.of(start.x));
      arr.set(1, PdfNumber.of(start.y));
      arr.set(2, PdfNumber.of(end.x));
      arr.set(3, PdfNumber.of(end.y));
    } else {
      this.dict.set(
        "L",
        new PdfArray([
          PdfNumber.of(start.x),
          PdfNumber.of(start.y),
          PdfNumber.of(end.x),
          PdfNumber.of(end.y),
        ]),
      );
    }

    this.markModified();
  }

  /**
   * Get the start point.
   */
  get start(): Point {
    return this.lineEndpoints.start;
  }

  /**
   * Get the end point.
   */
  get end(): Point {
    return this.lineEndpoints.end;
  }

  /**
   * Line ending styles [start, end].
   */
  get lineEndingStyles(): [LineEndingStyle, LineEndingStyle] {
    const le = this.dict.getArray("LE", this.registry.resolve.bind(this.registry));

    if (!le || le.length < 2) {
      return ["None", "None"];
    }

    const [startStyle, endStyle] = le
      .toArray()
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion
      .map(item => (item instanceof PdfName ? (item.value as LineEndingStyle) : "None"));

    return [startStyle ?? "None", endStyle ?? "None"];
  }

  /**
   * Set the line ending styles.
   */
  setLineEndingStyles(startStyle: LineEndingStyle, endStyle: LineEndingStyle): void {
    this.dict.set("LE", new PdfArray([PdfName.of(startStyle), PdfName.of(endStyle)]));
    this.markModified();
  }

  /**
   * Interior color (fill color for closed arrow heads).
   */
  get interiorColor(): Color | null {
    const ic = this.dict.getArray("IC", this.registry.resolve.bind(this.registry));

    return parseColorArray(ic);
  }

  /**
   * Set the interior color.
   */
  setInteriorColor(color: Color): void {
    const components = colorToArray(color);
    this.dict.set("IC", new PdfArray(components.map(n => PdfNumber.of(n))));
    this.markModified();
  }

  /**
   * Line leader length (for dimension lines).
   */
  get leaderLength(): number {
    const ll = this.dict.getNumber("LL", this.registry.resolve.bind(this.registry));

    return ll?.value ?? 0;
  }

  /**
   * Line leader line extension.
   */
  get leaderExtension(): number {
    const lle = this.dict.getNumber("LLE", this.registry.resolve.bind(this.registry));

    return lle?.value ?? 0;
  }

  /**
   * Caption flag - whether to show caption with the line.
   */
  get hasCaption(): boolean {
    const cap = this.dict.getBool("Cap", this.registry.resolve.bind(this.registry));

    return cap?.value ?? false;
  }

  /**
   * Line width from border style.
   */
  get lineWidth(): number {
    const bs = this.getBorderStyle();

    return bs?.width ?? 1;
  }
}
