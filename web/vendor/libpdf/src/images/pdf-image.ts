/**
 * PDFImage - Represents an embedded image in a PDF document.
 *
 * Created via `pdf.embedImage()`, `pdf.embedJpeg()`, or `pdf.embedPng()`.
 * Used with `page.drawImage()` to render images on pages.
 */

import type { PdfRef } from "#src/objects/pdf-ref";

/**
 * PDFImage represents an embedded image XObject.
 *
 * @example
 * ```typescript
 * const image = await pdf.embedImage(jpegBytes);
 * console.log(`Image size: ${image.width}x${image.height}`);
 *
 * page.drawImage(image, {
 *   x: 50,
 *   y: 500,
 *   width: 200,
 * });
 * ```
 */
export class PDFImage {
  /** Image width in pixels */
  readonly width: number;

  /** Image height in pixels */
  readonly height: number;

  /** Reference to the image XObject in the document */
  readonly ref: PdfRef;

  /**
   * Scale factor to convert pixels to points.
   * Default is 1 (1 pixel = 1 point).
   * For print-quality (300 DPI), use 72/300 = 0.24.
   */
  readonly scale: number;

  constructor(ref: PdfRef, width: number, height: number, scale = 1) {
    this.ref = ref;
    this.width = width;
    this.height = height;
    this.scale = scale;
  }

  /**
   * Width in points (pixels * scale).
   */
  get widthInPoints(): number {
    return this.width * this.scale;
  }

  /**
   * Height in points (pixels * scale).
   */
  get heightInPoints(): number {
    return this.height * this.scale;
  }

  /**
   * Aspect ratio (width / height).
   */
  get aspectRatio(): number {
    return this.width / this.height;
  }
}
