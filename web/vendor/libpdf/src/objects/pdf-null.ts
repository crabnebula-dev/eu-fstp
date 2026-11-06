import type { ByteWriter } from "../io/byte-writer.js";

import type { PdfPrimitive } from "./pdf-primitive.js";

/**
 * PDF null object - a singleton representing the null value.
 *
 * In PDF: `null`
 */
export class PdfNull implements PdfPrimitive {
  static readonly instance = new PdfNull();

  get type(): "null" {
    return "null";
  }

  private constructor() {}

  toBytes(writer: ByteWriter): void {
    writer.writeAscii("null");
  }
}
