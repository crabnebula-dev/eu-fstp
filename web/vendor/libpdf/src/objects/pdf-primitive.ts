/**
 * Interface for PDF primitive objects that can serialize themselves.
 *
 * Each concrete PDF object class (PdfNull, PdfBool, etc.) implements this
 * interface, allowing them to write their own byte representation to a
 * ByteWriter.
 *
 * This design moves serialization logic from a central switch/instanceof chain
 * into the objects themselves, following the "objects know how to serialize
 * themselves" principle.
 */

import type { ByteWriter } from "#src/io/byte-writer";

export interface PdfPrimitive {
  /**
   * The type discriminator for this object.
   * Used for type guards and pattern matching.
   */
  readonly type: string;

  /**
   * Write this object's PDF byte representation to the given ByteWriter.
   *
   * Called recursively for nested objects (arrays, dicts, streams).
   * Implementations should write valid PDF syntax.
   *
   * @param writer - The ByteWriter to write bytes to
   */
  toBytes(writer: ByteWriter): void;
}
