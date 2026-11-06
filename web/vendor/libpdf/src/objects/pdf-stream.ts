import type { ByteWriter } from "../io/byte-writer.js";
import { RefusedError } from "../parser/errors.js";

import { PdfDict } from "./pdf-dict.js";
import type { PdfName } from "./pdf-name.js";
import type { PdfObject } from "./pdf-object.js";

/**
 * PDF stream object (dictionary + binary data).
 *
 * In PDF:
 * ```
 * << /Length 5 /Filter /FlateDecode >>
 * stream
 * ...binary data...
 * endstream
 * ```
 *
 * Extends PdfDict with attached data.
 *
 * ## Data State
 *
 * The `_data` field can contain either encoded (compressed) or decoded
 * (uncompressed) bytes, depending on how the stream was created:
 *
 * - **After parsing**: `_data` contains the raw bytes from the PDF file,
 *   which are typically encoded/compressed. Use `getDecodedData()` to
 *   decompress them.
 *
 * - **After setData()**: `_data` contains uncompressed bytes. The /Filter
 *   entries are cleared. The stream will be written as-is (or re-compressed
 *   if `compressStreams` is enabled during save).
 *
 * This asymmetry is intentional for efficiency (avoid decompressing during
 * parse if not needed) but users should be aware of it.
 */
export class PdfStream extends PdfDict {
  override get type(): "stream" {
    return "stream";
  }

  private _data: Uint8Array;

  /**
   * Create a new PdfStream.
   *
   * @param dict - Either a PdfDict to copy entries from, or an iterable of
   *               [key, value] pairs. When passing a PdfDict, all its entries
   *               are copied to the new stream.
   * @param data - The stream data (default: empty). After parsing, this is
   *               the raw (possibly encoded) bytes. After setData(), this is
   *               the decoded bytes.
   */
  constructor(
    dict?: PdfDict | Iterable<[PdfName | string, PdfObject]>,
    data: Uint8Array = new Uint8Array(0),
  ) {
    // PdfDict's [Symbol.iterator] yields [PdfName, PdfObject] pairs,
    // so we can pass it directly to super() when dict is a PdfDict.
    // The super constructor will iterate over the entries.
    super(dict);

    this._data = data;
  }

  /**
   * The raw (possibly compressed) stream data.
   */
  get data(): Uint8Array {
    return this._data;
  }

  /**
   * Set new stream content (decoded/uncompressed).
   *
   * Clears any existing filters since the data is now uncompressed.
   * Compression will be applied at write time if `compressStreams` is enabled.
   */
  setData(value: Uint8Array): void {
    // Clear filters - the new data is uncompressed
    this.delete("Filter");
    this.delete("DecodeParms");
    this._data = value;
    this.dirty = true;
  }

  /**
   * Create stream from dict entries and data.
   */
  static fromDict(
    entries: Record<string, PdfObject>,
    data: Uint8Array = new Uint8Array(0),
  ): PdfStream {
    return new PdfStream(Object.entries(entries), data);
  }

  /**
   * Get the decoded stream data.
   *
   * FSTP (ADR-016): the filters module is not built. An unfiltered stream
   * returns its bytes; a filtered one is refused with a typed error.
   *
   * @returns The stream bytes
   * @throws {RefusedError} if the stream has a /Filter
   */
  getDecodedData(): Uint8Array {
    if (this.has("Filter")) {
      throw new RefusedError("filter", "filtered streams are not decoded");
    }

    return this._data;
  }

  /**
   * Get the encoded stream data.
   *
   * FSTP (ADR-016): the filters module is not built, so only unfiltered
   * streams have encoded data.
   *
   * @returns The stream bytes
   * @throws {RefusedError} if the stream has a /Filter
   */
  getEncodedData(): Uint8Array {
    if (this.has("Filter")) {
      throw new RefusedError("filter", "filtered streams are not encoded");
    }

    return this._data;
  }

  /**
   * Write stream to bytes.
   *
   * Streams consist of:
   * 1. Dictionary (with /Length entry)
   * 2. "stream" keyword followed by newline
   * 3. Raw stream data
   * 4. Newline followed by "endstream" keyword
   */
  override toBytes(writer: ByteWriter): void {
    // Write dictionary with /Length first
    writer.writeAscii("<<\n");

    // Always write /Length as direct value
    writer.writeAscii(`/Length ${this._data.length}`);

    // Write other entries (skip /Length if present, we already wrote it)
    for (const [key, value] of this) {
      if (key.value === "Length") {
        continue;
      }

      // Skip null/undefined values silently
      if (value == null) {
        continue;
      }

      key.toBytes(writer);
      writer.writeAscii(" ");
      value.toBytes(writer);
      writer.writeAscii("\n");
    }

    writer.writeAscii(">>");

    // Per PDF spec, stream keyword followed by single newline (or CRLF)
    // endstream preceded by newline
    writer.writeAscii("\nstream\n");
    writer.writeBytes(this._data);
    writer.writeAscii("\nendstream");
  }
}
