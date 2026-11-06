import type { RefResolver } from "#src/helpers/types";
import type { ByteWriter } from "#src/io/byte-writer";

import type { PdfArray } from "./pdf-array";
import type { PdfBool } from "./pdf-bool";
import { PdfName } from "./pdf-name";
import type { PdfNumber } from "./pdf-number";
import type { PdfObject } from "./pdf-object";
import type { PdfPrimitive } from "./pdf-primitive";
import { PdfRef } from "./pdf-ref";
import type { PdfString } from "./pdf-string";

/**
 * PDF dictionary object (mutable).
 *
 * In PDF: `<< /Type /Page /MediaBox [0 0 612 792] >>`
 *
 * Keys are always PdfName. Tracks modifications via a dirty flag
 * for incremental save support.
 */
export class PdfDict implements PdfPrimitive {
  get type(): "dict" | "stream" {
    return "dict";
  }

  private entries = new Map<PdfName, PdfObject>();

  /**
   * Dirty flag for modification tracking.
   * Set to true when the dict is mutated, cleared after save.
   */
  dirty = false;

  constructor(entries?: Iterable<[PdfName | string, PdfObject]>) {
    if (entries) {
      for (const [key, value] of entries) {
        const name = typeof key === "string" ? PdfName.of(key) : key;

        this.entries.set(name, value);
      }
    }
  }

  /**
   * Clear the dirty flag. Called after saving.
   */
  clearDirty(): void {
    this.dirty = false;
  }

  get size(): number {
    return this.entries.size;
  }

  /**
   * Get value for key. Key can be string or PdfName.
   */
  get(key: PdfName | string, resolver?: RefResolver): PdfObject | undefined {
    const name = typeof key === "string" ? PdfName.of(key) : key;

    const value = this.entries.get(name);

    if (resolver && value?.type === "ref") {
      return resolver(value) ?? undefined;
    }

    return value;
  }

  /**
   * Set value for key. Key can be string or PdfName.
   */
  set(key: PdfName | string, value: PdfObject): void {
    const name = typeof key === "string" ? PdfName.of(key) : key;

    this.entries.set(name, value);
    this.dirty = true;
  }

  /**
   * Check if key exists.
   */
  has(key: PdfName | string): boolean {
    const name = typeof key === "string" ? PdfName.of(key) : key;

    return this.entries.has(name);
  }

  /**
   * Delete key. Returns true if key existed.
   */
  delete(key: PdfName | string): boolean {
    const name = typeof key === "string" ? PdfName.of(key) : key;
    const existed = this.entries.delete(name);

    if (existed) {
      this.dirty = true;
    }

    return existed;
  }

  /**
   * Iterate over keys.
   */
  keys(): Iterable<PdfName> {
    return this.entries.keys();
  }

  /**
   * Iterate over entries.
   */
  *[Symbol.iterator](): Iterator<[PdfName, PdfObject]> {
    yield* this.entries;
  }

  /**
   * Typed getters.
   *
   * All typed getters accept an optional resolver function. When provided,
   * if the value is a PdfRef, it will be automatically dereferenced.
   * This prevents the common bug of forgetting to handle indirect references.
   */

  getName(key: string, resolver?: RefResolver): PdfName | undefined {
    const value = this.get(key, resolver);

    return value?.type === "name" ? value : undefined;
  }

  getNumber(key: string, resolver?: RefResolver): PdfNumber | undefined {
    const value = this.get(key, resolver);

    return value?.type === "number" ? value : undefined;
  }

  getString(key: string, resolver?: RefResolver): PdfString | undefined {
    const value = this.get(key, resolver);

    return value?.type === "string" ? value : undefined;
  }

  getArray(key: string, resolver?: RefResolver): PdfArray | undefined {
    const value = this.get(key, resolver);

    return value?.type === "array" ? value : undefined;
  }

  getDict(key: string, resolver?: RefResolver): PdfDict | undefined {
    const value = this.get(key, resolver);

    return value?.type === "dict" ? value : undefined;
  }

  getRef(key: string): PdfRef | undefined {
    const value = this.get(key);

    return value?.type === "ref" ? value : undefined;
  }

  getBool(key: string, resolver?: RefResolver): PdfBool | undefined {
    const value = this.get(key, resolver);

    return value?.type === "bool" ? value : undefined;
  }

  /**
   * Create a shallow clone of this dictionary.
   * Values are shared, not deep-copied.
   */
  clone(): PdfDict {
    const cloned = new PdfDict();

    for (const [key, value] of this.entries) {
      cloned.entries.set(key, value);
    }

    return cloned;
  }

  /**
   * Create dict from entries.
   */
  static of(entries: Record<string, PdfObject>): PdfDict {
    return new PdfDict(Object.entries(entries));
  }

  toBytes(writer: ByteWriter): void {
    writer.writeAscii("<<\n");

    for (const [key, value] of this.entries) {
      // Skip null/undefined values silently (lenient serialization)
      if (value == null) {
        continue;
      }

      // Write key (PdfName implements toBytes)
      key.toBytes(writer);
      writer.writeAscii(" ");

      // Write value (each type in PdfObject union implements PdfPrimitive)
      value.toBytes(writer);
      writer.writeAscii("\n");
    }

    writer.writeAscii(">>");
  }
}
