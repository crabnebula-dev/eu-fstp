/**
 * PDF file writer.
 *
 * FSTP (ADR-016): incremental save only (append only changed objects).
 * The full save, stream compression, encryption and xref streams are
 * removed, so the writer needs neither the filters nor the security
 * module.
 *
 * Uses a single ByteWriter for the entire PDF to minimize allocations.
 */

import { clearAllDirtyFlags, collectChanges } from "../document/change-collector.js";
import type { ObjectRegistry } from "../document/object-registry.js";
import { CR, LF } from "../helpers/chars.js";
import { ByteWriter } from "../io/byte-writer.js";
import type { PdfObject } from "../objects/pdf-object.js";
import type { PdfRef } from "../objects/pdf-ref.js";

import { writeXRefTable, type XRefWriteEntry } from "./xref-writer.js";

/**
 * Options for PDF writing.
 */
export interface WriteOptions {
  /** Root catalog reference */
  root: PdfRef;

  /** Info dictionary reference (optional) */
  info?: PdfRef;

  /** Document ID (optional, two byte arrays, written unchanged) */
  id?: [Uint8Array, Uint8Array];
}

/**
 * Options for incremental save.
 */
export interface IncrementalWriteOptions extends WriteOptions {
  /** Original PDF bytes */
  originalBytes: Uint8Array;

  /** Offset of the original xref */
  originalXRefOffset: number;
}

/**
 * Result of a write operation.
 */
export interface WriteResult {
  /** The written PDF bytes */
  bytes: Uint8Array;

  /** Byte offset where the xref section starts */
  xrefOffset: number;
}

/**
 * Write an indirect object to the ByteWriter.
 *
 * Format: "N G obj\n[object]\nendobj\n"
 */
function writeIndirectObject(writer: ByteWriter, ref: PdfRef, obj: PdfObject): void {
  writer.writeAscii(`${ref.objectNumber} ${ref.generation} obj\n`);
  obj.toBytes(writer);
  writer.writeAscii("\nendobj\n");
}

/**
 * Write an incremental update to a PDF.
 *
 * Appends only the changed/new objects to the original PDF bytes,
 * preserving the original content exactly.
 *
 * Structure:
 * ```
 * [original PDF bytes]
 * [modified object 1]
 * [modified object 2]
 * ...
 * xref
 * ...
 * trailer
 * << ... /Prev [originalXRefOffset] >>
 * startxref
 * ...
 * %%EOF
 * ```
 */
export function writeIncremental(
  registry: ObjectRegistry,
  options: IncrementalWriteOptions,
): WriteResult {
  // Collect changes
  const changes = collectChanges(registry);

  // If no changes, return original (should caller handle this?)
  if (changes.modified.size === 0 && changes.created.size === 0) {
    return {
      bytes: options.originalBytes,
      xrefOffset: options.originalXRefOffset,
    };
  }

  // Initialize ByteWriter with original bytes
  const writer = new ByteWriter(options.originalBytes);

  // Ensure there's a newline before appended content
  const lastByte = options.originalBytes[options.originalBytes.length - 1];

  if (lastByte !== LF && lastByte !== CR) {
    writer.writeByte(0x0a); // newline
  }

  // Track offsets for new xref
  const offsets = new Map<number, { offset: number; generation: number }>();

  // Write modified objects
  // FSTP (ADR-016): objects are written as they are, with no compression
  // and no encryption.
  for (const [ref, obj] of changes.modified) {
    offsets.set(ref.objectNumber, {
      offset: writer.position,
      generation: ref.generation,
    });

    writeIndirectObject(writer, ref, obj);
  }

  // Write new objects
  for (const [ref, obj] of changes.created) {
    offsets.set(ref.objectNumber, {
      offset: writer.position,
      generation: ref.generation,
    });

    writeIndirectObject(writer, ref, obj);
  }

  // Record xref offset
  const xrefOffset = writer.position;

  // Build xref entries (only for changed objects)
  const entries: XRefWriteEntry[] = [];

  for (const [objNum, info] of offsets) {
    entries.push({
      objectNumber: objNum,
      generation: info.generation,
      type: "inuse",
      offset: info.offset,
    });
  }

  // Write xref section with /Prev pointer
  // FSTP (ADR-016): always a table; xref streams are not written.
  {
    // Size must cover all objects (original + new)
    const size = Math.max(changes.maxObjectNumber + 1, registry.nextObjectNumber);

    writeXRefTable(writer, {
      entries,
      size,
      xrefOffset,
      prev: options.originalXRefOffset,
      root: options.root,
      info: options.info,
      id: options.id,
    });
  }

  // Clear dirty flags and commit new objects
  clearAllDirtyFlags(registry);
  registry.commitNewObjects();

  return {
    bytes: writer.toBytes(),
    xrefOffset,
  };
}

/**
 * Utility to check if incremental save produced valid output.
 *
 * Verifies that:
 * 1. Original bytes are preserved exactly
 * 2. New content starts after original
 * 3. Basic structure is valid
 */
export function verifyIncrementalSave(
  original: Uint8Array,
  result: Uint8Array,
): { valid: boolean; error?: string } {
  // Result must be at least as long as original
  if (result.length < original.length) {
    return { valid: false, error: "Result shorter than original" };
  }

  // Original bytes must be preserved exactly
  for (let i = 0; i < original.length; i++) {
    if (result[i] !== original[i]) {
      return {
        valid: false,
        error: `Byte mismatch at offset ${i}: expected ${original[i]}, got ${result[i]}`,
      };
    }
  }

  // Check for %%EOF at end
  const tail = new TextDecoder().decode(result.slice(-10));

  if (!tail.includes("%%EOF")) {
    return { valid: false, error: "Missing %%EOF at end" };
  }

  return { valid: true };
}
