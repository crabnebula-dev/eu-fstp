/**
 * XRef section writing for PDF files.
 *
 * Supports both traditional xref tables (PDF 1.0+) and
 * xref streams (PDF 1.5+).
 */

import { SINGLE_BYTE_MASK } from "#src/helpers/chars";
import type { ByteWriter } from "#src/io/byte-writer";
import { PdfArray } from "#src/objects/pdf-array";
import { PdfDict } from "#src/objects/pdf-dict";
import { PdfName } from "#src/objects/pdf-name";
import { PdfNumber } from "#src/objects/pdf-number";
import type { PdfObject } from "#src/objects/pdf-object";
import { PdfRef } from "#src/objects/pdf-ref";
import { PdfStream } from "#src/objects/pdf-stream";
import { PdfString } from "#src/objects/pdf-string";

/**
 * Represents an entry in the xref section.
 */
export interface XRefWriteEntry {
  /** The object number */
  objectNumber: number;

  /** The generation number */
  generation: number;

  /** Entry type */
  type: "inuse" | "free" | "compressed";

  /** For inuse: byte offset. For compressed: object stream number */
  offset: number;

  /** For compressed: index within object stream */
  index?: number;
}

/**
 * Options for writing xref sections.
 */
export interface XRefWriteOptions {
  /** Byte offset where the xref section starts */
  xrefOffset: number;

  /** Maximum object number + 1 (for /Size) */
  size: number;

  /** Object entries to include */
  entries: XRefWriteEntry[];

  /** Previous xref offset (for /Prev in incremental updates) */
  prev?: number;

  /** Root catalog reference */
  root: PdfRef;

  /** Info dictionary reference (optional) */
  info?: PdfRef;

  /** Encrypt dictionary reference (optional) */
  encrypt?: PdfRef;

  /** Document ID array (optional) */
  id?: [Uint8Array, Uint8Array];
}

/**
 * Group consecutive object numbers into subsections.
 *
 * For example: [1, 2, 3, 7, 8] → [[1, 3], [7, 2]] (start, count pairs)
 */
function groupIntoSubsections(
  entries: XRefWriteEntry[],
): { start: number; entries: XRefWriteEntry[] }[] {
  if (entries.length === 0) {
    return [];
  }

  // Sort by object number
  const sorted = [...entries].sort((a, b) => a.objectNumber - b.objectNumber);

  const subsections: { start: number; entries: XRefWriteEntry[] }[] = [];
  let current: { start: number; entries: XRefWriteEntry[] } | null = null;

  for (const entry of sorted) {
    if (current === null) {
      current = { start: entry.objectNumber, entries: [entry] };
    } else if (entry.objectNumber === current.start + current.entries.length) {
      // Consecutive - add to current subsection
      current.entries.push(entry);
    } else {
      // Gap - start new subsection
      subsections.push(current);
      current = { start: entry.objectNumber, entries: [entry] };
    }
  }

  if (current !== null) {
    subsections.push(current);
  }

  return subsections;
}

/**
 * Write a traditional xref table to the provided ByteWriter.
 *
 * Format:
 * ```
 * xref
 * 0 1
 * 0000000000 65535 f
 * 5 2
 * 0000012345 00000 n
 * 0000012567 00000 n
 * trailer
 * << /Size 7 /Root 1 0 R >>
 * startxref
 * 12345
 * %%EOF
 * ```
 */
export function writeXRefTable(writer: ByteWriter, options: XRefWriteOptions): void {
  // xref keyword
  writer.writeAscii("xref\n");

  // Group into subsections
  const subsections = groupIntoSubsections(options.entries);

  for (const subsection of subsections) {
    // Subsection header: start count
    writer.writeAscii(`${subsection.start} ${subsection.entries.length}\n`);

    // Entries (each is exactly 20 bytes)
    for (const entry of subsection.entries) {
      const line = formatXRefTableEntry(entry);
      writer.writeAscii(line);
    }
  }

  // Trailer
  writer.writeAscii("trailer\n");
  const trailerDict = buildTrailerDict(options);
  trailerDict.toBytes(writer);
  writer.writeAscii("\n");

  // startxref
  writer.writeAscii("startxref\n");
  writer.writeAscii(`${options.xrefOffset}\n`);
  writer.writeAscii("%%EOF\n");
}

/**
 * Format a single xref table entry (exactly 20 bytes).
 *
 * Format: "OOOOOOOOOO GGGGG n\r\n" or "OOOOOOOOOO GGGGG f\r\n"
 */
function formatXRefTableEntry(entry: XRefWriteEntry): string {
  const offset = entry.offset.toString().padStart(10, "0");
  const generation = entry.generation.toString().padStart(5, "0");
  const marker = entry.type === "free" ? "f" : "n";

  // PDF spec requires \r\n for xref entries
  return `${offset} ${generation} ${marker}\r\n`;
}

/**
 * Build the trailer dictionary.
 */
function buildTrailerDict(options: XRefWriteOptions): PdfDict {
  const entries: [string, PdfObject][] = [
    ["Size", PdfNumber.of(options.size)],
    ["Root", options.root],
  ];

  if (options.prev !== undefined) {
    entries.push(["Prev", PdfNumber.of(options.prev)]);
  }

  if (options.info) {
    entries.push(["Info", options.info]);
  }

  if (options.encrypt) {
    entries.push(["Encrypt", options.encrypt]);
  }

  if (options.id) {
    const [id1, id2] = options.id;
    entries.push(["ID", PdfArray.of(new PdfString(id1, "hex"), new PdfString(id2, "hex"))]);
  }

  return new PdfDict(entries);
}

/**
 * Calculate field widths for xref stream encoding.
 *
 * Returns [typeWidth, offsetWidth, generationWidth]
 */
function calculateFieldWidths(entries: XRefWriteEntry[]): [number, number, number] {
  let maxOffset = 0;
  let maxGeneration = 0;

  for (const entry of entries) {
    maxOffset = Math.max(maxOffset, entry.offset);

    if (entry.type === "compressed" && entry.index !== undefined) {
      maxGeneration = Math.max(maxGeneration, entry.index);
    } else {
      maxGeneration = Math.max(maxGeneration, entry.generation);
    }
  }

  // Type field is always 1 byte (values 0, 1, or 2)
  const typeWidth = 1;

  // Calculate bytes needed for offset
  const offsetWidth = maxOffset === 0 ? 1 : Math.ceil(Math.log2(maxOffset + 1) / 8);

  // Calculate bytes needed for generation/index
  const generationWidth = maxGeneration === 0 ? 1 : Math.ceil(Math.log2(maxGeneration + 1) / 8);

  // Ensure at least 1 byte for each field
  return [typeWidth, Math.max(1, offsetWidth), Math.max(1, generationWidth)];
}

/**
 * Encode a number as big-endian bytes.
 */
function encodeNumber(value: number, width: number): Uint8Array {
  const bytes = new Uint8Array(width);

  for (let i = width - 1; i >= 0; i--) {
    bytes[i] = value & SINGLE_BYTE_MASK;
    value = Math.floor(value / 256);
  }

  return bytes;
}

/**
 * Encode xref entries as binary stream data.
 */
function encodeXRefStreamData(
  entries: XRefWriteEntry[],
  widths: [number, number, number],
): Uint8Array {
  const [w1, w2, w3] = widths;
  const entrySize = w1 + w2 + w3;
  const data = new Uint8Array(entries.length * entrySize);

  let offset = 0;

  for (const entry of entries) {
    // Type field
    let type: number;

    if (entry.type === "free") {
      type = 0;
    } else if (entry.type === "inuse") {
      type = 1;
    } else {
      type = 2;
    }

    data.set(encodeNumber(type, w1), offset);
    offset += w1;

    // Offset/object number field
    data.set(encodeNumber(entry.offset, w2), offset);
    offset += w2;

    // Generation/index field
    const field3 =
      entry.type === "compressed" && entry.index !== undefined ? entry.index : entry.generation;

    data.set(encodeNumber(field3, w3), offset);
    offset += w3;
  }

  return data;
}

/**
 * Build the /Index array for xref stream.
 *
 * Format: [start1 count1 start2 count2 ...]
 */
function buildIndexArray(subsections: { start: number; entries: XRefWriteEntry[] }[]): PdfArray {
  const items: PdfObject[] = [];

  for (const sub of subsections) {
    items.push(PdfNumber.of(sub.start));
    items.push(PdfNumber.of(sub.entries.length));
  }

  return new PdfArray(items);
}

/**
 * Write an xref stream (PDF 1.5+) to the provided ByteWriter.
 *
 * The caller is responsible for:
 * - Including an entry for the xref stream object itself in `entries`
 * - Computing the correct `/Size` value (max object number + 1, across all sections for incremental updates)
 *
 * Returns the stream object for reference.
 */
export function writeXRefStream(
  writer: ByteWriter,
  options: XRefWriteOptions & { streamObjectNumber: number },
): PdfStream {
  // Group into subsections (sorted)
  const subsections = groupIntoSubsections(options.entries);

  // Flatten entries in subsection order
  const orderedEntries = subsections.flatMap(s => s.entries);

  // Calculate field widths
  const widths = calculateFieldWidths(orderedEntries);

  // Encode binary data
  const data = encodeXRefStreamData(orderedEntries, widths);

  // Build stream dictionary
  const dictEntries: [string, PdfObject][] = [
    ["Type", PdfName.of("XRef")],
    ["Size", PdfNumber.of(options.size)],
    ["W", PdfArray.of(...widths.map(w => PdfNumber.of(w)))],
  ];

  // Add Index if not default (0 to size-1)
  if (subsections.length !== 1 || subsections[0].start !== 0) {
    dictEntries.push(["Index", buildIndexArray(subsections)]);
  }

  if (options.prev !== undefined) {
    dictEntries.push(["Prev", PdfNumber.of(options.prev)]);
  }

  dictEntries.push(["Root", options.root]);

  if (options.info) {
    dictEntries.push(["Info", options.info]);
  }

  if (options.encrypt) {
    dictEntries.push(["Encrypt", options.encrypt]);
  }

  if (options.id) {
    const [id1, id2] = options.id;
    dictEntries.push(["ID", PdfArray.of(new PdfString(id1, "hex"), new PdfString(id2, "hex"))]);
  }

  const stream = new PdfStream(dictEntries, data);

  // Write the indirect object
  const ref = PdfRef.of(options.streamObjectNumber, 0);
  writer.writeAscii(`${ref.objectNumber} ${ref.generation} obj\n`);
  stream.toBytes(writer);
  writer.writeAscii("\nendobj\n");

  // Write footer
  writer.writeAscii("startxref\n");
  writer.writeAscii(`${options.xrefOffset}\n`);
  writer.writeAscii("%%EOF\n");

  return stream;
}
