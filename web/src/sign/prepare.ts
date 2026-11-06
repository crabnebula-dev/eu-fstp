// Prepares one incremental revision for a party's signature (ADR-016,
// M5 design section 3.1 step 3). It sets the party's field value to a new
// signature dictionary with `/ByteRange` and `/Contents` placeholders,
// saves incrementally, patches `/ByteRange` and returns only the appended
// bytes. No hashing, no signing, no font work and no DOM. The server
// concatenates the increment with its stored revision and verifies it
// (step 4), so nothing here is trusted.

import { ObjectRegistry } from "../../vendor/libpdf/src/document/object-registry.js";
import { Scanner } from "../../vendor/libpdf/src/io/scanner.js";
import { PdfArray } from "../../vendor/libpdf/src/objects/pdf-array.js";
import { PdfDict } from "../../vendor/libpdf/src/objects/pdf-dict.js";
import { PdfName } from "../../vendor/libpdf/src/objects/pdf-name.js";
import { PdfRef } from "../../vendor/libpdf/src/objects/pdf-ref.js";
import { PdfString } from "../../vendor/libpdf/src/objects/pdf-string.js";
import { DocumentParser } from "../../vendor/libpdf/src/parser/document-parser.js";
import { LIMITS } from "../../vendor/libpdf/src/parser/limits.js";
import { XRefParser } from "../../vendor/libpdf/src/parser/xref-parser.js";
import {
  calculateByteRange,
  createByteRangePlaceholderObject,
  createContentsPlaceholderObject,
  findPlaceholders,
  patchByteRange,
} from "../../vendor/libpdf/src/signatures/placeholder.js";
import { writeIncremental } from "../../vendor/libpdf/src/writer/pdf-writer.js";
import { type Refusal, guarded, refuse } from "./errors.js";
import { signatureFields } from "./fields.js";
import { loadEveryObject } from "./parse.js";

/** Smallest `/Contents` placeholder, in bytes of signature. */
export const CONTENTS_BYTES_MIN = 1024;
/** Largest `/Contents` placeholder, in bytes of signature. */
export const CONTENTS_BYTES_MAX = 32768;
/** Longest party field name, in UTF-16 code units. */
export const FIELD_NAME_MAX = 256;

/** One preparation request. */
export interface PrepareRequest {
  /** The `/T` name of the party's signature field. */
  readonly field: string;
  /** The `/Contents` placeholder size, in bytes of signature. */
  readonly contentsBytes: number;
}

/** A prepared increment: the appended bytes and the patched `/ByteRange`. */
export interface Prepared {
  readonly ok: true;
  readonly increment: Uint8Array;
  readonly byteRange: readonly [number, number, number, number];
}

function requestRefusal(request: PrepareRequest): Refusal | null {
  const f = request.field;
  if (typeof f !== "string" || f.length === 0 || f.length > FIELD_NAME_MAX || /[\u0000-\u001f\u007f]/.test(f)) {
    return refuse("request", "the field name is not 1 to 256 printable characters");
  }
  const n = request.contentsBytes;
  if (!Number.isSafeInteger(n) || n < CONTENTS_BYTES_MIN || n > CONTENTS_BYTES_MAX) {
    return refuse("request", `the placeholder size is not an integer from ${CONTENTS_BYTES_MIN} to ${CONTENTS_BYTES_MAX}`);
  }
  return null;
}

/** The two byte strings of a trailer `/ID`, null when absent, or a refusal for any other `/ID`. */
function fileId(trailer: PdfDict): [Uint8Array, Uint8Array] | null | Refusal {
  if (!trailer.has("ID")) {
    return null;
  }
  const id = trailer.get("ID");
  const a = id instanceof PdfArray ? id.at(0) : undefined;
  const b = id instanceof PdfArray ? id.at(1) : undefined;
  if (!(id instanceof PdfArray) || id.length !== 2 || !(a instanceof PdfString) || !(b instanceof PdfString)) {
    return refuse("malformed", "the trailer /ID is not two strings");
  }
  return [a.bytes, b.bytes];
}

/** Prepares the increment that signs `request.field` of `revision`. Never changes `revision`. */
export function prepareSignature(revision: Uint8Array, request: PrepareRequest): Prepared | Refusal {
  const bad = requestRefusal(request);
  if (bad !== null) {
    return bad;
  }
  if (revision.length > LIMITS.maxFileBytes) {
    return refuse("limit", `a file of ${revision.length} bytes`);
  }
  return guarded((): Prepared | Refusal => {
    const scanner = new Scanner(revision);
    const doc = new DocumentParser(scanner).parse();
    // The whole revision is read, so an object stream, a filter or a
    // malformed object anywhere refuses it, not only on the field's path.
    loadEveryObject(doc);
    const trailer = doc.trailer;
    const root = trailer.getRef("Root");
    const id = fileId(trailer);
    if (id !== null && !Array.isArray(id)) {
      return id;
    }
    const size = trailer.getNumber("Size")?.value;
    if (root === undefined || size === undefined || !Number.isSafeInteger(size) || size < 1 || size >= LIMITS.maxObjects) {
      return refuse("malformed", "the trailer has no /Root or no valid /Size");
    }
    for (const num of doc.xref.keys()) {
      if (num >= size) {
        return refuse("malformed", `object ${num} is at or beyond /Size ${size}`);
      }
    }
    const registry = new ObjectRegistry(doc.xref);
    registry.setResolver(doc.getObject);
    const catalog = registry.resolve(root);
    if (!(catalog instanceof PdfDict)) {
      return refuse("malformed", "no catalog");
    }
    const all = signatureFields(catalog, (ref) => registry.resolve(ref));
    const mine = all.filter((f) => f.name === request.field);
    const field = mine[0];
    if (field === undefined) {
      return refuse("no-field", "no signature field has that name");
    }
    if (mine.length > 1 || new Set(all.map((f) => f.ref.objectNumber)).size !== all.length) {
      return refuse("malformed", "a field name or field object appears twice");
    }
    if (field.signed) {
      return refuse("field-signed", "the field already has a value");
    }
    // A reference at or beyond /Size would move the new object number.
    if (registry.nextObjectNumber > size) {
      return refuse("malformed", "a reference names an object at or beyond /Size");
    }

    const sig = new PdfDict([
      ["Type", PdfName.of("Sig")],
      ["Filter", PdfName.of("Adobe.PPKLite")],
      ["SubFilter", PdfName.of("ETSI.CAdES.detached")],
      ["ByteRange", createByteRangePlaceholderObject()],
      ["Contents", createContentsPlaceholderObject(request.contentsBytes)],
    ]);
    const sigRef = PdfRef.of(size, 0);
    registry.registerAt(sigRef, sig);
    field.dict.set("V", sigRef);

    const info = trailer.getRef("Info");
    const written = writeIncremental(registry, {
      root,
      originalBytes: revision,
      originalXRefOffset: new XRefParser(scanner).findStartXRef(),
      ...(info === undefined ? {} : { info }),
      ...(id === null ? {} : { id }),
    });
    const bytes = written.bytes;
    const at = findPlaceholders(bytes, revision.length);
    const range = calculateByteRange(bytes, at);
    patchByteRange(bytes, at, range);
    return {
      ok: true,
      increment: bytes.slice(revision.length),
      byteRange: [range.offset1, range.length1, range.offset2, range.length2],
    };
  });
}

/** The Worker's reply to one message. */
export type Reply =
  | { readonly ok: true; readonly increment: ArrayBuffer; readonly byteRange: readonly number[] }
  | Refusal;

const MESSAGE_KEYS = ["contentsBytes", "field", "revision"];

/**
 * Handles one Worker message `{ revision, field, contentsBytes }`, where
 * `revision` is an ArrayBuffer of the current revision. Any other shape
 * is refused with `request`.
 */
export function handleMessage(data: unknown): Reply {
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    return refuse("request", "the message is not an object");
  }
  const keys = Object.keys(data).sort();
  if (keys.length !== MESSAGE_KEYS.length || keys.some((k, i) => k !== MESSAGE_KEYS[i])) {
    return refuse("request", "the message has other members than revision, field and contentsBytes");
  }
  const m = data as { revision: unknown; field: unknown; contentsBytes: unknown };
  if (!(m.revision instanceof ArrayBuffer) || typeof m.field !== "string" || typeof m.contentsBytes !== "number") {
    return refuse("request", "the message members have the wrong types");
  }
  const out = prepareSignature(new Uint8Array(m.revision), { field: m.field, contentsBytes: m.contentsBytes });
  if (!out.ok) {
    return out;
  }
  return { ok: true, increment: out.increment.slice().buffer, byteRange: [...out.byteRange] };
}
