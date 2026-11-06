// Entry points of the vendored LibPDF parser for the ADR-016 fuzz targets
// pdf_token, pdf_xref and pdf_document. Each returns a summary or a typed
// refusal; any other error is a defect and propagates.

import { Scanner } from "../../vendor/libpdf/src/io/scanner.js";
import { PdfArray } from "../../vendor/libpdf/src/objects/pdf-array.js";
import { PdfDict } from "../../vendor/libpdf/src/objects/pdf-dict.js";
import type { PdfObject } from "../../vendor/libpdf/src/objects/pdf-object.js";
import { PdfRef } from "../../vendor/libpdf/src/objects/pdf-ref.js";
import { DocumentParser, type ParsedDocument } from "../../vendor/libpdf/src/parser/document-parser.js";
import { LIMITS } from "../../vendor/libpdf/src/parser/limits.js";
import { ObjectParser } from "../../vendor/libpdf/src/parser/object-parser.js";
import { TokenReader } from "../../vendor/libpdf/src/parser/token-reader.js";
import { XRefParser } from "../../vendor/libpdf/src/parser/xref-parser.js";
import { type Refusal, guarded, refuse } from "./errors.js";
import { signatureFields } from "./fields.js";

export { LIMITS };

export type Outcome<T> = { readonly ok: true; readonly value: T } | Refusal;

function ok<T>(value: T): Outcome<T> {
  return { ok: true, value };
}

/** The nesting depth of `obj`, the outer object counting 1. */
function depthOf(obj: PdfObject): number {
  let deepest = 0;
  const stack: { o: PdfObject; d: number }[] = [{ o: obj, d: 1 }];
  for (let top = stack.pop(); top !== undefined; top = stack.pop()) {
    deepest = Math.max(deepest, top.d);
    if (top.o instanceof PdfArray) {
      for (const v of top.o.toArray()) {
        stack.push({ o: v, d: top.d + 1 });
      }
    } else if (top.o instanceof PdfDict) {
      for (const [, v] of top.o) {
        stack.push({ o: v, d: top.d + 1 });
      }
    }
  }
  return deepest;
}

function sizeRefusal(bytes: Uint8Array): Refusal | null {
  return bytes.length > LIMITS.maxFileBytes ? refuse("limit", `a file of ${bytes.length} bytes`) : null;
}

/** pdf_token: one object from the start of `bytes`. */
export function parseObjectBytes(bytes: Uint8Array): Outcome<{ depth: number; kind: string }> {
  return sizeRefusal(bytes) ?? guarded(() => {
    const parsed = new ObjectParser(new TokenReader(new Scanner(bytes))).parseObject();
    if (parsed === null) {
      return refuse("malformed", "no object");
    }
    return ok({ depth: depthOf(parsed.object), kind: parsed.object.type });
  });
}

/** pdf_xref: the cross-reference chain from `startxref`, through `/Prev`. */
export function parseXRefBytes(bytes: Uint8Array): Outcome<{ sections: number; entries: number }> {
  return sizeRefusal(bytes) ?? guarded(() => {
    const scanner = new Scanner(bytes);
    const xref = new XRefParser(scanner);
    const chain = new DocumentParser(scanner).parseXRefChain(xref, xref.findStartXRef());
    return ok({ sections: chain.sections, entries: chain.xref.size });
  });
}

/**
 * Loads every in-use object of `doc` and returns how many there are, so
 * a malformed or refused object anywhere in the file refuses the file.
 */
export function loadEveryObject(doc: ParsedDocument): number {
  let objects = 0;
  for (const [num, entry] of doc.xref) {
    if (entry.type === "free") {
      continue;
    }
    const generation = entry.type === "uncompressed" ? entry.generation : 0;
    if (doc.getObject(PdfRef.of(num, generation)) !== null) {
      objects += 1;
    }
  }
  return objects;
}

/** pdf_document: the whole document, with every in-use object loaded. */
export function parseDocumentBytes(
  bytes: Uint8Array,
): Outcome<{ objects: number; sections: number; fields: { name: string; objectNumber: number; signed: boolean }[] }> {
  return sizeRefusal(bytes) ?? guarded(() => {
    const doc = new DocumentParser(new Scanner(bytes)).parse();
    const objects = loadEveryObject(doc);
    const catalog = doc.getCatalog();
    if (catalog === null) {
      return refuse("malformed", "no catalog");
    }
    const fields = signatureFields(catalog, doc.getObject).map((f) => ({
      name: f.name,
      objectNumber: f.ref.objectNumber,
      signed: f.signed,
    }));
    return ok({ objects, sections: doc.sections, fields });
  });
}
