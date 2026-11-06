// The party signature fields of a revision (ADR-016, M5 design section
// 3.1 step 1: one empty signature field per party, declared by the
// server). Only top-level, indirect fields with `/FT /Sig` and a `/T`
// name count. A field with `/Kids` is not a candidate.

import { PdfArray } from "../../vendor/libpdf/src/objects/pdf-array.js";
import { PdfDict } from "../../vendor/libpdf/src/objects/pdf-dict.js";
import type { PdfObject } from "../../vendor/libpdf/src/objects/pdf-object.js";
import { PdfRef } from "../../vendor/libpdf/src/objects/pdf-ref.js";
import { PdfString } from "../../vendor/libpdf/src/objects/pdf-string.js";

/** One signature field. */
export interface SignatureField {
  readonly name: string;
  readonly ref: PdfRef;
  readonly dict: PdfDict;
  readonly signed: boolean;
}

/** Resolves an indirect reference, or gives null. */
export type Resolve = (ref: PdfRef) => PdfObject | null;

function direct(obj: PdfObject | undefined, resolve: Resolve): PdfObject | null {
  if (obj === undefined) {
    return null;
  }
  return obj instanceof PdfRef ? resolve(obj) : obj;
}

/** The signature fields of the catalog's `/AcroForm`, in `/Fields` order. */
export function signatureFields(catalog: PdfDict, resolve: Resolve): SignatureField[] {
  const form = direct(catalog.get("AcroForm"), resolve);
  if (!(form instanceof PdfDict)) {
    return [];
  }
  const fields = direct(form.get("Fields"), resolve);
  if (!(fields instanceof PdfArray)) {
    return [];
  }
  const out: SignatureField[] = [];
  for (const item of fields.toArray()) {
    if (!(item instanceof PdfRef)) {
      continue;
    }
    const dict = resolve(item);
    if (!(dict instanceof PdfDict) || dict.type !== "dict" || dict.has("Kids")) {
      continue;
    }
    const t = dict.get("T");
    if (dict.getName("FT")?.value !== "Sig" || !(t instanceof PdfString)) {
      continue;
    }
    out.push({ name: t.asString(), ref: item, dict, signed: dict.has("V") });
  }
  return out;
}
