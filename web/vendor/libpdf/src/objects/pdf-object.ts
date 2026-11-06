/**
 * PDF object types and type guards.
 */
import type { PdfArray } from "./pdf-array";
import type { PdfBool } from "./pdf-bool";
import type { PdfDict } from "./pdf-dict";
import type { PdfName } from "./pdf-name";
import type { PdfNull } from "./pdf-null";
import type { PdfNumber } from "./pdf-number";
import type { PdfRaw } from "./pdf-raw";
import type { PdfRef } from "./pdf-ref";
import type { PdfStream } from "./pdf-stream";
import type { PdfString } from "./pdf-string";

/**
 * Union of all PDF object types.
 * All types have a `type` field for discrimination.
 */
export type PdfObject =
  | PdfNull
  | PdfBool
  | PdfNumber
  | PdfName
  | PdfString
  | PdfRef
  | PdfArray
  | PdfDict
  | PdfStream
  | PdfRaw;

// Type guards

export function isPdfNull(obj: PdfObject): obj is PdfNull {
  return obj.type === "null";
}

export function isPdfBool(obj: PdfObject): obj is PdfBool {
  return obj.type === "bool";
}

export function isPdfNumber(obj: PdfObject): obj is PdfNumber {
  return obj.type === "number";
}

export function isPdfName(obj: PdfObject): obj is PdfName {
  return obj.type === "name";
}

export function isPdfString(obj: PdfObject): obj is PdfString {
  return obj.type === "string";
}

export function isPdfRef(obj: PdfObject): obj is PdfRef {
  return obj.type === "ref";
}

export function isPdfArray(obj: PdfObject): obj is PdfArray {
  return obj.type === "array";
}

export function isPdfDict(obj: PdfObject): obj is PdfDict {
  return obj.type === "dict";
}

export function isPdfStream(obj: PdfObject): obj is PdfStream {
  return obj.type === "stream";
}

export function isPdfRaw(obj: PdfObject): obj is PdfRaw {
  return obj.type === "raw";
}
