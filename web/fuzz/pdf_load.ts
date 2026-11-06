// Loads the signing Worker's modules for the ADR-016 tests and fuzz targets.
//
// `tsc -b web/src/sign` builds web/src/sign and the vendored LibPDF into
// web/dist/signer, mirroring the web/ tree. The tests and targets load that
// output by URL, so they test the shipped modules and still compile while
// the build is missing. A missing module throws `NotImplemented`.

import { NotImplemented } from "../test/support/harness.js";

/** Why the parser or the preparation refused, as web/src/sign/errors.ts names it. */
export type RefusalCode =
  | "malformed"
  | "encrypted"
  | "object-stream"
  | "xref-stream"
  | "filter"
  | "limit"
  | "no-field"
  | "field-signed"
  | "request";

/** Every refusal code. */
export const REFUSAL_CODES: readonly RefusalCode[] = [
  "malformed",
  "encrypted",
  "object-stream",
  "xref-stream",
  "filter",
  "limit",
  "no-field",
  "field-signed",
  "request",
];

/** A typed refusal. */
export interface Refusal {
  readonly ok: false;
  readonly code: RefusalCode;
  readonly message: string;
}

export type Outcome<T> = { readonly ok: true; readonly value: T } | Refusal;

/** The hard limits of ADR-016 "Security review plan" item 3. */
export interface Limits {
  readonly maxFileBytes: number;
  readonly maxObjects: number;
  readonly maxDepth: number;
  readonly maxStringBytes: number;
  readonly maxXRefSections: number;
}

/** What parse.ts reports of one object. */
export interface ObjectSummary {
  readonly depth: number;
  readonly kind: string;
}

/** What parse.ts reports of the cross-reference chain from `startxref`. */
export interface XRefSummary {
  readonly sections: number;
  readonly entries: number;
}

/** One signature field of a parsed document. */
export interface FieldSummary {
  readonly name: string;
  readonly objectNumber: number;
  readonly signed: boolean;
}

/** What parse.ts reports of a whole document. */
export interface DocumentSummary {
  readonly objects: number;
  readonly sections: number;
  readonly fields: readonly FieldSummary[];
}

/** web/src/sign/parse.ts. */
export interface ParseModule {
  readonly LIMITS: Limits;
  parseObjectBytes(bytes: Uint8Array): Outcome<ObjectSummary>;
  parseXRefBytes(bytes: Uint8Array): Outcome<XRefSummary>;
  parseDocumentBytes(bytes: Uint8Array): Outcome<DocumentSummary>;
}

/** One preparation request. */
export interface PrepareRequest {
  readonly field: string;
  readonly contentsBytes: number;
}

/** A prepared increment. */
export interface Prepared {
  readonly ok: true;
  readonly increment: Uint8Array;
  readonly byteRange: readonly [number, number, number, number];
}

/** web/src/sign/prepare.ts. */
export interface PrepareModule {
  readonly CONTENTS_BYTES_MIN: number;
  readonly CONTENTS_BYTES_MAX: number;
  prepareSignature(revision: Uint8Array, request: PrepareRequest): Prepared | Refusal;
}

const cache = new Map<string, Record<string, unknown>>();

async function load(name: string, exports: readonly string[]): Promise<Record<string, unknown>> {
  let mod = cache.get(name);
  if (mod === undefined) {
    const url = new URL(`../../signer/src/sign/${name}.js`, import.meta.url);
    try {
      mod = (await import(url.href)) as Record<string, unknown>;
    } catch (e) {
      const code = typeof e === "object" && e !== null ? (e as { code?: unknown }).code : undefined;
      if (code === "ERR_MODULE_NOT_FOUND") {
        throw new NotImplemented(`web/src/sign/${name}.ts is not built (tsc -b web/src/sign): ${String(e)}`);
      }
      throw e;
    }
    cache.set(name, mod);
  }
  const absent = exports.filter((k) => !(k in mod));
  if (absent.length > 0) {
    throw new NotImplemented(`web/src/sign/${name}.ts does not export ${absent.join(", ")}`);
  }
  return mod;
}

/** web/src/sign/parse.ts, built. */
export async function parseModule(): Promise<ParseModule> {
  return (await load("parse", ["LIMITS", "parseObjectBytes", "parseXRefBytes", "parseDocumentBytes"])) as unknown as ParseModule;
}

/** web/src/sign/prepare.ts, built. */
export async function prepareModule(): Promise<PrepareModule> {
  return (await load("prepare", ["prepareSignature", "CONTENTS_BYTES_MIN", "CONTENTS_BYTES_MAX"])) as unknown as PrepareModule;
}
