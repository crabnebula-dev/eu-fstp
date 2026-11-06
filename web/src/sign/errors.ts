// Typed refusals of the signing Worker (ADR-016, M5 design section 3.1
// step 3). Every outcome of the parser and the preparation is a success
// or one of these. Any other error is a defect, and the fuzz targets of
// web/fuzz/pdf_* fail on it.

import {
  RecoverableParseError,
  RefusedError,
  UnrecoverableParseError,
} from "../../vendor/libpdf/src/parser/errors.js";

/**
 * Why a file or a request is refused:
 * - `malformed`: the strict parser cannot read the file;
 * - `encrypted`, `object-stream`, `xref-stream`, `filter`: features the
 *   server's revisions never use;
 * - `limit`: a hard limit of the vendored `parser/limits.ts`;
 * - `no-field`, `field-signed`: the party's field is absent, or has a value;
 * - `request`: the request itself is malformed.
 */
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

/** A typed refusal. */
export interface Refusal {
  readonly ok: false;
  readonly code: RefusalCode;
  readonly message: string;
}

/** A refusal with `code`. */
export function refuse(code: RefusalCode, message: string): Refusal {
  return { ok: false, code, message };
}

/**
 * The refusal for a parse error of the vendored parser, or null for any
 * other error. The caller rethrows null cases, so a defect is never
 * hidden as a refusal.
 */
export function refusalOf(e: unknown): Refusal | null {
  if (e instanceof RefusedError) {
    return refuse(e.reason, e.message);
  }
  if (e instanceof RecoverableParseError || e instanceof UnrecoverableParseError) {
    return refuse("malformed", e.message);
  }
  return null;
}

/** Runs `fn`, turning parse errors into refusals and rethrowing anything else. */
export function guarded<T>(fn: () => T | Refusal): T | Refusal {
  try {
    return fn();
  } catch (e) {
    const r = refusalOf(e);
    if (r === null) {
      throw e;
    }
    return r;
  }
}
