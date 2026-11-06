/**
 * FSTP (ADR-016 "Security review plan", item 3): the hard limits of the
 * strict parser. The server's revisions stay far below each one. A file
 * beyond a limit is refused with `RefusedError("limit")`, never trimmed.
 */

import { RefusedError } from "./errors.js";

export const LIMITS = {
  /** Largest file accepted, in bytes. */
  maxFileBytes: 32 * 1024 * 1024,
  /** Largest object number, and most in-use objects, of one file. */
  maxObjects: 65536,
  /** Deepest nesting of arrays and dictionaries, the outer object counting 1. */
  maxDepth: 32,
  /** Longest string or name, in bytes after decoding. */
  maxStringBytes: 65536,
  /** Most cross-reference sections in the `/Prev` chain. */
  maxXRefSections: 64,
} as const;

/** Throws `RefusedError("limit")` when `value` is above `max`. */
export function checkLimit(what: string, value: number, max: number): void {
  if (value > max) {
    throw new RefusedError("limit", `${what} ${value} is above the limit ${max}`);
  }
}
