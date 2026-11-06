/**
 * PDF string encoding utilities.
 */

import { CHAR_BACKSLASH, CHAR_PARENTHESIS_CLOSE, CHAR_PARENTHESIS_OPEN } from "./chars";

/**
 * Escape a PDF literal string for serialization.
 *
 * Handles:
 * - Backslash escaping for \, (, )
 * - Other bytes pass through unchanged
 *
 * @param bytes - Raw string bytes
 * @returns Escaped bytes safe for literal string output
 */
export function escapeLiteralString(bytes: Uint8Array): Uint8Array {
  // Pre-scan to count bytes needing escape
  let escapeCount = 0;

  for (const byte of bytes) {
    if (
      byte === CHAR_BACKSLASH ||
      byte === CHAR_PARENTHESIS_OPEN ||
      byte === CHAR_PARENTHESIS_CLOSE
    ) {
      escapeCount++;
    }
  }

  if (escapeCount === 0) {
    return bytes;
  }

  const result = new Uint8Array(bytes.length + escapeCount);
  let j = 0;

  for (const byte of bytes) {
    if (byte === CHAR_BACKSLASH) {
      result[j++] = CHAR_BACKSLASH;
      result[j++] = CHAR_BACKSLASH;
    } else if (byte === CHAR_PARENTHESIS_OPEN) {
      result[j++] = CHAR_BACKSLASH;
      result[j++] = CHAR_PARENTHESIS_OPEN;
    } else if (byte === CHAR_PARENTHESIS_CLOSE) {
      result[j++] = CHAR_BACKSLASH;
      result[j++] = CHAR_PARENTHESIS_CLOSE;
    } else {
      result[j++] = byte;
    }
  }

  return result;
}

/**
 * Generate a unique name by appending a number to a prefix.
 *
 * Finds the first available name by incrementing a counter until a name
 * that doesn't exist in the provided set is found.
 *
 * @param existingNames - Set of names that already exist
 * @param prefix - Prefix to use (e.g., "Signature_" or "DocTimeStamp_")
 * @returns A unique name that doesn't exist in the set
 *
 * @example
 * ```ts
 * const names = new Set(["Signature_1", "Signature_2"]);
 * generateUniqueName(names, "Signature_") // "Signature_3"
 * ```
 */
export function generateUniqueName(existingNames: Set<string>, prefix: string): string {
  let n = 1;

  while (existingNames.has(`${prefix}${n}`)) {
    n++;
  }

  return `${prefix}${n}`;
}
