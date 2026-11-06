/**
 * Built-in Encoding.
 *
 * A font's built-in encoding. This is a custom encoding embedded in a font.
 *
 * Ported from Apache PDFBox's fontbox/encoding/BuiltInEncoding.java
 */

import { createEncodingFromMap, type Encoding } from "./encoding.ts";

/**
 * Create a built-in encoding from a code-to-name map.
 *
 * This is used for custom encodings embedded in fonts.
 *
 * @param codeToName - Map from character codes to glyph names
 * @returns An Encoding instance
 */
export function createBuiltInEncoding(codeToName: ReadonlyMap<number, string>): Encoding {
  return createEncodingFromMap(codeToName);
}

/**
 * Create a built-in encoding from an object mapping codes to names.
 *
 * @param mapping - Object with numeric keys mapping to glyph names
 * @returns An Encoding instance
 */
export function createBuiltInEncodingFromObject(mapping: Record<number, string>): Encoding {
  const map = new Map<number, string>();

  for (const [code, name] of Object.entries(mapping)) {
    map.set(Number(code), name);
  }

  return createEncodingFromMap(map);
}
