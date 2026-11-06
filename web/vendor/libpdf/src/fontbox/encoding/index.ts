/**
 * Encoding module for fontbox.
 *
 * Provides PostScript encoding vectors that map character codes to glyph names.
 *
 * Ported from Apache PDFBox's fontbox/encoding module.
 */

/** biome-ignore-all assist/source/organizeImports: api file */

export {
  type Encoding,
  EncodingBuilder,
  createEncodingFromMap,
  createEncodingFromEntries,
} from "./encoding.ts";

export { STANDARD_ENCODING, getStandardEncoding } from "./standard-encoding.ts";

export { MAC_ROMAN_ENCODING, getMacRomanEncoding } from "./mac-roman-encoding.ts";

export { createBuiltInEncoding, createBuiltInEncodingFromObject } from "./built-in-encoding.ts";
