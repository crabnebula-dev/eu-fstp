/**
 * Type 1 font parsing module.
 *
 * Provides parsing for Adobe Type 1 PostScript fonts (.pfb, .pfa).
 */

/** biome-ignore-all assist/source/organizeImports: api file */

// Font model
export { Type1Font, StandardEncoding, BuiltInEncoding } from "./font.ts";
export type { Type1Encoding } from "./font.ts";

// Parser
export { parseType1 } from "./parser.ts";

// PFB parser
export { parsePfb, PfbParser } from "./pfb-parser.ts";
export type { PfbSegments } from "./pfb-parser.ts";

// Lexer (for advanced use)
export { Type1Lexer, DamagedFontError } from "./lexer.ts";

// Token types (for advanced use)
export { Token, TokenKind } from "./token.ts";
