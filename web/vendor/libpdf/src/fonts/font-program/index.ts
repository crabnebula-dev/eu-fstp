/**
 * Font program types and implementations.
 *
 * Provides a unified interface for accessing font data regardless
 * of the underlying font format (TrueType, CFF, Type1).
 */

export type { FontProgram, FontProgramType } from "./base.ts";
export { CFFType1FontProgram } from "./cff.ts";
export { CFFCIDFontProgram } from "./cff-cid.ts";
export { TrueTypeFontProgram } from "./truetype.ts";
export { Type1FontProgram } from "./type1.ts";
