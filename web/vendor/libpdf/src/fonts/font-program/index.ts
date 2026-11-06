/**
 * Font program types and implementations.
 *
 * Provides a unified interface for accessing font data regardless
 * of the underlying font format (TrueType, CFF, Type1).
 */

export type { FontProgram, FontProgramType } from "./base.js";
export { CFFType1FontProgram } from "./cff.js";
export { CFFCIDFontProgram } from "./cff-cid.js";
export { TrueTypeFontProgram } from "./truetype.js";
export { Type1FontProgram } from "./type1.js";
