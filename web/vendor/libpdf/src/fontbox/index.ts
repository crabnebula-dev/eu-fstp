/**
 * Fontbox module - Font parsing and subsetting.
 *
 * Port of Apache PDFBox's fontbox module to TypeScript.
 *
 * Supported formats:
 * - TTF/OTF: TrueType and OpenType fonts
 * - CFF: Compact Font Format (PostScript outlines in OpenType)
 * - Type1: Adobe Type 1 PostScript fonts (.pfb, .pfa)
 * - AFM: Adobe Font Metrics
 * - CMap: Character maps for CID-keyed fonts
 * - Encoding: PostScript encoding vectors
 */

/** biome-ignore-all assist/source/organizeImports: api file */

// AFM (Adobe Font Metrics) parsing
export * from "./afm/index.ts";

// CFF (Compact Font Format) parsing
export * from "./cff/index.ts";

// CMap (Character Map) parsing
export * from "./cmap/index.ts";

// Encoding (PostScript encoding vectors)
export * from "./encoding/index.ts";

// TrueType font parsing
export * from "./ttf/index.ts";

// Type 1 font parsing
export * from "./type1/index.ts";
