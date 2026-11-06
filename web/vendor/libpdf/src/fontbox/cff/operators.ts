/**
 * CFF operators lookup table.
 *
 * Maps byte codes to operator names used in Top DICT and Private DICT.
 * Based on Adobe Technical Note #5176 "The Compact Font Format Specification"
 */

// Operator key calculation: for 2-byte operators (12, b1), key = (b1 << 8) + 12
function key(b0: number, b1 = 0): number {
  return (b1 << 8) + b0;
}

/**
 * Map of operator byte codes to their names.
 */
const operatorMap = new Map<number, string>();

// Top DICT operators
operatorMap.set(key(0), "version");
operatorMap.set(key(1), "Notice");
operatorMap.set(key(12, 0), "Copyright");
operatorMap.set(key(2), "FullName");
operatorMap.set(key(3), "FamilyName");
operatorMap.set(key(4), "Weight");
operatorMap.set(key(12, 1), "isFixedPitch");
operatorMap.set(key(12, 2), "ItalicAngle");
operatorMap.set(key(12, 3), "UnderlinePosition");
operatorMap.set(key(12, 4), "UnderlineThickness");
operatorMap.set(key(12, 5), "PaintType");
operatorMap.set(key(12, 6), "CharstringType");
operatorMap.set(key(12, 7), "FontMatrix");
operatorMap.set(key(13), "UniqueID");
operatorMap.set(key(5), "FontBBox");
operatorMap.set(key(12, 8), "StrokeWidth");
operatorMap.set(key(14), "XUID");
operatorMap.set(key(15), "charset");
operatorMap.set(key(16), "Encoding");
operatorMap.set(key(17), "CharStrings");
operatorMap.set(key(18), "Private");
operatorMap.set(key(12, 20), "SyntheticBase");
operatorMap.set(key(12, 21), "PostScript");
operatorMap.set(key(12, 22), "BaseFontName");
operatorMap.set(key(12, 23), "BaseFontBlend");
operatorMap.set(key(12, 30), "ROS");
operatorMap.set(key(12, 31), "CIDFontVersion");
operatorMap.set(key(12, 32), "CIDFontRevision");
operatorMap.set(key(12, 33), "CIDFontType");
operatorMap.set(key(12, 34), "CIDCount");
operatorMap.set(key(12, 35), "UIDBase");
operatorMap.set(key(12, 36), "FDArray");
operatorMap.set(key(12, 37), "FDSelect");
operatorMap.set(key(12, 38), "FontName");

// Private DICT operators
operatorMap.set(key(6), "BlueValues");
operatorMap.set(key(7), "OtherBlues");
operatorMap.set(key(8), "FamilyBlues");
operatorMap.set(key(9), "FamilyOtherBlues");
operatorMap.set(key(12, 9), "BlueScale");
operatorMap.set(key(12, 10), "BlueShift");
operatorMap.set(key(12, 11), "BlueFuzz");
operatorMap.set(key(10), "StdHW");
operatorMap.set(key(11), "StdVW");
operatorMap.set(key(12, 12), "StemSnapH");
operatorMap.set(key(12, 13), "StemSnapV");
operatorMap.set(key(12, 14), "ForceBold");
operatorMap.set(key(12, 15), "LanguageGroup");
operatorMap.set(key(12, 16), "ExpansionFactor");
operatorMap.set(key(12, 17), "initialRandomSeed");
operatorMap.set(key(19), "Subrs");
operatorMap.set(key(20), "defaultWidthX");
operatorMap.set(key(21), "nominalWidthX");

/**
 * Get operator name for a single-byte operator.
 */
export function getOperator(b0: number): string | undefined {
  return operatorMap.get(key(b0));
}

/**
 * Get operator name for a two-byte operator.
 */
export function getOperator2(b0: number, b1: number): string | undefined {
  return operatorMap.get(key(b0, b1));
}

/**
 * Check if byte is the start of a two-byte operator (escape byte).
 */
export function isTwoByteOperator(b0: number): boolean {
  return b0 === 12;
}
