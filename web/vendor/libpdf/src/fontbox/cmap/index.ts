/**
 * CMap (Character Map) module for PDF fonts.
 *
 * Provides parsing for CMap streams used in PDF fonts to map character
 * codes to Unicode characters or CIDs (Character IDs).
 */

/** biome-ignore-all assist/source/organizeImports: api file */

// Main CMap class
export { CMap } from "./cmap.ts";

// Parser
export { parseCMap } from "./parser.ts";

// Supporting types
export { CodespaceRange } from "./codespace-range.ts";
export { CIDRange } from "./cid-range.ts";

// Utilities
export {
  bytesToInt,
  bytesToIntN,
  intToBytes,
  incrementBytes,
  createStringFromBytes,
} from "./utils.ts";
