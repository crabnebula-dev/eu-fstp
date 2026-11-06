/**
 * Text extraction module for PDF documents.
 *
 * Provides functionality to extract text content with position information
 * from PDF pages, and search for text patterns.
 */

export { getPlainText, groupCharsIntoLines, type LineGrouperOptions } from "./line-grouper.js";
export { TextExtractor } from "./text-extractor.js";
export { type FormXObject, TextResources } from "./text-resources.js";
export { searchPage, searchPages } from "./text-search.js";
export { TextState } from "./text-state.js";
export * from "./types.js";
