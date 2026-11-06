/**
 * Linearization detection and handling.
 *
 * Linearized PDFs are optimized for byte-serving (show first page
 * before downloading entire file). They have specific structural
 * requirements that are incompatible with incremental saves.
 *
 * When a linearized PDF is modified, we must perform a full save
 * (which strips the linearization).
 */

import type { PdfDict } from "#src/objects/pdf-dict";
import { PdfNumber } from "#src/objects/pdf-number";

/**
 * Linearization dictionary parameters.
 *
 * Per PDF 1.7 spec, Annex F.
 */
export interface LinearizationParams {
  /** Linearization version (always 1.0) */
  version: number;

  /** Total file length */
  fileLength: number;

  /** Primary hint stream offset */
  hintOffset: number;

  /** Primary hint stream length */
  hintLength: number;

  /** First page object number */
  firstPage: number;

  /** End of first page offset */
  endOfFirstPage: number;

  /** Number of pages */
  pageCount: number;

  /** Offset to main XRef */
  mainXRefOffset: number;
}

/**
 * Check if a dictionary is a linearization dictionary.
 *
 * The linearization dict is typically the first object in the file
 * and contains a /Linearized key with value 1.
 *
 * @param dict - The dictionary to check
 * @returns True if this is a linearization dictionary
 */
export function isLinearizationDict(dict: PdfDict): boolean {
  const linearized = dict.getNumber("Linearized");

  return linearized !== undefined && linearized.value === 1;
}

/**
 * Parse linearization parameters from a linearization dictionary.
 *
 * @param dict - The linearization dictionary
 * @returns The parsed parameters, or null if invalid
 */
export function parseLinearizationDict(dict: PdfDict): LinearizationParams | null {
  // Required fields
  const version = dict.getNumber("Linearized")?.value;
  const fileLength = dict.getNumber("L")?.value;
  const firstPage = dict.getNumber("O")?.value;
  const endOfFirstPage = dict.getNumber("E")?.value;
  const pageCount = dict.getNumber("N")?.value;
  const mainXRefOffset = dict.getNumber("T")?.value;

  // Hint stream info (in /H array)
  const hintArray = dict.getArray("H");
  const hintOffset = hintArray?.at(0);
  const hintLength = hintArray?.at(1);

  if (
    version === undefined ||
    fileLength === undefined ||
    firstPage === undefined ||
    endOfFirstPage === undefined ||
    pageCount === undefined ||
    mainXRefOffset === undefined
  ) {
    return null;
  }

  return {
    version,
    fileLength,
    hintOffset: hintOffset && hintOffset instanceof PdfNumber ? hintOffset.value : 0,
    hintLength: hintLength && hintLength instanceof PdfNumber ? hintLength.value : 0,
    firstPage,
    endOfFirstPage,
    pageCount,
    mainXRefOffset,
  };
}
