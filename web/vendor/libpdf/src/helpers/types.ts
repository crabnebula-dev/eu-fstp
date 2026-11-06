/**
 * Shared type definitions used across the library.
 */

import type { PdfObject } from "#src/objects/pdf-object";
import type { PdfRef } from "#src/objects/pdf-ref";

/**
 * Function type for resolving a PdfRef to its target PdfObject.
 *
 * This is the standard resolver signature used throughout the library
 * for dereferencing indirect object references. All PDF data is loaded
 * into memory at parse time, so resolution is synchronous.
 *
 * @param ref - The indirect reference to resolve
 * @returns The resolved object, or null if not found
 */
export type RefResolver = (ref: PdfRef) => PdfObject | null;
