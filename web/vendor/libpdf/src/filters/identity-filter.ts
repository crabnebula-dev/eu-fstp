import type { PdfDict } from "../objects/pdf-dict.js";

import type { Filter } from "./filter.js";

/**
 * Identity filter - passes data through unchanged.
 *
 * Used for:
 * - The "Identity" crypt filter (no encryption)
 * - Default behavior when no filter is specified
 *
 * This is a no-op filter that satisfies the Filter interface.
 */
export const identityFilter: Filter = {
  name: "Identity",

  decode(data: Uint8Array, _params?: PdfDict): Uint8Array {
    return data;
  },

  encode(data: Uint8Array, _params?: PdfDict): Uint8Array {
    return data;
  },
};
