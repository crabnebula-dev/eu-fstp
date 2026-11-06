/**
 * FontFactory - Creates appropriate font objects from PDF dictionaries.
 *
 * Examines the /Subtype of a font dictionary and returns the
 * appropriate font class (SimpleFont or Type0Font).
 */

import type { RefResolver } from "../helpers/types.js";
import type { PdfDict } from "../objects/pdf-dict.js";

import { CompositeFont, parseCompositeFont } from "./composite-font.js";
import { PdfFont } from "./pdf-font.js";
import { parseSimpleFont, SimpleFont } from "./simple-font.js";
import type { ToUnicodeMap } from "./to-unicode.js";

// Re-export PdfFont for convenience
export { PdfFont };

/**
 * Options for parsing fonts.
 */
export interface FontParseOptions {
  /**
   * Resolve indirect references to their objects.
   */
  resolver?: RefResolver;

  /**
   * Pre-parsed ToUnicode map (if available).
   */
  toUnicodeMap?: ToUnicodeMap | null;
}

/**
 * Parse a font dictionary and return the appropriate font object.
 *
 * @param dict - The font dictionary
 * @param options - Parsing options for resolving references
 * @returns A SimpleFont or CompositeFont instance
 */
export function parseFont(dict: PdfDict, options: FontParseOptions = {}): PdfFont {
  const subtype = dict.getName("Subtype", options.resolver)?.value;

  switch (subtype) {
    case "Type0":
      return parseCompositeFont(dict, options);

    case "TrueType":
    case "Type1":
    case "Type3":
    case "MMType1":
      return parseSimpleFont(dict, options);

    default:
      // Default to SimpleFont for unknown subtypes
      return parseSimpleFont(dict, options);
  }
}

/**
 * Check if a font is a SimpleFont (TrueType, Type1, Type3).
 */
export function isSimpleFont(font: PdfFont): font is SimpleFont {
  return font instanceof SimpleFont;
}

/**
 * Check if a font is a CompositeFont (Type0/CID font).
 */
export function isCompositeFont(font: PdfFont): font is CompositeFont {
  return font instanceof CompositeFont;
}

/**
 * FontFactory class for creating font objects.
 *
 * This is an alternative API to the `parseFont` function,
 * providing a class-based interface.
 */
export class FontFactory {
  private readonly options: FontParseOptions;

  constructor(options: FontParseOptions = {}) {
    this.options = options;
  }

  /**
   * Parse a font dictionary and return the appropriate font object.
   */
  parse(dict: PdfDict): PdfFont {
    return parseFont(dict, this.options);
  }

  /**
   * Create a FontFactory with a reference resolver.
   */
  static withResolver(resolver: RefResolver): FontFactory {
    return new FontFactory({ resolver });
  }
}
