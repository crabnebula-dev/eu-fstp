/**
 * The 'post' table - PostScript Table.
 *
 * Contains information for PostScript printers.
 * Required in all TrueType fonts.
 *
 * Based on Apache PDFBox fontbox PostScriptTable.java and WGL4Names.java
 * @see https://learn.microsoft.com/en-us/typography/opentype/spec/post
 */

import type { TableParseContext, TTFTable } from "../types.ts";

/**
 * The 258 standard Macintosh glyph names used in 'post' format 1 and 2.
 */
const MAC_GLYPH_NAMES = [
  ".notdef",
  ".null",
  "nonmarkingreturn",
  "space",
  "exclam",
  "quotedbl",
  "numbersign",
  "dollar",
  "percent",
  "ampersand",
  "quotesingle",
  "parenleft",
  "parenright",
  "asterisk",
  "plus",
  "comma",
  "hyphen",
  "period",
  "slash",
  "zero",
  "one",
  "two",
  "three",
  "four",
  "five",
  "six",
  "seven",
  "eight",
  "nine",
  "colon",
  "semicolon",
  "less",
  "equal",
  "greater",
  "question",
  "at",
  "A",
  "B",
  "C",
  "D",
  "E",
  "F",
  "G",
  "H",
  "I",
  "J",
  "K",
  "L",
  "M",
  "N",
  "O",
  "P",
  "Q",
  "R",
  "S",
  "T",
  "U",
  "V",
  "W",
  "X",
  "Y",
  "Z",
  "bracketleft",
  "backslash",
  "bracketright",
  "asciicircum",
  "underscore",
  "grave",
  "a",
  "b",
  "c",
  "d",
  "e",
  "f",
  "g",
  "h",
  "i",
  "j",
  "k",
  "l",
  "m",
  "n",
  "o",
  "p",
  "q",
  "r",
  "s",
  "t",
  "u",
  "v",
  "w",
  "x",
  "y",
  "z",
  "braceleft",
  "bar",
  "braceright",
  "asciitilde",
  "Adieresis",
  "Aring",
  "Ccedilla",
  "Eacute",
  "Ntilde",
  "Odieresis",
  "Udieresis",
  "aacute",
  "agrave",
  "acircumflex",
  "adieresis",
  "atilde",
  "aring",
  "ccedilla",
  "eacute",
  "egrave",
  "ecircumflex",
  "edieresis",
  "iacute",
  "igrave",
  "icircumflex",
  "idieresis",
  "ntilde",
  "oacute",
  "ograve",
  "ocircumflex",
  "odieresis",
  "otilde",
  "uacute",
  "ugrave",
  "ucircumflex",
  "udieresis",
  "dagger",
  "degree",
  "cent",
  "sterling",
  "section",
  "bullet",
  "paragraph",
  "germandbls",
  "registered",
  "copyright",
  "trademark",
  "acute",
  "dieresis",
  "notequal",
  "AE",
  "Oslash",
  "infinity",
  "plusminus",
  "lessequal",
  "greaterequal",
  "yen",
  "mu",
  "partialdiff",
  "summation",
  "product",
  "pi",
  "integral",
  "ordfeminine",
  "ordmasculine",
  "Omega",
  "ae",
  "oslash",
  "questiondown",
  "exclamdown",
  "logicalnot",
  "radical",
  "florin",
  "approxequal",
  "Delta",
  "guillemotleft",
  "guillemotright",
  "ellipsis",
  "nonbreakingspace",
  "Agrave",
  "Atilde",
  "Otilde",
  "OE",
  "oe",
  "endash",
  "emdash",
  "quotedblleft",
  "quotedblright",
  "quoteleft",
  "quoteright",
  "divide",
  "lozenge",
  "ydieresis",
  "Ydieresis",
  "fraction",
  "currency",
  "guilsinglleft",
  "guilsinglright",
  "fi",
  "fl",
  "daggerdbl",
  "periodcentered",
  "quotesinglbase",
  "quotedblbase",
  "perthousand",
  "Acircumflex",
  "Ecircumflex",
  "Aacute",
  "Edieresis",
  "Egrave",
  "Iacute",
  "Icircumflex",
  "Idieresis",
  "Igrave",
  "Oacute",
  "Ocircumflex",
  "apple",
  "Ograve",
  "Uacute",
  "Ucircumflex",
  "Ugrave",
  "dotlessi",
  "circumflex",
  "tilde",
  "macron",
  "breve",
  "dotaccent",
  "ring",
  "cedilla",
  "hungarumlaut",
  "ogonek",
  "caron",
  "Lslash",
  "lslash",
  "Scaron",
  "scaron",
  "Zcaron",
  "zcaron",
  "brokenbar",
  "Eth",
  "eth",
  "Yacute",
  "yacute",
  "Thorn",
  "thorn",
  "minus",
  "multiply",
  "onesuperior",
  "twosuperior",
  "threesuperior",
  "onehalf",
  "onequarter",
  "threequarters",
  "franc",
  "Gbreve",
  "gbreve",
  "Idotaccent",
  "Scedilla",
  "scedilla",
  "Cacute",
  "cacute",
  "Ccaron",
  "ccaron",
  "dcroat",
];

/** Number of standard Mac glyph names */
export const NUMBER_OF_MAC_GLYPHS = 258;

/**
 * Build a map from glyph name to index.
 */
const MAC_GLYPH_NAME_TO_INDEX = new Map<string, number>(
  MAC_GLYPH_NAMES.map((name, index) => [name, index]),
);

/**
 * Get the index of a standard Mac glyph name.
 */
export function getMacGlyphIndex(name: string): number | undefined {
  return MAC_GLYPH_NAME_TO_INDEX.get(name);
}

/**
 * Get a standard Mac glyph name by index.
 */
export function getMacGlyphName(index: number): string | undefined {
  return index >= 0 && index < NUMBER_OF_MAC_GLYPHS ? MAC_GLYPH_NAMES[index] : undefined;
}

/**
 * Get all standard Mac glyph names.
 */
export function getAllMacGlyphNames(): string[] {
  return [...MAC_GLYPH_NAMES];
}

/**
 * Parsed 'post' table data.
 */
export interface PostTable extends TTFTable {
  readonly tag: "post";

  /** Table format (1.0, 2.0, 2.5, 3.0) */
  readonly formatType: number;
  /** Italic angle in degrees */
  readonly italicAngle: number;
  /** Underline position (negative = below baseline) */
  readonly underlinePosition: number;
  /** Underline thickness */
  readonly underlineThickness: number;
  /** Is fixed pitch (monospace) */
  readonly isFixedPitch: number;
  /** Minimum memory for Type 42 */
  readonly minMemType42: number;
  /** Maximum memory for Type 42 */
  readonly maxMemType42: number;
  /** Minimum memory for Type 1 */
  readonly minMemType1: number;
  /** Maximum memory for Type 1 */
  readonly maxMemType1: number;

  /** Glyph names (undefined for format 3.0) */
  readonly glyphNames: string[] | undefined;

  /**
   * Get glyph name by glyph ID.
   * Returns undefined if not available.
   */
  getName(glyphId: number): string | undefined;
}

/**
 * Parse the 'post' table.
 */
export function parsePostTable(ctx: TableParseContext): PostTable {
  const { data, font, record } = ctx;
  const tableStart = data.position;

  const formatType = data.readFixed();
  const italicAngle = data.readFixed();
  const underlinePosition = data.readInt16();
  const underlineThickness = data.readInt16();
  const isFixedPitch = data.readUint32();
  const minMemType42 = data.readUint32();
  const maxMemType42 = data.readUint32();
  const minMemType1 = data.readUint32();
  const maxMemType1 = data.readUint32();

  let glyphNames: string[] | undefined;

  // Check if we've read all the data
  const bytesRead = data.position - tableStart;
  const hasMoreData = bytesRead < record.length;

  if (!hasMoreData) {
    // No glyph name data
    glyphNames = undefined;
  } else if (formatType === 1.0) {
    // Format 1.0: uses standard Mac glyph names
    glyphNames = [...MAC_GLYPH_NAMES];
  } else if (formatType === 2.0) {
    // Format 2.0: custom glyph names
    const numGlyphs = data.readUint16();
    const glyphNameIndex = new Uint16Array(numGlyphs);
    let maxIndex = -1;

    for (let i = 0; i < numGlyphs; i++) {
      const index = data.readUint16();
      glyphNameIndex[i] = index;

      // PDFBOX-808: Indices 32768-65535 are reserved
      if (index <= 32767) {
        maxIndex = Math.max(maxIndex, index);
      }
    }

    // Read custom names (indices >= 258)
    let customNames: string[] = [];

    if (maxIndex >= NUMBER_OF_MAC_GLYPHS) {
      const numCustomNames = maxIndex - NUMBER_OF_MAC_GLYPHS + 1;
      customNames = new Array(numCustomNames);

      for (let i = 0; i < numCustomNames; i++) {
        try {
          const length = data.readUint8();
          const bytes = new Uint8Array(length);

          for (let j = 0; j < length; j++) {
            bytes[j] = data.readUint8();
          }

          customNames[i] = String.fromCharCode(...bytes);
        } catch {
          // PDFBOX-4851: EOF - fill remaining with .notdef
          for (let j = i; j < numCustomNames; j++) {
            customNames[j] = ".notdef";
          }

          break;
        }
      }
    }

    // Build glyph names array
    glyphNames = new Array(numGlyphs);

    for (let i = 0; i < numGlyphs; i++) {
      const index = glyphNameIndex[i];

      if (index >= 0 && index < NUMBER_OF_MAC_GLYPHS) {
        glyphNames[i] = MAC_GLYPH_NAMES[index];
      } else if (index >= NUMBER_OF_MAC_GLYPHS && index <= 32767) {
        const customIndex = index - NUMBER_OF_MAC_GLYPHS;
        glyphNames[i] = customNames[customIndex] ?? ".undefined";
      } else {
        // PDFBOX-808: Reserved indices
        glyphNames[i] = ".undefined";
      }
    }
  } else if (formatType === 2.5) {
    // Format 2.5: offset-based mapping
    const numGlyphs = font.numGlyphs;
    glyphNames = new Array(numGlyphs);

    for (let i = 0; i < numGlyphs; i++) {
      const offset = data.readInt8();
      const index = i + 1 + offset;

      if (index >= 0 && index < NUMBER_OF_MAC_GLYPHS) {
        glyphNames[i] = MAC_GLYPH_NAMES[index];
      } else {
        glyphNames[i] = ".undefined";
      }
    }
  } else if (formatType === 3.0) {
    // Format 3.0: no PostScript name information
    glyphNames = undefined;
  }

  function getName(glyphId: number): string | undefined {
    if (!glyphNames || glyphId < 0 || glyphId >= glyphNames.length) {
      return undefined;
    }

    return glyphNames[glyphId];
  }

  return {
    tag: "post",
    formatType,
    italicAngle,
    underlinePosition,
    underlineThickness,
    isFixedPitch,
    minMemType42,
    maxMemType42,
    minMemType1,
    maxMemType1,
    glyphNames,
    getName,
  };
}
