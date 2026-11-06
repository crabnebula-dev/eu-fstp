/**
 * Represents an Adobe Type 1 (.pfb) font.
 *
 * Type 1 fonts contain:
 * - Font dictionary (FontName, FontMatrix, FontBBox, etc.)
 * - FontInfo dictionary (FamilyName, Weight, ItalicAngle, etc.)
 * - Private dictionary (hinting values)
 * - CharStrings (glyph outlines)
 * - Subrs (subroutines used by CharStrings)
 *
 * @see "Adobe Type 1 Font Format, Adobe Systems (1999)"
 */

/** biome-ignore-all lint/complexity/useSimpleNumberKeys: hex mapping */

/**
 * Encoding for Type 1 fonts.
 * Maps character codes (0-255) to glyph names.
 */
export interface Type1Encoding {
  /** Get glyph name for a character code. */
  getName(code: number): string | undefined;
}

/**
 * Standard encoding (Adobe's standard character set).
 */
export const StandardEncoding: Type1Encoding = {
  getName(code: number): string | undefined {
    return STANDARD_ENCODING[code];
  },
};

/**
 * Built-in encoding defined in the font itself.
 */
export class BuiltInEncoding implements Type1Encoding {
  private readonly codeToName: Map<number, string>;

  constructor(codeToName: Map<number, string>) {
    this.codeToName = codeToName;
  }

  getName(code: number): string | undefined {
    return this.codeToName.get(code);
  }
}

/**
 * Represents an Adobe Type 1 font.
 */
export class Type1Font {
  // =========================================================================
  // Font dictionary
  // =========================================================================

  /** Font name (e.g., "Times-Roman") */
  fontName = "";

  /** Character encoding */
  encoding: Type1Encoding | undefined;

  /** Paint type (0 = filled, 2 = stroked) */
  paintType = 0;

  /** Font type (should be 1 for Type 1) */
  fontType = 1;

  /** Font matrix [a b c d e f] transforms from glyph space to user space */
  fontMatrix: number[] = [];

  /** Font bounding box [llx lly urx ury] */
  fontBBox: number[] = [];

  /** Unique ID for font caching */
  uniqueID = 0;

  /** Stroke width for stroked fonts */
  strokeWidth = 0;

  /** Font ID */
  fontID = "";

  // =========================================================================
  // FontInfo dictionary
  // =========================================================================

  /** Font version string */
  version = "";

  /** Copyright/trademark notice */
  notice = "";

  /** Full name (e.g., "Times Roman") */
  fullName = "";

  /** Family name (e.g., "Times") */
  familyName = "";

  /** Weight name (e.g., "Bold", "Medium") */
  weight = "";

  /** Italic angle in degrees (0 = upright) */
  italicAngle = 0;

  /** Whether the font is monospaced */
  isFixedPitch = false;

  /** Underline position */
  underlinePosition = 0;

  /** Underline thickness */
  underlineThickness = 0;

  // =========================================================================
  // Private dictionary (hinting)
  // =========================================================================

  /** Blue zones for alignment */
  blueValues: number[] = [];

  /** Additional blue zones below baseline */
  otherBlues: number[] = [];

  /** Family-wide blue zones */
  familyBlues: number[] = [];

  /** Family-wide other blues */
  familyOtherBlues: number[] = [];

  /** Blue scale factor */
  blueScale = 0.039625;

  /** Blue shift threshold */
  blueShift = 7;

  /** Blue fuzz tolerance */
  blueFuzz = 1;

  /** Standard horizontal stem width */
  stdHW: number[] = [];

  /** Standard vertical stem width */
  stdVW: number[] = [];

  /** Horizontal stem snap widths */
  stemSnapH: number[] = [];

  /** Vertical stem snap widths */
  stemSnapV: number[] = [];

  /** Force bold rendering at small sizes */
  forceBold = false;

  /** Language group (0 = Latin, 1 = CJK) */
  languageGroup = 0;

  // =========================================================================
  // Glyph data
  // =========================================================================

  /** Subroutines (indexed array) */
  readonly subrs: (Uint8Array | null)[] = [];

  /** CharStrings dictionary (glyph name -> encrypted charstring data) */
  readonly charstrings: Map<string, Uint8Array> = new Map();

  // =========================================================================
  // Raw data
  // =========================================================================

  private readonly _segment1: Uint8Array;
  private readonly _segment2: Uint8Array;

  /**
   * Constructs a new Type1Font.
   * @param segment1 ASCII segment
   * @param segment2 Binary segment
   */
  constructor(segment1: Uint8Array, segment2: Uint8Array) {
    this._segment1 = segment1;
    this._segment2 = segment2;
  }

  // =========================================================================
  // Public API
  // =========================================================================

  /** Get the font name. */
  get name(): string {
    return this.fontName;
  }

  /** Check if the font has a glyph with the given name. */
  hasGlyph(name: string): boolean {
    return this.charstrings.has(name);
  }

  /** Get all glyph names in the font. */
  getGlyphNames(): string[] {
    return Array.from(this.charstrings.keys());
  }

  /** Get the ASCII segment. */
  get asciiSegment(): Uint8Array {
    return this._segment1;
  }

  /** Get the binary segment. */
  get binarySegment(): Uint8Array {
    return this._segment2;
  }

  /** Get the raw charstring data for a glyph (decrypted). */
  getCharstring(name: string): Uint8Array | undefined {
    return this.charstrings.get(name);
  }

  /** Get the subroutine at the given index. */
  getSubr(index: number): Uint8Array | null {
    if (index < 0 || index >= this.subrs.length) {
      return null;
    }
    return this.subrs[index];
  }

  toString(): string {
    return `Type1Font[fontName=${this.fontName}, fullName=${this.fullName}]`;
  }
}

// Standard encoding table
// Based on Adobe's Standard Encoding
const STANDARD_ENCODING: Record<number, string> = {
  0x20: "space",
  0x21: "exclam",
  0x22: "quotedbl",
  0x23: "numbersign",
  0x24: "dollar",
  0x25: "percent",
  0x26: "ampersand",
  0x27: "quoteright",
  0x28: "parenleft",
  0x29: "parenright",
  0x2a: "asterisk",
  0x2b: "plus",
  0x2c: "comma",
  0x2d: "hyphen",
  0x2e: "period",
  0x2f: "slash",
  0x30: "zero",
  0x31: "one",
  0x32: "two",
  0x33: "three",
  0x34: "four",
  0x35: "five",
  0x36: "six",
  0x37: "seven",
  0x38: "eight",
  0x39: "nine",
  0x3a: "colon",
  0x3b: "semicolon",
  0x3c: "less",
  0x3d: "equal",
  0x3e: "greater",
  0x3f: "question",
  0x40: "at",
  0x41: "A",
  0x42: "B",
  0x43: "C",
  0x44: "D",
  0x45: "E",
  0x46: "F",
  0x47: "G",
  0x48: "H",
  0x49: "I",
  0x4a: "J",
  0x4b: "K",
  0x4c: "L",
  0x4d: "M",
  0x4e: "N",
  0x4f: "O",
  0x50: "P",
  0x51: "Q",
  0x52: "R",
  0x53: "S",
  0x54: "T",
  0x55: "U",
  0x56: "V",
  0x57: "W",
  0x58: "X",
  0x59: "Y",
  0x5a: "Z",
  0x5b: "bracketleft",
  0x5c: "backslash",
  0x5d: "bracketright",
  0x5e: "asciicircum",
  0x5f: "underscore",
  0x60: "quoteleft",
  0x61: "a",
  0x62: "b",
  0x63: "c",
  0x64: "d",
  0x65: "e",
  0x66: "f",
  0x67: "g",
  0x68: "h",
  0x69: "i",
  0x6a: "j",
  0x6b: "k",
  0x6c: "l",
  0x6d: "m",
  0x6e: "n",
  0x6f: "o",
  0x70: "p",
  0x71: "q",
  0x72: "r",
  0x73: "s",
  0x74: "t",
  0x75: "u",
  0x76: "v",
  0x77: "w",
  0x78: "x",
  0x79: "y",
  0x7a: "z",
  0x7b: "braceleft",
  0x7c: "bar",
  0x7d: "braceright",
  0x7e: "asciitilde",
  0xa1: "exclamdown",
  0xa2: "cent",
  0xa3: "sterling",
  0xa4: "fraction",
  0xa5: "yen",
  0xa6: "florin",
  0xa7: "section",
  0xa8: "currency",
  0xa9: "quotesingle",
  0xaa: "quotedblleft",
  0xab: "guillemotleft",
  0xac: "guilsinglleft",
  0xad: "guilsinglright",
  0xae: "fi",
  0xaf: "fl",
  0xb1: "endash",
  0xb2: "dagger",
  0xb3: "daggerdbl",
  0xb4: "periodcentered",
  0xb6: "paragraph",
  0xb7: "bullet",
  0xb8: "quotesinglbase",
  0xb9: "quotedblbase",
  0xba: "quotedblright",
  0xbb: "guillemotright",
  0xbc: "ellipsis",
  0xbd: "perthousand",
  0xbf: "questiondown",
  0xc1: "grave",
  0xc2: "acute",
  0xc3: "circumflex",
  0xc4: "tilde",
  0xc5: "macron",
  0xc6: "breve",
  0xc7: "dotaccent",
  0xc8: "dieresis",
  0xca: "ring",
  0xcb: "cedilla",
  0xcc: "hungarumlaut",
  0xcd: "ogonek",
  0xce: "caron",
  0xcf: "emdash",
  0xe1: "AE",
  0xe3: "ordfeminine",
  0xe8: "Lslash",
  0xe9: "Oslash",
  0xea: "OE",
  0xeb: "ordmasculine",
  0xf1: "ae",
  0xf5: "dotlessi",
  0xf8: "lslash",
  0xf9: "oslash",
  0xfa: "oe",
  0xfb: "germandbls",
};
