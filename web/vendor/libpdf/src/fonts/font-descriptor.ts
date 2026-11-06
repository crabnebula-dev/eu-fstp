/**
 * PDF FontDescriptor - contains font metrics and flags.
 */

import type { PdfDict } from "#src/objects/pdf-dict";
import { PdfNumber } from "#src/objects/pdf-number.ts";

/**
 * Font flags as defined in PDF spec Table 123.
 */
export const FontFlags = {
  FIXED_PITCH: 1 << 0,
  SERIF: 1 << 1,
  SYMBOLIC: 1 << 2,
  SCRIPT: 1 << 3,
  NONSYMBOLIC: 1 << 5,
  ITALIC: 1 << 6,
  ALL_CAP: 1 << 16,
  SMALL_CAP: 1 << 17,
  FORCE_BOLD: 1 << 18,
} as const;

export interface FontDescriptorData {
  fontName: string;
  flags: number;
  fontBBox: [number, number, number, number];
  italicAngle: number;
  ascent: number;
  descent: number;
  leading: number;
  capHeight: number;
  xHeight: number;
  stemV: number;
  stemH: number;
  avgWidth: number;
  maxWidth: number;
  missingWidth: number;
}

/**
 * FontDescriptor contains font metrics and flags.
 */
export class FontDescriptor {
  readonly fontName: string;
  readonly flags: number;
  readonly fontBBox: [number, number, number, number];
  readonly italicAngle: number;
  readonly ascent: number;
  readonly descent: number;
  readonly leading: number;
  readonly capHeight: number;
  readonly xHeight: number;
  readonly stemV: number;
  readonly stemH: number;
  readonly avgWidth: number;
  readonly maxWidth: number;
  readonly missingWidth: number;

  constructor(data: FontDescriptorData) {
    this.fontName = data.fontName;
    this.flags = data.flags;
    this.fontBBox = data.fontBBox;
    this.italicAngle = data.italicAngle;
    this.ascent = data.ascent;
    this.descent = data.descent;
    this.leading = data.leading;
    this.capHeight = data.capHeight;
    this.xHeight = data.xHeight;
    this.stemV = data.stemV;
    this.stemH = data.stemH;
    this.avgWidth = data.avgWidth;
    this.maxWidth = data.maxWidth;
    this.missingWidth = data.missingWidth;
  }

  /** Check if font is fixed-pitch (monospace) */
  get isFixedPitch(): boolean {
    return (this.flags & FontFlags.FIXED_PITCH) !== 0;
  }

  /** Check if font is serif */
  get isSerif(): boolean {
    return (this.flags & FontFlags.SERIF) !== 0;
  }

  /** Check if font is symbolic (uses custom encoding) */
  get isSymbolic(): boolean {
    return (this.flags & FontFlags.SYMBOLIC) !== 0;
  }

  /** Check if font is script (cursive) */
  get isScript(): boolean {
    return (this.flags & FontFlags.SCRIPT) !== 0;
  }

  /** Check if font is non-symbolic (uses standard encoding) */
  get isNonSymbolic(): boolean {
    return (this.flags & FontFlags.NONSYMBOLIC) !== 0;
  }

  /** Check if font is italic */
  get isItalic(): boolean {
    return (this.flags & FontFlags.ITALIC) !== 0;
  }

  /** Check if font is all caps */
  get isAllCap(): boolean {
    return (this.flags & FontFlags.ALL_CAP) !== 0;
  }

  /** Check if font is small caps */
  get isSmallCap(): boolean {
    return (this.flags & FontFlags.SMALL_CAP) !== 0;
  }

  /** Check if font should be bold */
  get isForceBold(): boolean {
    return (this.flags & FontFlags.FORCE_BOLD) !== 0;
  }

  /**
   * Parse FontDescriptor from a PDF dictionary.
   */
  static parse(dict: PdfDict): FontDescriptor {
    const bboxArray = dict.getArray("FontBBox");

    const fontBBox: [number, number, number, number] = [0, 0, 0, 0];

    if (bboxArray && bboxArray.length >= 4) {
      for (let i = 0; i < 4; i++) {
        const item = bboxArray.at(i);

        if (item instanceof PdfNumber) {
          fontBBox[i] = item.value;
        }
      }
    }

    return new FontDescriptor({
      fontName: dict.getName("FontName")?.value ?? "",
      flags: dict.getNumber("Flags")?.value ?? 0,
      fontBBox,
      italicAngle: dict.getNumber("ItalicAngle")?.value ?? 0,
      ascent: dict.getNumber("Ascent")?.value ?? 0,
      descent: dict.getNumber("Descent")?.value ?? 0,
      leading: dict.getNumber("Leading")?.value ?? 0,
      capHeight: dict.getNumber("CapHeight")?.value ?? 0,
      xHeight: dict.getNumber("XHeight")?.value ?? 0,
      stemV: dict.getNumber("StemV")?.value ?? 0,
      stemH: dict.getNumber("StemH")?.value ?? 0,
      avgWidth: dict.getNumber("AvgWidth")?.value ?? 0,
      maxWidth: dict.getNumber("MaxWidth")?.value ?? 0,
      missingWidth: dict.getNumber("MissingWidth")?.value ?? 0,
    });
  }
}
