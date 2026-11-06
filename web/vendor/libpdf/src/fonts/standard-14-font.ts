/**
 * Standard14Font - A font wrapper for Standard 14 PDF fonts.
 *
 * This class provides width/height measurement for text using Standard 14 fonts,
 * which are built into every PDF reader and don't need embedding.
 *
 * Usage:
 * ```typescript
 * const font = Standard14Font.of("Helvetica-Bold");
 *
 * // Measure text
 * const width = font.widthOfTextAtSize("Hello", 12);
 * const height = font.heightAtSize(12);
 * ```
 */

import {
  getGlyphName,
  getStandard14BasicMetrics,
  getStandard14DefaultWidth,
  getStandard14GlyphWidth,
  isStandard14Font,
  type Standard14FontName,
} from "./standard-14";

/**
 * A wrapper class for Standard 14 fonts that provides measurement methods.
 *
 * Standard 14 fonts don't need to be embedded - they're built into PDF readers.
 * This class provides the same measurement API as EmbeddedFont.
 */
export class Standard14Font {
  /** The Standard 14 font name */
  readonly name: Standard14FontName;

  /** Cached metrics */
  private readonly metrics: {
    ascent: number;
    descent: number;
  };

  private constructor(name: Standard14FontName) {
    this.name = name;
    const basicMetrics = getStandard14BasicMetrics(name);

    if (!basicMetrics) {
      throw new Error(`Unknown Standard 14 font: ${name}`);
    }

    this.metrics = {
      ascent: basicMetrics.ascent,
      descent: basicMetrics.descent,
    };
  }

  /**
   * Create a Standard14Font instance.
   *
   * @param name - The Standard 14 font name (e.g., "Helvetica", "Times-Bold")
   * @returns Standard14Font instance
   * @throws {Error} if name is not a valid Standard 14 font
   *
   * @example
   * ```typescript
   * const helvetica = Standard14Font.of("Helvetica");
   * const timesBold = Standard14Font.of("Times-Bold");
   * ```
   */
  static of(name: Standard14FontName): Standard14Font {
    if (!isStandard14Font(name)) {
      throw new Error(
        `"${name}" is not a Standard 14 font. Valid names: Helvetica, Helvetica-Bold, ` +
          `Helvetica-Oblique, Helvetica-BoldOblique, Times-Roman, Times-Bold, Times-Italic, ` +
          `Times-BoldItalic, Courier, Courier-Bold, Courier-Oblique, Courier-BoldOblique, ` +
          `Symbol, ZapfDingbats`,
      );
    }

    return new Standard14Font(name);
  }

  /**
   * Get width of text in points at a given font size.
   *
   * @param text - The text to measure
   * @param size - Font size in points
   * @returns Width in points
   */
  widthOfTextAtSize(text: string, size: number): number {
    let totalWidth = 0;

    for (const char of text) {
      const glyphName = getGlyphName(char);
      const width =
        getStandard14GlyphWidth(this.name, glyphName) ?? getStandard14DefaultWidth(this.name);
      totalWidth += width;
    }

    return (totalWidth * size) / 1000;
  }

  /**
   * Get the height of the font at a given size.
   *
   * This returns the full height from descender to ascender.
   *
   * @param size - Font size in points
   * @returns Height in points
   */
  heightAtSize(size: number): number {
    return ((this.metrics.ascent - this.metrics.descent) * size) / 1000;
  }

  /**
   * Calculate font size needed to achieve a specific text height.
   *
   * @param height - Desired height in points
   * @returns Font size in points
   */
  sizeAtHeight(height: number): number {
    const unitsHeight = this.metrics.ascent - this.metrics.descent;

    return (height * 1000) / unitsHeight;
  }

  /**
   * Calculate font size needed for text to fit a specific width.
   *
   * @param text - The text to measure
   * @param width - Desired width in points
   * @returns Font size in points
   */
  sizeAtWidth(text: string, width: number): number {
    if (text.length === 0) {
      return 0;
    }

    // Get width at size 1000 (in glyph units)
    let totalWidth = 0;

    for (const char of text) {
      const glyphName = getGlyphName(char);
      const charWidth =
        getStandard14GlyphWidth(this.name, glyphName) ?? getStandard14DefaultWidth(this.name);
      totalWidth += charWidth;
    }

    if (totalWidth === 0) {
      return 0;
    }

    // width = (totalWidth * size) / 1000
    // size = (width * 1000) / totalWidth
    return (width * 1000) / totalWidth;
  }
}
