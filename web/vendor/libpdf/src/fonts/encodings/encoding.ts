/**
 * Font encoding interface.
 *
 * Font encodings map between character codes (0-255 for simple fonts)
 * and Unicode code points.
 */

/**
 * Interface for font encodings.
 */
export interface FontEncoding {
  /** Encoding name (e.g., "WinAnsiEncoding") */
  readonly name: string;

  /**
   * Encode text to character codes.
   * Throws if any character cannot be encoded.
   */
  encode(text: string): number[];

  /**
   * Decode character code to Unicode string.
   * Returns empty string for unmapped codes.
   */
  decode(code: number): string;

  /**
   * Check if a character can be encoded.
   */
  canEncode(char: string): boolean;

  /**
   * Get the Unicode code point for a character code.
   * Returns undefined for unmapped codes.
   */
  getUnicode(code: number): number | undefined;

  /**
   * Get the character code for a Unicode code point.
   * Returns undefined if not encodable.
   */
  getCode(unicode: number): number | undefined;
}

/**
 * Base class for simple 256-entry encodings.
 */
export abstract class SimpleEncoding implements FontEncoding {
  abstract readonly name: string;

  /** Mapping from code (0-255) to Unicode code point */
  protected abstract readonly toUnicode: (number | undefined)[];

  /** Reverse mapping from Unicode to code */
  private _fromUnicode: Map<number, number> | null = null;

  private get fromUnicode(): Map<number, number> {
    if (!this._fromUnicode) {
      this._fromUnicode = new Map();

      for (let code = 0; code < this.toUnicode.length; code++) {
        const unicode = this.toUnicode[code];

        if (unicode !== undefined) {
          this._fromUnicode.set(unicode, code);
        }
      }
    }

    return this._fromUnicode;
  }

  encode(text: string): number[] {
    const codes: number[] = [];

    for (const char of text) {
      // biome-ignore lint/style/noNonNullAssertion: char will exist since it's a string
      const unicode = char.codePointAt(0)!;
      const code = this.fromUnicode.get(unicode);

      if (code === undefined) {
        throw new Error(
          `Cannot encode '${char}' (U+${unicode.toString(16).toUpperCase().padStart(4, "0")}) in ${this.name}`,
        );
      }

      codes.push(code);
    }

    return codes;
  }

  decode(code: number): string {
    const unicode = this.toUnicode[code];

    if (unicode === undefined) {
      return "";
    }

    return String.fromCodePoint(unicode);
  }

  canEncode(char: string): boolean {
    const unicode = char.codePointAt(0);

    return unicode !== undefined && this.fromUnicode.has(unicode);
  }

  getUnicode(code: number): number | undefined {
    return this.toUnicode[code];
  }

  getCode(unicode: number): number | undefined {
    return this.fromUnicode.get(unicode);
  }
}
