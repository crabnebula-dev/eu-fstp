/**
 * DifferencesEncoding - wraps a base encoding with custom overrides.
 *
 * PDF fonts can specify a base encoding (like WinAnsiEncoding) and then
 * override specific character codes using a /Differences array.
 *
 * The Differences array format is:
 *   [code1 /name1 /name2 ... codeN /nameN ...]
 *
 * Where each code starts a sequence of glyph name overrides.
 */

import type { FontEncoding } from "./encoding.ts";
import { glyphToUnicode } from "./glyph-list.ts";

/**
 * DifferencesEncoding wraps a base encoding with glyph overrides.
 */
export class DifferencesEncoding implements FontEncoding {
  readonly name: string;
  private readonly base: FontEncoding;
  private readonly differences: Map<number, number>; // code -> Unicode
  private readonly reverseDifferences: Map<number, number>; // Unicode -> code

  constructor(base: FontEncoding, differences: Map<number, string>) {
    this.name = `${base.name}+Differences`;
    this.base = base;
    this.differences = new Map();
    this.reverseDifferences = new Map();

    // Convert glyph names to Unicode code points
    for (const [code, glyphName] of differences) {
      const unicode = glyphToUnicode(glyphName);
      if (unicode !== undefined) {
        this.differences.set(code, unicode);
        this.reverseDifferences.set(unicode, code);
      }
    }
  }

  encode(text: string): number[] {
    const codes: number[] = [];

    for (const char of text) {
      // biome-ignore lint/style/noNonNullAssertion: for loop indicates existence
      const unicode = char.codePointAt(0)!;

      // Check differences first
      const diffCode = this.reverseDifferences.get(unicode);

      if (diffCode !== undefined) {
        codes.push(diffCode);

        continue;
      }

      // Fall back to base encoding
      const baseCode = this.base.getCode(unicode);

      if (baseCode !== undefined) {
        // Make sure this code wasn't overridden in differences
        if (!this.differences.has(baseCode)) {
          codes.push(baseCode);

          continue;
        }
      }

      throw new Error(
        `Cannot encode '${char}' (U+${unicode.toString(16).toUpperCase().padStart(4, "0")}) in ${this.name}`,
      );
    }

    return codes;
  }

  decode(code: number): string {
    // Check differences first
    const diffUnicode = this.differences.get(code);

    if (diffUnicode !== undefined) {
      return String.fromCodePoint(diffUnicode);
    }

    // Fall back to base encoding
    return this.base.decode(code);
  }

  canEncode(char: string): boolean {
    const unicode = char.codePointAt(0);
    if (unicode === undefined) {
      return false;
    }

    // Check differences
    if (this.reverseDifferences.has(unicode)) {
      return true;
    }

    // Check base encoding
    const baseCode = this.base.getCode(unicode);

    if (baseCode !== undefined && !this.differences.has(baseCode)) {
      return true;
    }

    return false;
  }

  getUnicode(code: number): number | undefined {
    // Check differences first
    const diffUnicode = this.differences.get(code);

    if (diffUnicode !== undefined) {
      return diffUnicode;
    }

    // Fall back to base encoding
    return this.base.getUnicode(code);
  }

  getCode(unicode: number): number | undefined {
    // Check differences first
    const diffCode = this.reverseDifferences.get(unicode);

    if (diffCode !== undefined) {
      return diffCode;
    }

    // Check base encoding (but not if that code was overridden)
    const baseCode = this.base.getCode(unicode);

    if (baseCode !== undefined && !this.differences.has(baseCode)) {
      return baseCode;
    }

    return undefined;
  }

  /**
   * Parse a Differences array from PDF.
   *
   * @param differencesArray - Array of [code, name, name, ...] entries
   * @returns Map from code to glyph name
   */
  static parseDifferencesArray(differencesArray: Array<number | string>): Map<number, string> {
    const differences = new Map<number, string>();
    let currentCode = 0;

    for (const item of differencesArray) {
      if (typeof item === "number") {
        currentCode = item;
      } else if (typeof item === "string") {
        differences.set(currentCode, item);
        currentCode++;
      }
    }

    return differences;
  }
}
