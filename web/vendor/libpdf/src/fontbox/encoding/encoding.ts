/**
 * PostScript Encoding vector.
 *
 * An encoding maps character codes (0-255) to glyph names.
 *
 * Ported from Apache PDFBox's fontbox/encoding/Encoding.java
 */

/**
 * A PostScript encoding vector that maps character codes to glyph names.
 */
export interface Encoding {
  /**
   * Get the glyph name for a character code.
   * @param code - Character code (0-255)
   * @returns The glyph name, or ".notdef" if not mapped
   */
  getName(code: number): string;

  /**
   * Get the character code for a glyph name.
   * @param name - The glyph name
   * @returns The character code, or undefined if not mapped
   */
  getCode(name: string): number | undefined;

  /**
   * Get an unmodifiable view of the code to name mapping.
   * @returns Map from character codes to glyph names
   */
  getCodeToNameMap(): ReadonlyMap<number, string>;
}

/**
 * Mutable encoding builder for constructing encodings.
 */
export class EncodingBuilder implements Encoding {
  private readonly codeToName = new Map<number, string>();
  private readonly nameToCode = new Map<string, number>();

  /**
   * Add a character encoding mapping.
   * @param code - Character code (0-255)
   * @param name - Glyph name
   */
  addCharacterEncoding(code: number, name: string): void {
    this.codeToName.set(code, name);
    this.nameToCode.set(name, code);
  }

  /**
   * Get the glyph name for a character code.
   * @param code - Character code (0-255)
   * @returns The glyph name, or ".notdef" if not mapped
   */
  getName(code: number): string {
    return this.codeToName.get(code) ?? ".notdef";
  }

  /**
   * Get the character code for a glyph name.
   * @param name - The glyph name
   * @returns The character code, or undefined if not mapped
   */
  getCode(name: string): number | undefined {
    return this.nameToCode.get(name);
  }

  /**
   * Get an unmodifiable view of the code to name mapping.
   * @returns Map from character codes to glyph names
   */
  getCodeToNameMap(): ReadonlyMap<number, string> {
    return this.codeToName;
  }
}

/**
 * Create an encoding from a code-to-name map.
 * @param codeToName - Map from character codes to glyph names
 * @returns An Encoding instance
 */
export function createEncodingFromMap(codeToName: ReadonlyMap<number, string>): Encoding {
  const builder = new EncodingBuilder();

  for (const [code, name] of codeToName) {
    builder.addCharacterEncoding(code, name);
  }

  return builder;
}

/**
 * Create an encoding from an array of [code, name] pairs.
 * @param entries - Array of [code, name] pairs
 * @returns An Encoding instance
 */
export function createEncodingFromEntries(
  entries: ReadonlyArray<readonly [number, string]>,
): Encoding {
  const builder = new EncodingBuilder();

  for (const [code, name] of entries) {
    builder.addCharacterEncoding(code, name);
  }

  return builder;
}
