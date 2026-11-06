/**
 * AFM (Adobe Font Metrics) Parser.
 *
 * Ported from Apache PDFBox's fontbox/afm/AFMParser.java
 *
 * @see https://partners.adobe.com/asn/developer/type/ AFM Documentation
 */

import type { FontMetrics } from "./font-metrics.ts";
import {
  addCharMetric,
  createFontMetricsBuilder,
  type FontMetricsBuilder,
  freezeFontMetrics,
} from "./font-metrics.ts";
import {
  type Composite,
  createBoundingBox,
  createCharMetricBuilder,
  createComposite,
  createCompositePart,
  createKernPair,
  createLigature,
  createTrackKern,
  freezeCharMetric,
  type KernPair,
} from "./types.ts";

// AFM Keywords
const START_FONT_METRICS = "StartFontMetrics";
const END_FONT_METRICS = "EndFontMetrics";
const FONT_NAME = "FontName";
const FULL_NAME = "FullName";
const FAMILY_NAME = "FamilyName";
const WEIGHT = "Weight";
const FONT_BBOX = "FontBBox";
const VERSION = "Version";
const NOTICE = "Notice";
const ENCODING_SCHEME = "EncodingScheme";
const MAPPING_SCHEME = "MappingScheme";
const ESC_CHAR = "EscChar";
const CHARACTER_SET = "CharacterSet";
const CHARACTERS = "Characters";
const IS_BASE_FONT = "IsBaseFont";
const V_VECTOR = "VVector";
const IS_FIXED_V = "IsFixedV";
const CAP_HEIGHT = "CapHeight";
const X_HEIGHT = "XHeight";
const ASCENDER = "Ascender";
const DESCENDER = "Descender";
const UNDERLINE_POSITION = "UnderlinePosition";
const UNDERLINE_THICKNESS = "UnderlineThickness";
const ITALIC_ANGLE = "ItalicAngle";
const CHAR_WIDTH = "CharWidth";
const IS_FIXED_PITCH = "IsFixedPitch";
const COMMENT = "Comment";
const STD_HW = "StdHW";
const STD_VW = "StdVW";

// Character metrics
const START_CHAR_METRICS = "StartCharMetrics";
const END_CHAR_METRICS = "EndCharMetrics";
const CHARMETRICS_C = "C";
const CHARMETRICS_CH = "CH";
const CHARMETRICS_WX = "WX";
const CHARMETRICS_W0X = "W0X";
const CHARMETRICS_W1X = "W1X";
const CHARMETRICS_WY = "WY";
const CHARMETRICS_W0Y = "W0Y";
const CHARMETRICS_W1Y = "W1Y";
const CHARMETRICS_W = "W";
const CHARMETRICS_W0 = "W0";
const CHARMETRICS_W1 = "W1";
const CHARMETRICS_VV = "VV";
const CHARMETRICS_N = "N";
const CHARMETRICS_B = "B";
const CHARMETRICS_L = "L";

// Kerning
const START_KERN_DATA = "StartKernData";
const END_KERN_DATA = "EndKernData";
const START_TRACK_KERN = "StartTrackKern";
const END_TRACK_KERN = "EndTrackKern";
const START_KERN_PAIRS = "StartKernPairs";
const START_KERN_PAIRS0 = "StartKernPairs0";
const START_KERN_PAIRS1 = "StartKernPairs1";
const END_KERN_PAIRS = "EndKernPairs";
const KERN_PAIR_KP = "KP";
const KERN_PAIR_KPH = "KPH";
const KERN_PAIR_KPX = "KPX";
const KERN_PAIR_KPY = "KPY";

// Composites
const START_COMPOSITES = "StartComposites";
const END_COMPOSITES = "EndComposites";
const CC = "CC";
const PCC = "PCC";

/**
 * Parser options.
 */
export interface AFMParserOptions {
  /**
   * Parse only a reduced subset of data (skip kerning and composites).
   * Useful when you only need character metrics.
   */
  reducedDataset?: boolean;
}

/**
 * Parse AFM data from a Uint8Array.
 *
 * @param data - The AFM file contents
 * @param options - Parser options
 * @returns The parsed FontMetrics
 * @throws {Error} if the AFM is malformed
 */
export function parseAFM(data: Uint8Array, options: AFMParserOptions = {}): FontMetrics {
  const parser = new AFMParser(data, options);

  return parser.parse();
}

/**
 * Internal parser class.
 */
class AFMParser {
  private readonly data: Uint8Array;
  private readonly reducedDataset: boolean;
  private pos = 0;

  constructor(data: Uint8Array, options: AFMParserOptions = {}) {
    this.data = data;
    this.reducedDataset = options.reducedDataset ?? false;
  }

  /**
   * Parse the AFM document.
   */
  parse(): FontMetrics {
    return this.parseFontMetrics();
  }

  private parseFontMetrics(): FontMetrics {
    this.readCommand(START_FONT_METRICS);
    const builder = createFontMetricsBuilder();
    builder.afmVersion = this.readFloat();

    let charMetricsRead = false;

    for (;;) {
      const nextCommand = this.readString();
      if (nextCommand === END_FONT_METRICS) {
        break;
      }

      switch (nextCommand) {
        case FONT_NAME:
          builder.fontName = this.readLine();
          break;
        case FULL_NAME:
          builder.fullName = this.readLine();
          break;
        case FAMILY_NAME:
          builder.familyName = this.readLine();
          break;
        case WEIGHT:
          builder.weight = this.readLine();
          break;
        case FONT_BBOX:
          builder.fontBBox = createBoundingBox(
            this.readFloat(),
            this.readFloat(),
            this.readFloat(),
            this.readFloat(),
          );
          break;
        case VERSION:
          builder.fontVersion = this.readLine();
          break;
        case NOTICE:
          builder.notice = this.readLine();
          break;
        case ENCODING_SCHEME:
          builder.encodingScheme = this.readLine();
          break;
        case MAPPING_SCHEME:
          builder.mappingScheme = this.readInt();
          break;
        case ESC_CHAR:
          builder.escChar = this.readInt();
          break;
        case CHARACTER_SET:
          builder.characterSet = this.readLine();
          break;
        case CHARACTERS:
          builder.characters = this.readInt();
          break;
        case IS_BASE_FONT:
          builder.isBaseFont = this.readBoolean();
          break;
        case V_VECTOR:
          builder.vVector = [this.readFloat(), this.readFloat()];
          break;
        case IS_FIXED_V:
          builder.isFixedV = this.readBoolean();
          break;
        case CAP_HEIGHT:
          builder.capHeight = this.readFloat();
          break;
        case X_HEIGHT:
          builder.xHeight = this.readFloat();
          break;
        case ASCENDER:
          builder.ascender = this.readFloat();
          break;
        case DESCENDER:
          builder.descender = this.readFloat();
          break;
        case STD_HW:
          builder.standardHorizontalWidth = this.readFloat();
          break;
        case STD_VW:
          builder.standardVerticalWidth = this.readFloat();
          break;
        case COMMENT:
          builder.comments.push(this.readLine());
          break;
        case UNDERLINE_POSITION:
          builder.underlinePosition = this.readFloat();
          break;
        case UNDERLINE_THICKNESS:
          builder.underlineThickness = this.readFloat();
          break;
        case ITALIC_ANGLE:
          builder.italicAngle = this.readFloat();
          break;
        case CHAR_WIDTH:
          builder.charWidth = [this.readFloat(), this.readFloat()];
          break;
        case IS_FIXED_PITCH:
          builder.isFixedPitch = this.readBoolean();
          break;
        case START_CHAR_METRICS:
          charMetricsRead = this.parseCharMetrics(builder);
          break;
        case START_KERN_DATA:
          if (!this.reducedDataset) {
            this.parseKernData(builder);
          }

          break;
        case START_COMPOSITES:
          if (!this.reducedDataset) {
            this.parseComposites(builder);
          }

          break;
        default:
          if (!this.reducedDataset || !charMetricsRead) {
            throw new Error(`Unknown AFM key '${nextCommand}'`);
          }
        // In reduced dataset mode after char metrics, ignore unknown commands
      }
    }

    return freezeFontMetrics(builder);
  }

  private parseCharMetrics(builder: FontMetricsBuilder): boolean {
    const count = this.readInt();

    for (let i = 0; i < count; i++) {
      const metric = this.parseCharMetric();
      addCharMetric(builder, metric);
    }

    this.readCommand(END_CHAR_METRICS);

    return true;
  }

  private parseCharMetric(): ReturnType<typeof freezeCharMetric> {
    const charMetric = createCharMetricBuilder();
    const metrics = this.readLine();
    const tokens = this.tokenize(metrics);

    let i = 0;

    while (i < tokens.length) {
      const nextCommand = tokens[i++];

      switch (nextCommand) {
        case CHARMETRICS_C:
          charMetric.characterCode = this.parseInt(tokens[i++]);
          this.verifySemicolon(tokens, i++);
          break;
        case CHARMETRICS_CH:
          charMetric.characterCode = this.parseInt(tokens[i++], 16);
          this.verifySemicolon(tokens, i++);
          break;
        case CHARMETRICS_WX:
          charMetric.wx = this.parseFloat(tokens[i++]);
          this.verifySemicolon(tokens, i++);
          break;
        case CHARMETRICS_W0X:
          charMetric.w0x = this.parseFloat(tokens[i++]);
          this.verifySemicolon(tokens, i++);
          break;
        case CHARMETRICS_W1X:
          charMetric.w1x = this.parseFloat(tokens[i++]);
          this.verifySemicolon(tokens, i++);
          break;
        case CHARMETRICS_WY:
          charMetric.wy = this.parseFloat(tokens[i++]);
          this.verifySemicolon(tokens, i++);
          break;
        case CHARMETRICS_W0Y:
          charMetric.w0y = this.parseFloat(tokens[i++]);
          this.verifySemicolon(tokens, i++);
          break;
        case CHARMETRICS_W1Y:
          charMetric.w1y = this.parseFloat(tokens[i++]);
          this.verifySemicolon(tokens, i++);
          break;
        case CHARMETRICS_W:
          charMetric.w = [this.parseFloat(tokens[i++]), this.parseFloat(tokens[i++])];
          this.verifySemicolon(tokens, i++);
          break;
        case CHARMETRICS_W0:
          charMetric.w0 = [this.parseFloat(tokens[i++]), this.parseFloat(tokens[i++])];
          this.verifySemicolon(tokens, i++);
          break;
        case CHARMETRICS_W1:
          charMetric.w1 = [this.parseFloat(tokens[i++]), this.parseFloat(tokens[i++])];
          this.verifySemicolon(tokens, i++);
          break;
        case CHARMETRICS_VV:
          charMetric.vv = [this.parseFloat(tokens[i++]), this.parseFloat(tokens[i++])];
          this.verifySemicolon(tokens, i++);
          break;
        case CHARMETRICS_N:
          charMetric.name = tokens[i++];
          this.verifySemicolon(tokens, i++);
          break;
        case CHARMETRICS_B:
          charMetric.boundingBox = createBoundingBox(
            this.parseFloat(tokens[i++]),
            this.parseFloat(tokens[i++]),
            this.parseFloat(tokens[i++]),
            this.parseFloat(tokens[i++]),
          );

          this.verifySemicolon(tokens, i++);
          break;
        case CHARMETRICS_L:
          charMetric.ligatures.push(createLigature(tokens[i++], tokens[i++]));
          this.verifySemicolon(tokens, i++);
          break;
        default:
          throw new Error(`Unknown CharMetrics command '${nextCommand}'`);
      }
    }

    return freezeCharMetric(charMetric);
  }

  private parseKernData(builder: FontMetricsBuilder): void {
    for (;;) {
      const nextCommand = this.readString();

      if (nextCommand === END_KERN_DATA) {
        break;
      }

      switch (nextCommand) {
        case START_TRACK_KERN: {
          const count = this.readInt();

          for (let i = 0; i < count; i++) {
            builder.trackKern.push(
              createTrackKern(
                this.readInt(),
                this.readFloat(),
                this.readFloat(),
                this.readFloat(),
                this.readFloat(),
              ),
            );
          }

          this.readCommand(END_TRACK_KERN);

          break;
        }
        case START_KERN_PAIRS:
          this.parseKernPairs(builder.kernPairs);
          break;
        case START_KERN_PAIRS0:
          this.parseKernPairs(builder.kernPairs0);
          break;
        case START_KERN_PAIRS1:
          this.parseKernPairs(builder.kernPairs1);
          break;
        default:
          throw new Error(`Unknown kerning data type '${nextCommand}'`);
      }
    }
  }

  private parseKernPairs(kernPairs: KernPair[]): void {
    const count = this.readInt();

    for (let i = 0; i < count; i++) {
      kernPairs.push(this.parseKernPair());
    }

    this.readCommand(END_KERN_PAIRS);
  }

  private parseKernPair(): KernPair {
    const cmd = this.readString();

    switch (cmd) {
      case KERN_PAIR_KP:
        return createKernPair(
          this.readString(),
          this.readString(),
          this.readFloat(),
          this.readFloat(),
        );
      case KERN_PAIR_KPH:
        return createKernPair(
          this.hexToString(this.readString()),
          this.hexToString(this.readString()),
          this.readFloat(),
          this.readFloat(),
        );
      case KERN_PAIR_KPX:
        return createKernPair(this.readString(), this.readString(), this.readFloat(), 0);
      case KERN_PAIR_KPY:
        return createKernPair(this.readString(), this.readString(), 0, this.readFloat());
      default:
        throw new Error(`Error expected kern pair command actual='${cmd}'`);
    }
  }

  private parseComposites(builder: FontMetricsBuilder): void {
    const count = this.readInt();

    for (let i = 0; i < count; i++) {
      builder.composites.push(this.parseComposite());
    }

    this.readCommand(END_COMPOSITES);
  }

  private parseComposite(): Composite {
    const partData = this.readLine();
    const tokens = this.tokenize(partData);

    let i = 0;

    const cc = tokens[i++];

    if (cc !== CC) {
      throw new Error(`Expected '${CC}' actual='${cc}'`);
    }

    const name = tokens[i++];
    const composite = createComposite(name);
    const partCount = this.parseInt(tokens[i++]);

    for (let j = 0; j < partCount; j++) {
      const pcc = tokens[i++];

      if (pcc !== PCC) {
        throw new Error(`Expected '${PCC}' actual='${pcc}'`);
      }

      const partName = tokens[i++];
      const x = this.parseInt(tokens[i++]);
      const y = this.parseInt(tokens[i++]);

      composite.parts.push(createCompositePart(partName, x, y));
    }

    return { name: composite.name, parts: composite.parts };
  }

  // Low-level parsing methods

  private hexToString(hexString: string): string {
    if (hexString.length < 2) {
      throw new Error(`Error: Expected hex string of length >= 2 not='${hexString}'`);
    }

    if (hexString[0] !== "<" || hexString[hexString.length - 1] !== ">") {
      throw new Error(`String should be enclosed by angle brackets '${hexString}'`);
    }

    const hex = hexString.slice(1, -1);
    const bytes = new Uint8Array(hex.length / 2);

    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = Number.parseInt(hex.slice(i, i + 2), 16);
    }

    // ISO-8859-1 decoding
    return String.fromCharCode(...bytes);
  }

  private tokenize(line: string): string[] {
    // Split on whitespace and semicolons, keeping semicolons as tokens
    const tokens: string[] = [];
    let current = "";

    for (const char of line) {
      if (char === " " || char === "\t") {
        if (current) {
          tokens.push(current);
          current = "";
        }
      } else if (char === ";") {
        if (current) {
          tokens.push(current);
          current = "";
        }
        tokens.push(";");
      } else {
        current += char;
      }
    }

    if (current) {
      tokens.push(current);
    }

    return tokens;
  }

  private verifySemicolon(tokens: string[], index: number): void {
    if (index >= tokens.length) {
      throw new Error("CharMetrics is missing a semicolon after a command");
    }

    if (tokens[index] !== ";") {
      throw new Error(`Error: Expected semicolon in stream actual='${tokens[index]}'`);
    }
  }

  private readBoolean(): boolean {
    const value = this.readString();

    return value === "true";
  }

  private readInt(): number {
    return this.parseInt(this.readString());
  }

  private parseInt(value: string, radix = 10): number {
    // Validate that the entire string is a valid integer
    const trimmed = value.trim();

    if (!/^-?\d+$/.test(trimmed) && radix === 10) {
      throw new Error(`Error parsing AFM document: ${value}`);
    }

    if (radix === 16 && !/^-?[0-9a-fA-F]+$/.test(trimmed)) {
      throw new Error(`Error parsing AFM document: ${value}`);
    }

    const result = Number.parseInt(trimmed, radix);

    if (Number.isNaN(result)) {
      throw new Error(`Error parsing AFM document: ${value}`);
    }

    return result;
  }

  private readFloat(): number {
    return this.parseFloat(this.readString());
  }

  private parseFloat(value: string): number {
    // Validate that the entire string is a valid float
    const trimmed = value.trim();

    // Allow integers or decimals, with optional sign
    if (!/^-?\d+(\.\d+)?$/.test(trimmed)) {
      throw new Error(`Error parsing AFM document: ${value}`);
    }

    const result = Number.parseFloat(trimmed);

    if (Number.isNaN(result)) {
      throw new Error(`Error parsing AFM document: ${value}`);
    }

    return result;
  }

  private readLine(): string {
    // Skip leading whitespace
    this.skipWhitespace();

    const start = this.pos;

    while (this.pos < this.data.length && !this.isEOL(this.data[this.pos])) {
      this.pos++;
    }

    return this.decodeString(this.data.subarray(start, this.pos));
  }

  private readString(): string {
    // Skip leading whitespace
    this.skipWhitespace();

    const start = this.pos;

    while (this.pos < this.data.length && !this.isWhitespace(this.data[this.pos])) {
      this.pos++;
    }

    return this.decodeString(this.data.subarray(start, this.pos));
  }

  private readCommand(expectedCommand: string): void {
    const command = this.readString();

    if (command !== expectedCommand) {
      throw new Error(`Error: Expected '${expectedCommand}' actual '${command}'`);
    }
  }

  private skipWhitespace(): void {
    while (this.pos < this.data.length && this.isWhitespace(this.data[this.pos])) {
      this.pos++;
    }
  }

  private isEOL(char: number): boolean {
    return char === 0x0d || char === 0x0a;
  }

  private isWhitespace(char: number): boolean {
    return char === 0x20 || char === 0x09 || char === 0x0d || char === 0x0a;
  }

  private decodeString(bytes: Uint8Array): string {
    // AFM files are ASCII/ISO-8859-1
    return String.fromCharCode(...bytes);
  }
}
