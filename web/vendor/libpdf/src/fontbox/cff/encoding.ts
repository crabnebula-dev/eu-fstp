/**
 * CFF Encoding types and implementations.
 *
 * An encoding maps character codes to glyph names (via SIDs).
 * Only used by Type1-equivalent CFF fonts, not CID fonts.
 */

import { getStandardString } from "./standard-strings.ts";

/**
 * Interface for CFF encodings.
 */
export interface CFFEncoding {
  /** Get the glyph name for a character code */
  getName(code: number): string | undefined;

  /** Get the character code for a glyph name */
  getCode(name: string): number | undefined;
}

/**
 * Base class for CFF encodings.
 */
export class CFFEncodingBase implements CFFEncoding {
  // code -> name mapping
  protected readonly codeToName = new Map<number, string>();
  // name -> code mapping
  protected readonly nameToCode = new Map<string, number>();

  /**
   * Add a code/name mapping.
   */
  add(code: number, sid: number, name?: string): void {
    const glyphName = name ?? getStandardString(sid) ?? `.sid${sid}`;
    this.codeToName.set(code, glyphName);

    if (!this.nameToCode.has(glyphName)) {
      this.nameToCode.set(glyphName, code);
    }
  }

  getName(code: number): string | undefined {
    return this.codeToName.get(code);
  }

  getCode(name: string): number | undefined {
    return this.nameToCode.get(name);
  }
}

/**
 * Standard Encoding (encoding ID 0).
 * Maps codes 32-126 and 161-255 to standard glyph names.
 */
class StandardEncoding extends CFFEncodingBase {
  private static _instance: StandardEncoding | undefined;

  // Standard encoding: code -> SID mapping
  // Codes 0-31 and 127-160 map to .notdef (SID 0)
  private static readonly CODE_TO_SID: readonly number[] = [
    // 0-31: .notdef
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // 32-126: space through asciitilde
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74,
    75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
    // 127-160: .notdef
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0,
    // 161-175
    96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
    // 176
    0,
    // 177-189
    111, 112, 113, 114, 0, 115, 116, 117, 118, 119, 120, 121, 122,
    // 190
    0,
    // 191
    123,
    // 192
    0,
    // 193-200
    124, 125, 126, 127, 128, 129, 130, 131,
    // 201
    0,
    // 202-203
    132, 133,
    // 204
    0,
    // 205-208
    134, 135, 136, 137,
    // 209-224
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // 225
    138,
    // 226
    0,
    // 227
    139,
    // 228-231
    0, 0, 0, 0,
    // 232-235
    140, 141, 142, 143,
    // 236-240
    0, 0, 0, 0, 0,
    // 241
    144,
    // 242-244
    0, 0, 0,
    // 245
    145,
    // 246-247
    0, 0,
    // 248-251
    146, 147, 148, 149,
    // 252-255
    0, 0, 0, 0,
  ];

  private constructor() {
    super();

    for (let code = 0; code < StandardEncoding.CODE_TO_SID.length; code++) {
      const sid = StandardEncoding.CODE_TO_SID[code];

      this.add(code, sid);
    }
  }

  static getInstance(): StandardEncoding {
    if (!StandardEncoding._instance) {
      StandardEncoding._instance = new StandardEncoding();
    }

    return StandardEncoding._instance;
  }
}

/**
 * Expert Encoding (encoding ID 1).
 */
class ExpertEncoding extends CFFEncodingBase {
  private static _instance: ExpertEncoding | undefined;

  // Expert encoding: code -> SID mapping
  private static readonly CODE_TO_SID: ReadonlyArray<[number, number]> = [
    [32, 1],
    [33, 229],
    [34, 230],
    [35, 231],
    [36, 232],
    [37, 233],
    [38, 234],
    [39, 235],
    [40, 236],
    [41, 237],
    [42, 238],
    [43, 13],
    [44, 14],
    [45, 15],
    [46, 99],
    [47, 239],
    [48, 240],
    [49, 241],
    [50, 242],
    [51, 243],
    [52, 244],
    [53, 245],
    [54, 246],
    [55, 247],
    [56, 248],
    [57, 27],
    [58, 28],
    [59, 249],
    [60, 250],
    [61, 251],
    [62, 252],
    [63, 253],
    [64, 254],
    [65, 255],
    [66, 256],
    [67, 257],
    [68, 258],
    [69, 259],
    [70, 260],
    [71, 261],
    [72, 262],
    [73, 263],
    [74, 264],
    [75, 265],
    [76, 266],
    [77, 109],
    [78, 110],
    [79, 267],
    [80, 268],
    [81, 269],
    [82, 270],
    [83, 271],
    [84, 272],
    [85, 273],
    [86, 274],
    [87, 275],
    [88, 276],
    [89, 277],
    [90, 278],
    [91, 279],
    [92, 280],
    [93, 281],
    [94, 282],
    [95, 283],
    [96, 284],
    [97, 285],
    [98, 286],
    [99, 287],
    [100, 288],
    [101, 289],
    [102, 290],
    [103, 291],
    [104, 292],
    [105, 293],
    [106, 294],
    [107, 295],
    [108, 296],
    [109, 297],
    [110, 298],
    [111, 299],
    [112, 300],
    [113, 301],
    [114, 302],
    [115, 303],
    [116, 304],
    [117, 305],
    [118, 306],
    [119, 307],
    [120, 308],
    [121, 309],
    [122, 310],
    [123, 311],
    [124, 312],
    [125, 313],
    [126, 314],
    [161, 315],
    [162, 316],
    [163, 317],
    [164, 318],
    [165, 158],
    [166, 155],
    [167, 163],
    [168, 319],
    [169, 320],
    [170, 321],
    [171, 322],
    [172, 323],
    [173, 324],
    [174, 325],
    [175, 326],
    [176, 150],
    [177, 164],
    [178, 169],
    [179, 327],
    [180, 328],
    [181, 329],
    [182, 330],
    [183, 331],
    [184, 332],
    [185, 333],
    [186, 334],
    [187, 335],
    [188, 336],
    [189, 337],
    [190, 338],
    [191, 339],
    [192, 340],
    [193, 341],
    [194, 342],
    [195, 343],
    [196, 344],
    [197, 345],
    [198, 346],
    [199, 347],
    [200, 348],
    [201, 349],
    [202, 350],
    [203, 351],
    [204, 352],
    [205, 353],
    [206, 354],
    [207, 355],
    [208, 356],
    [209, 357],
    [210, 358],
    [211, 359],
    [212, 360],
    [213, 361],
    [214, 362],
    [215, 363],
    [216, 364],
    [217, 365],
    [218, 366],
    [219, 367],
    [220, 368],
    [221, 369],
    [222, 370],
    [223, 371],
    [224, 372],
    [225, 373],
    [226, 374],
    [227, 375],
    [228, 376],
    [229, 377],
    [230, 378],
  ];

  private constructor() {
    super();

    // Initialize with .notdef for all codes
    for (let code = 0; code < 256; code++) {
      this.add(code, 0);
    }

    // Override with expert encoding
    for (const [code, sid] of ExpertEncoding.CODE_TO_SID) {
      this.add(code, sid);
    }
  }

  static getInstance(): ExpertEncoding {
    if (!ExpertEncoding._instance) {
      ExpertEncoding._instance = new ExpertEncoding();
    }

    return ExpertEncoding._instance;
  }
}

/**
 * Get a predefined encoding by ID.
 * @param id Encoding ID (0 = Standard, 1 = Expert)
 * @returns The encoding, or undefined if not a predefined encoding
 */
export function getPredefinedEncoding(id: number): CFFEncoding | undefined {
  switch (id) {
    case 0:
      return StandardEncoding.getInstance();
    case 1:
      return ExpertEncoding.getInstance();
    default:
      return undefined;
  }
}

/**
 * Create an empty custom encoding.
 */
export function createEncoding(): CFFEncodingBase {
  return new CFFEncodingBase();
}
