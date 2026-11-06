/**
 * CFF Charset types and implementations.
 *
 * A charset maps GIDs (Glyph IDs) to SIDs (String IDs) for Type1 fonts,
 * or GIDs to CIDs (Character IDs) for CID fonts.
 */

import { getStandardString } from "./standard-strings.ts";

/**
 * Interface for CFF charsets.
 */
export interface CFFCharset {
  /** Whether this charset belongs to a CID font */
  readonly isCIDFont: boolean;

  /** Get the SID for a given GID (Type1 fonts) */
  getSIDForGID(gid: number): number;

  /** Get the GID for a given SID (Type1 fonts) */
  getGIDForSID(sid: number): number;

  /** Get the CID for a given GID (CID fonts) */
  getCIDForGID(gid: number): number;

  /** Get the GID for a given CID (CID fonts) */
  getGIDForCID(cid: number): number;

  /** Get the SID for a PostScript glyph name */
  getSID(name: string): number;

  /** Get the glyph name for a given GID */
  getNameForGID(gid: number): string | undefined;
}

/**
 * Base class for Type1 (non-CID) charsets.
 */
export class CFFCharsetType1 implements CFFCharset {
  readonly isCIDFont = false;

  // GID -> SID mapping
  protected readonly gidToSid: number[] = [];
  // GID -> name mapping
  protected readonly gidToName: string[] = [];
  // SID -> GID mapping
  protected readonly sidToGid = new Map<number, number>();
  // name -> SID mapping
  protected readonly nameToSid = new Map<string, number>();

  /**
   * Add a GID/SID/name mapping.
   */
  addSID(gid: number, sid: number, name: string): void {
    this.gidToSid[gid] = sid;
    this.gidToName[gid] = name;
    this.sidToGid.set(sid, gid);
    this.nameToSid.set(name, sid);
  }

  getSIDForGID(gid: number): number {
    return this.gidToSid[gid] ?? 0;
  }

  getGIDForSID(sid: number): number {
    return this.sidToGid.get(sid) ?? 0;
  }

  getCIDForGID(_gid: number): number {
    return 0; // Not applicable for Type1 fonts
  }

  getGIDForCID(_cid: number): number {
    return 0; // Not applicable for Type1 fonts
  }

  getSID(name: string): number {
    return this.nameToSid.get(name) ?? 0;
  }

  getNameForGID(gid: number): string | undefined {
    return this.gidToName[gid];
  }
}

/**
 * Base class for CID font charsets.
 */
export class CFFCharsetCID implements CFFCharset {
  readonly isCIDFont = true;

  // GID -> CID mapping
  protected readonly gidToCid: number[] = [];
  // CID -> GID mapping
  protected readonly cidToGid = new Map<number, number>();

  /**
   * Add a GID/CID mapping.
   */
  addCID(gid: number, cid: number): void {
    this.gidToCid[gid] = cid;
    this.cidToGid.set(cid, gid);
  }

  getSIDForGID(_gid: number): number {
    return 0; // Not applicable for CID fonts
  }

  getGIDForSID(_sid: number): number {
    return 0; // Not applicable for CID fonts
  }

  getCIDForGID(gid: number): number {
    return this.gidToCid[gid] ?? 0;
  }

  getGIDForCID(cid: number): number {
    return this.cidToGid.get(cid) ?? 0;
  }

  getSID(_name: string): number {
    return 0; // Not applicable for CID fonts
  }

  getNameForGID(_gid: number): string | undefined {
    return undefined; // CID fonts don't have glyph names
  }
}

/**
 * ISO Adobe charset (charset ID 0).
 * Contains the first 229 glyphs of the standard string table.
 */
class ISOAdobeCharset extends CFFCharsetType1 {
  private static _instance: ISOAdobeCharset | undefined;

  private constructor() {
    super();

    // ISO Adobe charset: SID 0-228 map to GID 0-228
    for (let gid = 0; gid <= 228; gid++) {
      const name = getStandardString(gid);

      if (name) {
        this.addSID(gid, gid, name);
      }
    }
  }

  static getInstance(): ISOAdobeCharset {
    if (!ISOAdobeCharset._instance) {
      ISOAdobeCharset._instance = new ISOAdobeCharset();
    }

    return ISOAdobeCharset._instance;
  }
}

/**
 * Expert charset (charset ID 1).
 */
class ExpertCharset extends CFFCharsetType1 {
  private static _instance: ExpertCharset | undefined;

  // Expert charset SID table
  private static readonly SIDS = [
    0, 1, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 13, 14, 15, 99, 239, 240, 241, 242, 243,
    244, 245, 246, 247, 248, 27, 28, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260,
    261, 262, 263, 264, 265, 266, 109, 110, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277,
    278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296,
    297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315,
    316, 317, 318, 158, 155, 163, 319, 320, 321, 322, 323, 324, 325, 326, 150, 164, 169, 327, 328,
    329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347,
    348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366,
    367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378,
  ];

  private constructor() {
    super();

    for (let gid = 0; gid < ExpertCharset.SIDS.length; gid++) {
      const sid = ExpertCharset.SIDS[gid];
      const name = getStandardString(sid);

      if (name) {
        this.addSID(gid, sid, name);
      }
    }
  }

  static getInstance(): ExpertCharset {
    if (!ExpertCharset._instance) {
      ExpertCharset._instance = new ExpertCharset();
    }

    return ExpertCharset._instance;
  }
}

/**
 * Expert Subset charset (charset ID 2).
 */
class ExpertSubsetCharset extends CFFCharsetType1 {
  private static _instance: ExpertSubsetCharset | undefined;

  // Expert Subset charset SID table
  private static readonly SIDS = [
    0, 1, 231, 232, 235, 236, 237, 238, 13, 14, 15, 99, 239, 240, 241, 242, 243, 244, 245, 246, 247,
    248, 27, 28, 249, 250, 251, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265,
    266, 109, 110, 267, 268, 269, 270, 272, 300, 301, 302, 305, 314, 315, 158, 155, 163, 320, 321,
    322, 323, 324, 325, 326, 150, 164, 169, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337,
    338, 339, 340, 341, 342, 343, 344, 345, 346,
  ];

  private constructor() {
    super();

    for (let gid = 0; gid < ExpertSubsetCharset.SIDS.length; gid++) {
      const sid = ExpertSubsetCharset.SIDS[gid];
      const name = getStandardString(sid);

      if (name) {
        this.addSID(gid, sid, name);
      }
    }
  }

  static getInstance(): ExpertSubsetCharset {
    if (!ExpertSubsetCharset._instance) {
      ExpertSubsetCharset._instance = new ExpertSubsetCharset();
    }

    return ExpertSubsetCharset._instance;
  }
}

/**
 * Get a predefined charset by ID.
 * @param id Charset ID (0 = ISO Adobe, 1 = Expert, 2 = Expert Subset)
 * @param isCIDFont Whether this is a CID font
 * @returns The charset, or undefined if ID is not a predefined charset
 */
export function getPredefinedCharset(id: number, isCIDFont: boolean): CFFCharset | undefined {
  // Predefined charsets are only for Type1 fonts
  if (isCIDFont) {
    return undefined;
  }

  switch (id) {
    case 0:
      return ISOAdobeCharset.getInstance();
    case 1:
      return ExpertCharset.getInstance();
    case 2:
      return ExpertSubsetCharset.getInstance();
    default:
      return undefined;
  }
}

/**
 * Create an empty charset for Type1 fonts.
 */
export function createType1Charset(): CFFCharsetType1 {
  return new CFFCharsetType1();
}

/**
 * Create an empty charset for CID fonts.
 */
export function createCIDCharset(): CFFCharsetCID {
  return new CFFCharsetCID();
}

/**
 * Embedded charset with range mappings (for format 1 and 2).
 * Used for CID fonts with range-based GID to CID mappings.
 */
export class RangeMappedCharset extends CFFCharsetCID {
  private ranges: Array<{ startGID: number; endGID: number; startCID: number }> = [];

  /**
   * Add a range mapping.
   */
  addRange(startGID: number, firstCID: number, count: number): void {
    const endGID = startGID + count;
    this.ranges.push({ startGID, endGID, startCID: firstCID });

    // Also populate the direct mappings for fast lookups
    for (let i = 0; i <= count; i++) {
      this.addCID(startGID + i, firstCID + i);
    }
  }

  override getCIDForGID(gid: number): number {
    // Check ranges first for efficiency
    for (const range of this.ranges) {
      if (gid >= range.startGID && gid <= range.endGID) {
        return range.startCID + (gid - range.startGID);
      }
    }

    return super.getCIDForGID(gid);
  }

  override getGIDForCID(cid: number): number {
    // Check ranges first for efficiency
    for (const range of this.ranges) {
      const endCID = range.startCID + (range.endGID - range.startGID);

      if (cid >= range.startCID && cid <= endCID) {
        return range.startGID + (cid - range.startCID);
      }
    }

    return super.getGIDForCID(cid);
  }
}
