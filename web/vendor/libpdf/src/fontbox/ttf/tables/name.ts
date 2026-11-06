/**
 * The 'name' table - Naming Table.
 *
 * Contains human-readable names for font metadata.
 * Required in all TrueType fonts.
 *
 * Based on Apache PDFBox fontbox NamingTable.java and NameRecord.java
 * @see https://learn.microsoft.com/en-us/typography/opentype/spec/name
 */

import type { TableParseContext, TTFTable } from "../types.ts";

// Platform IDs
export const PLATFORM_UNICODE = 0;
export const PLATFORM_MACINTOSH = 1;
export const PLATFORM_ISO = 2;
export const PLATFORM_WINDOWS = 3;

// Unicode encoding IDs
export const ENCODING_UNICODE_1_0 = 0;
export const ENCODING_UNICODE_1_1 = 1;
export const ENCODING_UNICODE_2_0_BMP = 3;
export const ENCODING_UNICODE_2_0_FULL = 4;

// Unicode language IDs
export const LANGUAGE_UNICODE = 0;

// Windows encoding IDs
export const ENCODING_WINDOWS_SYMBOL = 0;
export const ENCODING_WINDOWS_UNICODE_BMP = 1;
export const ENCODING_WINDOWS_UNICODE_UCS4 = 10;

// Windows language IDs
export const LANGUAGE_WINDOWS_EN_US = 0x0409;

// Macintosh encoding IDs
export const ENCODING_MACINTOSH_ROMAN = 0;

// Macintosh language IDs
export const LANGUAGE_MACINTOSH_ENGLISH = 0;

// Name IDs
export const NAME_COPYRIGHT = 0;
export const NAME_FONT_FAMILY = 1;
export const NAME_FONT_SUBFAMILY = 2;
export const NAME_UNIQUE_ID = 3;
export const NAME_FULL_NAME = 4;
export const NAME_VERSION = 5;
export const NAME_POSTSCRIPT_NAME = 6;
export const NAME_TRADEMARK = 7;
export const NAME_MANUFACTURER = 8;
export const NAME_DESIGNER = 9;
export const NAME_DESCRIPTION = 10;
export const NAME_VENDOR_URL = 11;
export const NAME_DESIGNER_URL = 12;
export const NAME_LICENSE = 13;
export const NAME_LICENSE_URL = 14;
export const NAME_TYPOGRAPHIC_FAMILY = 16;
export const NAME_TYPOGRAPHIC_SUBFAMILY = 17;
export const NAME_SAMPLE_TEXT = 19;
export const NAME_WWS_FAMILY = 21;
export const NAME_WWS_SUBFAMILY = 22;

/**
 * A name record in the name table.
 */
export interface NameRecord {
  /** Platform ID */
  readonly platformId: number;
  /** Platform-specific encoding ID */
  readonly encodingId: number;
  /** Language ID */
  readonly languageId: number;
  /** Name ID */
  readonly nameId: number;
  /** The decoded string value */
  readonly string: string;
}

/**
 * Parsed 'name' table data.
 */
export interface NameTable extends TTFTable {
  readonly tag: "name";

  /** All name records */
  readonly records: NameRecord[];

  /**
   * Get a specific name string by IDs.
   * Returns undefined if not found.
   */
  getName(
    nameId: number,
    platformId: number,
    encodingId: number,
    languageId: number,
  ): string | undefined;

  /**
   * Get the best English name for a name ID.
   * Tries Unicode, Windows, then Macintosh platforms.
   */
  getEnglishName(nameId: number): string | undefined;

  /** Font family name (name ID 1) */
  readonly fontFamily: string | undefined;
  /** Font subfamily name (name ID 2) */
  readonly fontSubfamily: string | undefined;
  /** PostScript name (name ID 6) */
  readonly postScriptName: string | undefined;
  /** Full font name (name ID 4) */
  readonly fullName: string | undefined;
  /** Version string (name ID 5) */
  readonly version: string | undefined;
}

/**
 * Parse the 'name' table.
 */
export function parseNameTable(ctx: TableParseContext): NameTable {
  const { data, record } = ctx;
  const tableStart = data.position;
  const tableLength = record.length;

  // Read table header
  const _format = data.readUint16();
  const count = data.readUint16();
  const stringOffset = data.readUint16();

  // Read name records
  const recordsData: Array<{
    platformId: number;
    encodingId: number;
    languageId: number;
    nameId: number;
    length: number;
    offset: number;
  }> = [];

  for (let i = 0; i < count; i++) {
    recordsData.push({
      platformId: data.readUint16(),
      encodingId: data.readUint16(),
      languageId: data.readUint16(),
      nameId: data.readUint16(),
      length: data.readUint16(),
      offset: data.readUint16(),
    });
  }

  // Parse strings
  const records: NameRecord[] = [];
  const stringStorageStart = tableStart + stringOffset;

  for (const rec of recordsData) {
    // Validate offset is within bounds (PDFBOX-2608)
    if (rec.offset + rec.length > tableLength - stringOffset) {
      continue;
    }

    // Read string bytes
    data.moveTo(stringStorageStart + rec.offset);
    const stringBytes = new Uint8Array(rec.length);

    for (let i = 0; i < rec.length; i++) {
      stringBytes[i] = data.readUint8();
    }

    // Decode string based on platform/encoding
    const string = decodeString(stringBytes, rec.platformId, rec.encodingId);

    records.push({
      platformId: rec.platformId,
      encodingId: rec.encodingId,
      languageId: rec.languageId,
      nameId: rec.nameId,
      string,
    });
  }

  // Build lookup map for fast access
  const lookupMap = new Map<string, string>();

  for (const rec of records) {
    const key = `${rec.nameId}:${rec.platformId}:${rec.encodingId}:${rec.languageId}`;
    lookupMap.set(key, rec.string);
  }

  function getName(
    nameId: number,
    platformId: number,
    encodingId: number,
    languageId: number,
  ): string | undefined {
    return lookupMap.get(`${nameId}:${platformId}:${encodingId}:${languageId}`);
  }

  function getEnglishName(nameId: number): string | undefined {
    // Try Unicode platform (various encodings)
    for (let enc = ENCODING_UNICODE_2_0_FULL; enc >= ENCODING_UNICODE_1_0; enc--) {
      const name = getName(nameId, PLATFORM_UNICODE, enc, LANGUAGE_UNICODE);

      if (name) {
        return name;
      }
    }

    // Try Windows Unicode BMP, English US
    const winName = getName(
      nameId,
      PLATFORM_WINDOWS,
      ENCODING_WINDOWS_UNICODE_BMP,
      LANGUAGE_WINDOWS_EN_US,
    );

    if (winName) {
      return winName;
    }

    // Try Macintosh Roman, English
    return getName(
      nameId,
      PLATFORM_MACINTOSH,
      ENCODING_MACINTOSH_ROMAN,
      LANGUAGE_MACINTOSH_ENGLISH,
    );
  }

  // Extract common names
  const fontFamily = getEnglishName(NAME_FONT_FAMILY);
  const fontSubfamily = getEnglishName(NAME_FONT_SUBFAMILY);
  const fullName = getEnglishName(NAME_FULL_NAME);
  const version = getEnglishName(NAME_VERSION);

  // PostScript name - try specific platforms first (per spec)
  let postScriptName = getName(
    NAME_POSTSCRIPT_NAME,
    PLATFORM_MACINTOSH,
    ENCODING_MACINTOSH_ROMAN,
    LANGUAGE_MACINTOSH_ENGLISH,
  );

  if (!postScriptName) {
    postScriptName = getName(
      NAME_POSTSCRIPT_NAME,
      PLATFORM_WINDOWS,
      ENCODING_WINDOWS_UNICODE_BMP,
      LANGUAGE_WINDOWS_EN_US,
    );
  }

  postScriptName = postScriptName?.trim();

  return {
    tag: "name",
    records,
    getName,
    getEnglishName,
    fontFamily,
    fontSubfamily,
    postScriptName,
    fullName,
    version,
  };
}

/**
 * Decode a string based on platform and encoding.
 */
function decodeString(bytes: Uint8Array, platformId: number, encodingId: number): string {
  if (platformId === PLATFORM_WINDOWS) {
    if (encodingId === ENCODING_WINDOWS_SYMBOL || encodingId === ENCODING_WINDOWS_UNICODE_BMP) {
      return decodeUTF16BE(bytes);
    }
  } else if (platformId === PLATFORM_UNICODE) {
    return decodeUTF16BE(bytes);
  } else if (platformId === PLATFORM_ISO) {
    if (encodingId === 0) {
      return decodeASCII(bytes);
    } else if (encodingId === 1) {
      return decodeUTF16BE(bytes);
    }
  }

  // Default: try Latin-1
  return decodeLatin1(bytes);
}

/**
 * Decode UTF-16BE string.
 */
function decodeUTF16BE(bytes: Uint8Array): string {
  const chars: number[] = [];

  for (let i = 0; i < bytes.length - 1; i += 2) {
    const code = (bytes[i] << 8) | bytes[i + 1];

    // Handle surrogate pairs
    if (code >= 0xd800 && code <= 0xdbff && i + 3 < bytes.length) {
      const low = (bytes[i + 2] << 8) | bytes[i + 3];

      if (low >= 0xdc00 && low <= 0xdfff) {
        chars.push(0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00));
        i += 2;

        continue;
      }
    }

    chars.push(code);
  }

  return String.fromCodePoint(...chars);
}

/**
 * Decode ASCII string.
 */
function decodeASCII(bytes: Uint8Array): string {
  return String.fromCharCode(...bytes.filter(b => b < 128));
}

/**
 * Decode Latin-1 (ISO-8859-1) string.
 */
function decodeLatin1(bytes: Uint8Array): string {
  return String.fromCharCode(...bytes);
}
