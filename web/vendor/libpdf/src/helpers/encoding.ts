/**
 * PDF text string encoding/decoding.
 *
 * PDF uses two encodings for text strings:
 * - PDFDocEncoding: Single-byte encoding (similar to Latin-1 with differences)
 * - UTF-16BE with BOM: For Unicode text outside PDFDocEncoding range
 *
 * Detection: If bytes start with 0xFE 0xFF (UTF-16BE BOM), decode as UTF-16BE.
 * Otherwise, decode as PDFDocEncoding.
 */

/** biome-ignore-all lint/complexity/useSimpleNumberKeys: remaps character codes */

import { CR, LF, TAB } from "./chars";

/**
 * PDFDocEncoding to Unicode mapping for bytes 0x80-0x9F.
 * These differ from Latin-1 (which has control chars here).
 * Based on PDF spec Table D.2.
 */
const PDF_DOC_HIGH: Record<number, number> = {
  0x80: 0x2022, // BULLET
  0x81: 0x2020, // DAGGER
  0x82: 0x2021, // DOUBLE DAGGER
  0x83: 0x2026, // HORIZONTAL ELLIPSIS
  0x84: 0x2014, // EM DASH
  0x85: 0x2013, // EN DASH
  0x86: 0x0192, // LATIN SMALL LETTER F WITH HOOK
  0x87: 0x2044, // FRACTION SLASH
  0x88: 0x2039, // SINGLE LEFT-POINTING ANGLE QUOTATION MARK
  0x89: 0x203a, // SINGLE RIGHT-POINTING ANGLE QUOTATION MARK
  0x8a: 0x2212, // MINUS SIGN
  0x8b: 0x2030, // PER MILLE SIGN
  0x8c: 0x201e, // DOUBLE LOW-9 QUOTATION MARK
  0x8d: 0x201c, // LEFT DOUBLE QUOTATION MARK
  0x8e: 0x201d, // RIGHT DOUBLE QUOTATION MARK
  0x8f: 0x2018, // LEFT SINGLE QUOTATION MARK
  0x90: 0x2019, // RIGHT SINGLE QUOTATION MARK
  0x91: 0x201a, // SINGLE LOW-9 QUOTATION MARK
  0x92: 0x2122, // TRADE MARK SIGN
  0x93: 0xfb01, // LATIN SMALL LIGATURE FI
  0x94: 0xfb02, // LATIN SMALL LIGATURE FL
  0x95: 0x0141, // LATIN CAPITAL LETTER L WITH STROKE
  0x96: 0x0152, // LATIN CAPITAL LIGATURE OE
  0x97: 0x0160, // LATIN CAPITAL LETTER S WITH CARON
  0x98: 0x0178, // LATIN CAPITAL LETTER Y WITH DIAERESIS
  0x99: 0x017d, // LATIN CAPITAL LETTER Z WITH CARON
  0x9a: 0x0131, // LATIN SMALL LETTER DOTLESS I
  0x9b: 0x0142, // LATIN SMALL LETTER L WITH STROKE
  0x9c: 0x0153, // LATIN SMALL LIGATURE OE
  0x9d: 0x0161, // LATIN SMALL LETTER S WITH CARON
  0x9e: 0x017e, // LATIN SMALL LETTER Z WITH CARON
  // 0x9F is undefined
  0xa0: 0x20ac, // EURO SIGN
};

/**
 * PDFDocEncoding to Unicode mapping for bytes 0x18-0x1F.
 * These are special accent characters.
 */
const PDF_DOC_LOW: Record<number, number> = {
  0x18: 0x02d8, // BREVE
  0x19: 0x02c7, // CARON
  0x1a: 0x02c6, // MODIFIER LETTER CIRCUMFLEX ACCENT
  0x1b: 0x02d9, // DOT ABOVE
  0x1c: 0x02dd, // DOUBLE ACUTE ACCENT
  0x1d: 0x02db, // OGONEK
  0x1e: 0x02da, // RING ABOVE
  0x1f: 0x02dc, // SMALL TILDE
};

/**
 * Build reverse mapping: Unicode code point -> PDFDocEncoding byte.
 */
function buildReverseMap(): Map<number, number> {
  const map = new Map<number, number>();

  // Add high byte mappings (0x80-0x9F special chars)
  for (const [byte, unicode] of Object.entries(PDF_DOC_HIGH)) {
    map.set(unicode, Number(byte));
  }

  // Add low byte mappings (0x18-0x1F accents)
  for (const [byte, unicode] of Object.entries(PDF_DOC_LOW)) {
    map.set(unicode, Number(byte));
  }

  return map;
}

const UNICODE_TO_PDF_DOC = buildReverseMap();

/**
 * Check if bytes start with UTF-16BE BOM (0xFE 0xFF).
 */
export function hasUtf16BOM(bytes: Uint8Array): boolean {
  return bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff;
}

/**
 * Decode UTF-16BE bytes to string (skips BOM if present).
 */
export function decodeUtf16BE(bytes: Uint8Array): string {
  const start = hasUtf16BOM(bytes) ? 2 : 0;

  const chars: string[] = [];

  for (let i = start; i < bytes.length - 1; i += 2) {
    const code = (bytes[i] << 8) | bytes[i + 1];

    // Handle surrogate pairs
    if (code >= 0xd800 && code <= 0xdbff && i + 3 < bytes.length) {
      const low = (bytes[i + 2] << 8) | bytes[i + 3];

      if (low >= 0xdc00 && low <= 0xdfff) {
        const codePoint = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
        chars.push(String.fromCodePoint(codePoint));

        i += 2;

        continue;
      }
    }

    chars.push(String.fromCharCode(code));
  }

  return chars.join("");
}

/**
 * Decode PDFDocEncoding bytes to string.
 */
export function decodePdfDocEncoding(bytes: Uint8Array): string {
  const chars: string[] = [];

  for (const byte of bytes) {
    if (byte < 0x18) {
      // Control chars - preserve tab, newline, carriage return
      if (byte === 0x09 || byte === 0x0a || byte === 0x0d) {
        chars.push(String.fromCharCode(byte));
      }
      // Skip other control chars
    } else if (byte <= 0x1f) {
      // Special low bytes (accents)
      const code = PDF_DOC_LOW[byte];

      if (code) {
        chars.push(String.fromCharCode(code));
      }
    } else if (byte < 0x80) {
      // ASCII range - direct mapping
      chars.push(String.fromCharCode(byte));
    } else if (byte <= 0xa0) {
      // High bytes with special mapping
      const code = PDF_DOC_HIGH[byte];

      if (code) {
        chars.push(String.fromCharCode(code));
      }
      // 0x9F is undefined, skip
    } else if (byte !== 0xad) {
      // 0xA1-0xFF map to Unicode (same as Latin-1), except 0xAD (undefined)
      chars.push(String.fromCharCode(byte));
    }
  }

  return chars.join("");
}

/**
 * Decode PDF text string bytes (auto-detects encoding).
 */
export function decodeTextString(bytes: Uint8Array): string {
  if (hasUtf16BOM(bytes)) {
    return decodeUtf16BE(bytes);
  }
  return decodePdfDocEncoding(bytes);
}

/**
 * Check if a string can be encoded in PDFDocEncoding.
 */
export function canEncodePdfDoc(text: string): boolean {
  for (const char of text) {
    // biome-ignore lint/style/noNonNullAssertion: char will exist since it's a string
    const code = char.codePointAt(0)!;

    // Check if it's in the reverse mapping (special chars)
    if (UNICODE_TO_PDF_DOC.has(code)) {
      continue;
    }

    // Tab, newline, carriage return are allowed
    if (code === TAB || code === LF || code === CR) {
      continue;
    }

    // ASCII printable range
    if (code >= 0x20 && code <= 0x7f) {
      continue;
    }

    // Latin-1 supplement (0xA1-0xFF, except 0xAD)
    if (code >= 0xa1 && code <= 0xff && code !== 0xad) {
      continue;
    }

    // Character cannot be encoded
    return false;
  }
  return true;
}

/**
 * Encode string as PDFDocEncoding.
 * Returns null if string contains characters not in PDFDocEncoding.
 */
export function encodePdfDocEncoding(text: string): Uint8Array | null {
  const bytes: number[] = [];

  for (const char of text) {
    // biome-ignore lint/style/noNonNullAssertion: char will exist since it's a string
    const code = char.codePointAt(0)!;

    // Check reverse mapping first (for special chars like €, •, —)
    const mapped = UNICODE_TO_PDF_DOC.get(code);

    if (mapped !== undefined) {
      bytes.push(mapped);

      continue;
    }

    // Tab, newline, carriage return
    if (code === TAB || code === LF || code === CR) {
      bytes.push(code);

      continue;
    }

    // ASCII printable range
    if (code >= 0x20 && code <= 0x7f) {
      bytes.push(code);

      continue;
    }

    // Latin-1 supplement (0xA1-0xFF, except 0xAD which is undefined)
    if (code >= 0xa1 && code <= 0xff && code !== 0xad) {
      bytes.push(code);

      continue;
    }

    // Cannot encode this character
    return null;
  }

  return new Uint8Array(bytes);
}

/**
 * Encode string as UTF-16BE with BOM.
 */
export function encodeUtf16BE(text: string): Uint8Array {
  const bytes: number[] = [0xfe, 0xff]; // BOM

  for (const char of text) {
    // biome-ignore lint/style/noNonNullAssertion: char will exist since it's a string
    const code = char.codePointAt(0)!;

    if (code > 0xffff) {
      // Surrogate pair needed for characters outside BMP
      const adjusted = code - 0x10000;
      const high = 0xd800 + (adjusted >> 10);
      const low = 0xdc00 + (adjusted & 0x3ff);

      bytes.push(high >> 8, high & 0xff);
      bytes.push(low >> 8, low & 0xff);
    } else {
      bytes.push(code >> 8, code & 0xff);
    }
  }

  return new Uint8Array(bytes);
}

/**
 * Encode string for PDF text string.
 * Uses PDFDocEncoding if possible, otherwise UTF-16BE with BOM.
 */
export function encodeTextString(text: string): Uint8Array {
  const pdfDoc = encodePdfDocEncoding(text);

  if (pdfDoc !== null) {
    return pdfDoc;
  }

  return encodeUtf16BE(text);
}
