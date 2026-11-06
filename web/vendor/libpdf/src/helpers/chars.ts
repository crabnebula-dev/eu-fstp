/**
 * PDF character constants (PDF spec 7.2.2)
 *
 * Reusable byte values and sets for parsing PDF syntax.
 */

// Line endings
export const LF = 0x0a; // Line Feed
export const CR = 0x0d; // Carriage Return

// Common whitespace
export const SPACE = 0x20; // Space
export const TAB = 0x09; // Tab
export const NUL = 0x00; // Null
export const FF = 0x0c; // Form Feed
export const BS = 0x08; // Backspace

/**
 * PDF whitespace characters (PDF spec 7.2.2)
 *
 * NUL, TAB, LF, FF, CR, SPACE
 */
export const WHITESPACE = new Set([NUL, TAB, LF, FF, CR, SPACE]);

// Delimiters
export const CHAR_PARENTHESIS_OPEN = 0x28; // (
export const CHAR_PARENTHESIS_CLOSE = 0x29; // )
export const CHAR_ANGLE_BRACKET_OPEN = 0x3c; // <
export const CHAR_ANGLE_BRACKET_CLOSE = 0x3e; // >
export const CHAR_SQUARE_BRACKET_OPEN = 0x5b; // [
export const CHAR_SQUARE_BRACKET_CLOSE = 0x5d; // ]
export const CHAR_CURLY_BRACE_OPEN = 0x7b; // {
export const CHAR_CURLY_BRACE_CLOSE = 0x7d; // }
export const CHAR_SLASH = 0x2f; // /
export const CHAR_PERCENT = 0x25; // %
export const CHAR_BACKSLASH = 0x5c; // \

/**
 * PDF delimiter characters (PDF spec 7.2.2)
 *
 * ( ) < > [ ] { } / %
 */
export const DELIMITERS = new Set([
  CHAR_PARENTHESIS_OPEN,
  CHAR_PARENTHESIS_CLOSE,
  CHAR_ANGLE_BRACKET_OPEN,
  CHAR_ANGLE_BRACKET_CLOSE,
  CHAR_SQUARE_BRACKET_OPEN,
  CHAR_SQUARE_BRACKET_CLOSE,
  CHAR_CURLY_BRACE_OPEN,
  CHAR_CURLY_BRACE_CLOSE,
  CHAR_SLASH,
  CHAR_PERCENT,
]);

export const CHAR_PLUS = 0x2b; // +
export const CHAR_MINUS = 0x2d; // -
export const CHAR_PERIOD = 0x2e; // .
export const CHAR_HASH = 0x23; // #

/**
 * Check if a byte is PDF whitespace.
 */
export function isWhitespace(byte: number): boolean {
  return WHITESPACE.has(byte);
}

/**
 * Check if a byte is a PDF delimiter.
 */
export function isDelimiter(byte: number): boolean {
  return DELIMITERS.has(byte);
}

/**
 * Check if a byte is a regular character (not whitespace or delimiter).
 */
export function isRegularChar(byte: number): boolean {
  return byte !== -1 && !WHITESPACE.has(byte) && !DELIMITERS.has(byte);
}

// Digit ranges
export const DIGIT_0 = 0x30;
export const DIGIT_9 = 0x39;

export const CHAR_LOWER_A = 0x61;
export const CHAR_LOWER_F = 0x66;
export const CHAR_LOWER_Z = 0x7a;
export const CHAR_UPPER_A = 0x41;
export const CHAR_UPPER_F = 0x46;
export const CHAR_UPPER_Z = 0x5a;

/**
 * Check if a byte is an ASCII digit (0-9).
 */
export function isDigit(byte: number): boolean {
  return byte >= DIGIT_0 && byte <= DIGIT_9;
}

/**
 * Check if a byte is a hex digit (0-9, A-F, a-f).
 */
export function isHexDigit(byte: number): boolean {
  return (
    (byte >= DIGIT_0 && byte <= DIGIT_9) || // 0-9
    (byte >= CHAR_UPPER_A && byte <= CHAR_UPPER_F) || // A-F
    (byte >= CHAR_LOWER_A && byte <= CHAR_LOWER_F) // a-f
  );
}

/**
 * Get numeric value of a hex digit (0-15), or -1 if invalid.
 */
export function hexValue(byte: number): number {
  if (byte >= DIGIT_0 && byte <= DIGIT_9) {
    return byte - DIGIT_0;
  }

  if (byte >= CHAR_UPPER_A && byte <= CHAR_UPPER_F) {
    return byte - CHAR_UPPER_A + 10;
  }

  if (byte >= CHAR_LOWER_A && byte <= CHAR_LOWER_F) {
    return byte - CHAR_LOWER_A + 10;
  }

  return -1;
}

/**
 * Byte mask for limiting values to a single byte (0-255).
 */
export const SINGLE_BYTE_MASK = 0xff; // 0-255
