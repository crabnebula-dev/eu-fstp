/**
 * Token types for Type 1 font lexer.
 *
 * Based on Adobe Type 1 Font Format specification.
 */

/**
 * Token kinds for Type 1 fonts.
 */
export enum TokenKind {
  /** String literal (text) */
  STRING = "STRING",
  /** Name (operator/keyword) */
  NAME = "NAME",
  /** Literal name (starts with /) */
  LITERAL = "LITERAL",
  /** Real number (floating point) */
  REAL = "REAL",
  /** Integer number */
  INTEGER = "INTEGER",
  /** Start of array [ */
  START_ARRAY = "START_ARRAY",
  /** End of array ] */
  END_ARRAY = "END_ARRAY",
  /** Start of procedure { */
  START_PROC = "START_PROC",
  /** End of procedure } */
  END_PROC = "END_PROC",
  /** Start of dictionary << */
  START_DICT = "START_DICT",
  /** End of dictionary >> */
  END_DICT = "END_DICT",
  /** CharString binary data */
  CHARSTRING = "CHARSTRING",
}

/**
 * A lexical token in an Adobe Type 1 font.
 */
export class Token {
  private readonly _text: string | undefined;
  private readonly _data: Uint8Array | undefined;
  private readonly _kind: TokenKind;

  /**
   * Create a token with text value.
   */
  constructor(text: string, kind: TokenKind);
  /**
   * Create a token with binary data (for CHARSTRING).
   */
  constructor(data: Uint8Array, kind: TokenKind);
  constructor(value: string | Uint8Array, kind: TokenKind) {
    this._kind = kind;

    if (typeof value === "string") {
      this._text = value;
    } else {
      this._data = value;
    }
  }

  /**
   * Create a token from a single character.
   */
  static fromChar(char: string, kind: TokenKind): Token {
    return new Token(char, kind);
  }

  /** Get the token text (for non-CHARSTRING tokens). */
  get text(): string | undefined {
    return this._text;
  }

  /** Get the token kind. */
  get kind(): TokenKind {
    return this._kind;
  }

  /** Get the token as an integer value. */
  intValue(): number {
    // Some fonts have reals where integers should be, so we tolerate it
    return Math.trunc(Number.parseFloat(this._text ?? ""));
  }

  /** Get the token as a float value. */
  floatValue(): number {
    return Number.parseFloat(this._text ?? "");
  }

  /** Get the token as a boolean value. */
  booleanValue(): boolean {
    return this._text === "true";
  }

  /** Get the binary data (for CHARSTRING tokens). */
  get data(): Uint8Array | undefined {
    return this._data;
  }

  toString(): string {
    if (this._kind === TokenKind.CHARSTRING) {
      return `Token[kind=CHARSTRING, data=${this._data?.length ?? 0} bytes]`;
    }
    return `Token[kind=${this._kind}, text=${this._text}]`;
  }
}
