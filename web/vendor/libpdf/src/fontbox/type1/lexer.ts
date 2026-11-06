/**
 * Lexer for the ASCII portions of an Adobe Type 1 font.
 *
 * The PostScript language, of which Type 1 fonts are a subset, has a
 * somewhat awkward lexical structure. It is neither regular nor
 * context-free, and the execution of the program can modify the
 * behaviour of the lexer/parser.
 *
 * Nevertheless, this class represents an attempt to artificially separate
 * the PostScript parsing process into separate lexing and parsing phases
 * in order to reduce the complexity of the parsing phase.
 *
 * @see "PostScript Language Reference 3rd ed, Adobe Systems (1999)"
 */

import { Token, TokenKind } from "./token.ts";

/**
 * Error thrown when a Type 1 font is damaged/corrupted.
 */
export class DamagedFontError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DamagedFontError";
  }
}

/**
 * Lexer for Type 1 font ASCII segments.
 */
export class Type1Lexer {
  private readonly data: Uint8Array;
  private position = 0;
  private aheadToken: Token | null;
  private openParens = 0;

  /**
   * Constructs a new Type1Lexer given a header-less .pfb segment.
   * @param bytes Header-less .pfb segment
   */
  constructor(bytes: Uint8Array) {
    this.data = bytes;
    this.aheadToken = this.readToken(null);
  }

  /**
   * Returns the next token and consumes it.
   * @returns The next token, or null if at end
   */
  nextToken(): Token | null {
    const curToken = this.aheadToken;
    this.aheadToken = this.readToken(curToken);

    return curToken;
  }

  /**
   * Returns the next token without consuming it.
   * @returns The next token, or null if at end
   */
  peekToken(): Token | null {
    return this.aheadToken;
  }

  /**
   * Checks if the kind of the next token equals the given one without consuming it.
   * @returns true if the kind of the next token equals the given one
   */
  peekKind(kind: TokenKind): boolean {
    return this.aheadToken !== null && this.aheadToken.kind === kind;
  }

  /**
   * Reads an ASCII char from the buffer.
   * Returns -1 at end of buffer.
   */
  private getChar(): number {
    if (this.position >= this.data.length) {
      return -1;
    }

    return this.data[this.position++];
  }

  /**
   * Reads an ASCII char from the buffer, throwing on EOF.
   */
  // private getCharOrThrow(): number {
  //   if (this.position >= this.data.length) {
  //     throw new Error("Premature end of buffer reached");
  //   }

  //   return this.data[this.position++];
  // }

  /**
   * Check if there's more data available.
   */
  private hasRemaining(): boolean {
    return this.position < this.data.length;
  }

  /**
   * Reads a single token.
   * @param prevToken the previous token
   */
  private readToken(prevToken: Token | null): Token | null {
    let skip: boolean;
    do {
      skip = false;

      while (this.hasRemaining()) {
        const c = this.getChar();

        // delimiters
        if (c === 0x25) {
          // %
          // comment
          this.readComment();
        } else if (c === 0x28) {
          // (
          return this.readString();
        } else if (c === 0x29) {
          // )
          // not allowed outside a string context
          throw new Error("unexpected closing parenthesis");
        } else if (c === 0x5b) {
          // [
          return Token.fromChar("[", TokenKind.START_ARRAY);
        } else if (c === 0x7b) {
          // {
          return Token.fromChar("{", TokenKind.START_PROC);
        } else if (c === 0x5d) {
          // ]
          return Token.fromChar("]", TokenKind.END_ARRAY);
        } else if (c === 0x7d) {
          // }
          return Token.fromChar("}", TokenKind.END_PROC);
        } else if (c === 0x2f) {
          // /
          const regular = this.readRegular();

          if (regular === null) {
            // the stream is corrupt
            throw new DamagedFontError(`Could not read token at position ${this.position}`);
          }

          return new Token(regular, TokenKind.LITERAL);
        } else if (c === 0x3c) {
          // <
          if (this.hasRemaining()) {
            const c2 = this.getChar();

            if (c2 === c) {
              return new Token("<<", TokenKind.START_DICT);
            }

            // put back
            this.position--;

            return new Token("<", TokenKind.NAME);
          }

          return new Token("<", TokenKind.NAME);
        } else if (c === 0x3e) {
          // >
          if (this.hasRemaining()) {
            const c2 = this.getChar();

            if (c2 === c) {
              return new Token(">>", TokenKind.END_DICT);
            }

            // put back
            this.position--;

            return new Token(">", TokenKind.NAME);
          }

          return new Token(">", TokenKind.NAME);
        } else if (isWhitespace(c)) {
          skip = true;
        } else if (c === 0) {
          // NULL byte, skip
          skip = true;
        } else {
          this.position--;

          // regular character: try parse as number
          const number = this.tryReadNumber();

          if (number !== null) {
            return number;
          }

          // otherwise this must be a name
          const name = this.readRegular();

          if (name === null) {
            // the stream is corrupt
            throw new DamagedFontError(`Could not read token at position ${this.position}`);
          }

          if (name === "RD" || name === "-|") {
            // return the next CharString instead
            if (prevToken !== null && prevToken.kind === TokenKind.INTEGER) {
              return this.readCharString(prevToken.intValue());
            }

            throw new Error("expected INTEGER before -| or RD");
          }

          return new Token(name, TokenKind.NAME);
        }
      }
    } while (skip);

    return null;
  }

  /**
   * Reads a number or returns null.
   */
  private tryReadNumber(): Token | null {
    const startPos = this.position;

    let sb = "";
    let radix: string | null = null;
    let c = this.getChar();

    if (c === -1) {
      this.position = startPos;
      return null;
    }

    let hasDigit = false;

    // optional + or -
    if (c === 0x2b || c === 0x2d) {
      // + or -
      sb += String.fromCharCode(c);
      c = this.getChar();

      if (c === -1) {
        this.position = startPos;

        return null;
      }
    }

    // optional digits
    while (c !== -1 && isDigit(c)) {
      sb += String.fromCharCode(c);
      hasDigit = true;
      c = this.getChar();
    }

    // Handle EOF after digits
    if (c === -1) {
      if (hasDigit) {
        return new Token(sb, TokenKind.INTEGER);
      }

      this.position = startPos;

      return null;
    }

    // optional .
    if (c === 0x2e) {
      // .
      sb += String.fromCharCode(c);
      c = this.getChar();

      if (c === -1) {
        // Just a dot after digits is still a real
        if (hasDigit) {
          return new Token(sb, TokenKind.REAL);
        }

        this.position = startPos;

        return null;
      }
    } else if (c === 0x23) {
      // # - PostScript radix number takes the form base#number
      radix = sb;
      sb = "";
      c = this.getChar();

      if (c === -1) {
        this.position = startPos;

        return null;
      }
    } else if (sb.length === 0 || !hasDigit) {
      // failure
      this.position = startPos;

      return null;
    } else if (c !== 0x65 && c !== 0x45) {
      // not e or E
      // integer
      this.position--;

      return new Token(sb, TokenKind.INTEGER);
    }

    // required digit (for after . or radix#)
    if (c !== -1 && isDigit(c)) {
      sb += String.fromCharCode(c);
      c = this.getChar();
    } else if (c !== 0x65 && c !== 0x45) {
      // not e or E
      // failure
      this.position = startPos;

      return null;
    }

    // optional digits
    while (c !== -1 && isDigit(c)) {
      sb += String.fromCharCode(c);
      c = this.getChar();
    }

    // optional E
    if (c === 0x45 || c === 0x65) {
      // E or e
      sb += String.fromCharCode(c);
      c = this.getChar();

      if (c === -1) {
        this.position = startPos;

        return null;
      }

      // optional minus
      if (c === 0x2d) {
        // -
        sb += String.fromCharCode(c);
        c = this.getChar();

        if (c === -1) {
          this.position = startPos;

          return null;
        }
      }

      // required digit
      if (isDigit(c)) {
        sb += String.fromCharCode(c);
        c = this.getChar();
      } else {
        // failure
        this.position = startPos;

        return null;
      }

      // optional digits
      while (c !== -1 && isDigit(c)) {
        sb += String.fromCharCode(c);
        c = this.getChar();
      }
    }

    if (c !== -1) {
      this.position--;
    }

    if (radix !== null) {
      const base = Number.parseInt(radix, 10);
      const val = Number.parseInt(sb, base);

      if (Number.isNaN(val)) {
        throw new Error(`Invalid number '${sb}'`);
      }

      return new Token(val.toString(), TokenKind.INTEGER);
    }

    return new Token(sb, TokenKind.REAL);
  }

  /**
   * Reads a sequence of regular characters, i.e. not delimiters or whitespace.
   */
  private readRegular(): string | null {
    let sb = "";

    while (this.hasRemaining()) {
      const startPos = this.position;
      const c = this.getChar();

      if (
        isWhitespace(c) ||
        c === 0x28 ||
        c === 0x29 || // ( )
        c === 0x3c ||
        c === 0x3e || // < >
        c === 0x5b ||
        c === 0x5d || // [ ]
        c === 0x7b ||
        c === 0x7d || // { }
        c === 0x2f ||
        c === 0x25
      ) {
        // / %
        this.position = startPos;
        break;
      }

      sb += String.fromCharCode(c);
    }

    if (sb.length === 0) {
      return null;
    }

    return sb;
  }

  /**
   * Reads a line comment.
   */
  private readComment(): string {
    let sb = "";

    while (this.hasRemaining()) {
      const c = this.getChar();

      if (c === 0x0d || c === 0x0a) {
        // \r or \n
        break;
      }

      sb += String.fromCharCode(c);
    }

    return sb;
  }

  /**
   * Reads a (string).
   */
  private readString(): Token | null {
    let sb = "";

    while (this.hasRemaining()) {
      const c = this.getChar();

      // string context
      switch (c) {
        case 0x28: // (
          this.openParens++;
          sb += "(";
          break;
        case 0x29: // )
          if (this.openParens === 0) {
            // end of string
            return new Token(sb, TokenKind.STRING);
          }

          sb += ")";
          this.openParens--;
          break;
        case 0x5c: {
          // \ - escapes: \n \r \t \b \f \\ \( \)
          const c1 = this.getChar();
          switch (c1) {
            case 0x6e: // n
            case 0x72: // r
              sb += "\n";
              break;
            case 0x74: // t
              sb += "\t";
              break;
            case 0x62: // b
              sb += "\b";
              break;
            case 0x66: // f
              sb += "\f";
              break;
            case 0x5c: // \
              sb += "\\";
              break;
            case 0x28: // (
              sb += "(";
              break;
            case 0x29: // )
              sb += ")";
              break;
            default:
              // octal \ddd
              if (isDigit(c1)) {
                const d1 = this.getChar();
                const d2 = this.getChar();
                const num =
                  String.fromCharCode(c1) + String.fromCharCode(d1) + String.fromCharCode(d2);
                const code = Number.parseInt(num, 8);

                if (Number.isNaN(code)) {
                  throw new Error(`Invalid octal escape: ${num}`);
                }

                sb += String.fromCharCode(code);
              }
              break;
          }
          break;
        }
        case 0x0d: // \r
        case 0x0a: // \n
          sb += "\n";
          break;
        default:
          sb += String.fromCharCode(c);
          break;
      }
    }
    return null;
  }

  /**
   * Reads a binary CharString.
   */
  private readCharString(length: number): Token {
    if (length > this.data.length) {
      throw new Error(`String length ${length} is larger than input`);
    }

    if (this.position >= this.data.length) {
      throw new Error("Premature end of buffer reached");
    }

    // skip space
    this.position++;

    const remaining = this.data.length - this.position;
    if (length > remaining) {
      throw new Error("Premature end of buffer reached");
    }

    const data = this.data.slice(this.position, this.position + length);

    this.position += length;

    return new Token(data, TokenKind.CHARSTRING);
  }
}

/**
 * Check if a byte is whitespace.
 */
function isWhitespace(c: number): boolean {
  return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d || c === 0x0c;
}

/**
 * Check if a byte is a digit (0-9).
 */
function isDigit(c: number): boolean {
  return c >= 0x30 && c <= 0x39;
}
