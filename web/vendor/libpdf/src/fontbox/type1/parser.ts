/**
 * Parses an Adobe Type 1 (.pfb) font.
 *
 * The Type 1 font format is a free-text format which is somewhat difficult
 * to parse. This is made worse by the fact that many Type 1 font files do
 * not conform to the specification, especially those embedded in PDFs. This
 * parser therefore tries to be as forgiving as possible.
 *
 * @see "Adobe Type 1 Font Format, Adobe Systems (1999)"
 */

import { BuiltInEncoding, StandardEncoding, Type1Font } from "./font.ts";
import { Type1Lexer } from "./lexer.ts";
import { type Token, TokenKind } from "./token.ts";

// Constants for encryption
const EEXEC_KEY = 55665;
const CHARSTRING_KEY = 4330;

/**
 * Parse a Type 1 font from two segments.
 * @param segment1 ASCII segment (header-less)
 * @param segment2 Binary segment (header-less)
 * @returns Parsed Type1Font
 */
export function parseType1(segment1: Uint8Array, segment2: Uint8Array): Type1Font {
  const parser = new Type1Parser();

  return parser.parse(segment1, segment2);
}

/**
 * Type 1 font parser.
 */
class Type1Parser {
  private lexer!: Type1Lexer;
  private font!: Type1Font;

  /**
   * Parses a Type 1 font and returns a Type1Font class which represents it.
   * @param segment1 Segment 1: ASCII
   * @param segment2 Segment 2: Binary
   */
  parse(segment1: Uint8Array, segment2: Uint8Array): Type1Font {
    this.font = new Type1Font(segment1, segment2);

    this.parseASCII(segment1);

    if (segment2.length > 0) {
      this.parseBinary(segment2);
    }

    return this.font;
  }

  /**
   * Parses the ASCII portion of a Type 1 font.
   */
  private parseASCII(bytes: Uint8Array): void {
    if (bytes.length === 0) {
      throw new Error("ASCII segment of type 1 font is empty");
    }

    // %!FontType1-1.0
    // %!PS-AdobeFont-1.0
    if (bytes.length < 2 || (bytes[0] !== 0x25 && bytes[1] !== 0x21)) {
      throw new Error("Invalid start of ASCII segment of type 1 font");
    }

    this.lexer = new Type1Lexer(bytes);

    // (corrupt?) synthetic font
    if (this.lexer.peekToken()?.text === "FontDirectory") {
      this.read(TokenKind.NAME, "FontDirectory");
      this.read(TokenKind.LITERAL); // font name
      this.read(TokenKind.NAME, "known");
      this.read(TokenKind.START_PROC);
      this.readProcVoid();
      this.read(TokenKind.START_PROC);
      this.readProcVoid();
      this.read(TokenKind.NAME, "ifelse");
    }

    // font dict
    const length = this.read(TokenKind.INTEGER).intValue();
    this.read(TokenKind.NAME, "dict");
    // found in some TeX fonts
    this.readMaybe(TokenKind.NAME, "dup");
    // if present, the "currentdict" is not required
    this.read(TokenKind.NAME, "begin");

    for (let i = 0; i < length; i++) {
      // premature end
      const token = this.lexer.peekToken();

      if (token === null) {
        break;
      }

      if (token.kind === TokenKind.NAME && (token.text === "currentdict" || token.text === "end")) {
        break;
      }

      // key/value
      const key = this.read(TokenKind.LITERAL).text;

      if (key === undefined) {
        throw new Error("Missing key in dictionary");
      }

      switch (key) {
        case "FontInfo":
        case "Fontinfo":
          this.readFontInfo(this.readSimpleDict());
          break;
        case "Metrics":
          this.readSimpleDict();
          break;
        case "Encoding":
          this.readEncoding();
          break;
        default:
          this.readSimpleValue(key);
          break;
      }
    }

    this.readMaybe(TokenKind.NAME, "currentdict");
    this.read(TokenKind.NAME, "end");

    this.read(TokenKind.NAME, "currentfile");
    this.read(TokenKind.NAME, "eexec");
  }

  private readSimpleValue(key: string): void {
    const value = this.readDictValue();

    switch (key) {
      case "FontName":
        this.font.fontName = value[0].text ?? "";
        break;
      case "PaintType":
        this.font.paintType = value[0].intValue();
        break;
      case "FontType":
        this.font.fontType = value[0].intValue();
        break;
      case "FontMatrix":
        this.font.fontMatrix = this.arrayToNumbers(value);
        break;
      case "FontBBox":
        this.font.fontBBox = this.arrayToNumbers(value);
        break;
      case "UniqueID":
        this.font.uniqueID = value[0].intValue();
        break;
      case "StrokeWidth":
        this.font.strokeWidth = value[0].floatValue();
        break;
      case "FID":
        this.font.fontID = value[0].text ?? "";
        break;
    }
  }

  private readEncoding(): void {
    if (this.lexer.peekKind(TokenKind.NAME)) {
      const name = this.lexer.nextToken()?.text;

      if (name === undefined) {
        throw new Error("Missing encoding name");
      }

      if (name === "StandardEncoding") {
        this.font.encoding = StandardEncoding;
      } else {
        throw new Error(`Unknown encoding: ${name}`);
      }

      this.readMaybe(TokenKind.NAME, "readonly");
      this.read(TokenKind.NAME, "def");
    } else {
      this.read(TokenKind.INTEGER).intValue();
      this.readMaybe(TokenKind.NAME, "array");

      // 0 1 255 {1 index exch /.notdef put } for
      // we have to check "readonly" and "def" too
      // as some fonts don't provide any dup-values
      while (
        !(
          this.lexer.peekKind(TokenKind.NAME) &&
          (this.lexer.peekToken()?.text === "dup" ||
            this.lexer.peekToken()?.text === "readonly" ||
            this.lexer.peekToken()?.text === "def")
        )
      ) {
        if (this.lexer.nextToken() === null) {
          throw new Error("Incomplete data while reading encoding of type 1 font");
        }
      }

      const codeToName = new Map<number, string>();
      while (this.lexer.peekKind(TokenKind.NAME) && this.lexer.peekToken()?.text === "dup") {
        this.read(TokenKind.NAME, "dup");

        const code = this.read(TokenKind.INTEGER).intValue();
        const name = this.read(TokenKind.LITERAL).text;

        if (name === undefined) {
          throw new Error("Missing name in encoding");
        }

        this.read(TokenKind.NAME, "put");

        codeToName.set(code, name);
      }

      this.font.encoding = new BuiltInEncoding(codeToName);

      this.readMaybe(TokenKind.NAME, "readonly");
      this.read(TokenKind.NAME, "def");
    }
  }

  /**
   * Extracts values from an array as numbers.
   */
  private arrayToNumbers(value: Token[]): number[] {
    const numbers: number[] = [];

    for (let i = 1; i < value.length - 1; i++) {
      const token = value[i];

      if (token.kind === TokenKind.REAL) {
        numbers.push(token.floatValue());
      } else if (token.kind === TokenKind.INTEGER) {
        numbers.push(token.intValue());
      } else {
        throw new Error(`Expected INTEGER or REAL but got ${token.kind} at array position ${i}`);
      }
    }

    return numbers;
  }

  /**
   * Extracts values from the /FontInfo dictionary.
   */
  private readFontInfo(fontInfo: Map<string, Token[]>): void {
    for (const [key, value] of fontInfo) {
      switch (key) {
        case "version":
          this.font.version = value[0].text ?? "";
          break;
        case "Notice":
          this.font.notice = value[0].text ?? "";
          break;
        case "FullName":
          this.font.fullName = value[0].text ?? "";
          break;
        case "FamilyName":
          this.font.familyName = value[0].text ?? "";
          break;
        case "Weight":
          this.font.weight = value[0].text ?? "";
          break;
        case "ItalicAngle":
          this.font.italicAngle = value[0].floatValue();
          break;
        case "isFixedPitch":
          this.font.isFixedPitch = value[0].booleanValue();
          break;
        case "UnderlinePosition":
          this.font.underlinePosition = value[0].floatValue();
          break;
        case "UnderlineThickness":
          this.font.underlineThickness = value[0].floatValue();
          break;
      }
    }
  }

  /**
   * Reads a dictionary whose values are simple, i.e., do not contain
   * nested dictionaries.
   */
  private readSimpleDict(): Map<string, Token[]> {
    const dict = new Map<string, Token[]>();

    const length = this.read(TokenKind.INTEGER).intValue();
    this.read(TokenKind.NAME, "dict");
    this.readMaybe(TokenKind.NAME, "dup");

    if (this.readMaybe(TokenKind.NAME, "def") !== null) {
      // PDFBOX-5942 empty dict
      return dict;
    }

    this.read(TokenKind.NAME, "begin");

    for (let i = 0; i < length; i++) {
      if (this.lexer.peekToken() === null) {
        break;
      }

      if (this.lexer.peekKind(TokenKind.NAME) && this.lexer.peekToken()?.text !== "end") {
        this.read(TokenKind.NAME);
      }
      // premature end
      if (this.lexer.peekToken() === null) {
        break;
      }
      if (this.lexer.peekKind(TokenKind.NAME) && this.lexer.peekToken()?.text === "end") {
        break;
      }

      // simple value
      const key = this.read(TokenKind.LITERAL).text;

      if (key === undefined) {
        throw new Error("Missing key in dictionary");
      }

      const value = this.readDictValue();

      dict.set(key, value);
    }

    this.read(TokenKind.NAME, "end");
    this.readMaybe(TokenKind.NAME, "readonly");
    this.read(TokenKind.NAME, "def");

    return dict;
  }

  /**
   * Reads a simple value from a dictionary.
   */
  private readDictValue(): Token[] {
    const value = this.readValue();

    this.readDef();

    return value;
  }

  /**
   * Reads a simple value. This is either a number, a string,
   * a name, a literal name, an array, a procedure, or a charstring.
   * This method does not support reading nested dictionaries unless they're empty.
   */
  private readValue(): Token[] {
    const value: Token[] = [];

    let token = this.lexer.nextToken();

    if (this.lexer.peekToken() === null) {
      return value;
    }

    if (token === null) {
      return value;
    }

    value.push(token);

    if (token.kind === TokenKind.START_ARRAY) {
      let openArray = 1;

      while (true) {
        if (this.lexer.peekToken() === null) {
          return value;
        }

        if (this.lexer.peekKind(TokenKind.START_ARRAY)) {
          openArray++;
        }

        token = this.lexer.nextToken();

        if (token === null) {
          break;
        }

        value.push(token);

        if (token.kind === TokenKind.END_ARRAY) {
          openArray--;

          if (openArray === 0) {
            break;
          }
        }
      }
    } else if (token.kind === TokenKind.START_PROC) {
      value.push(...this.readProc());
    } else if (token.kind === TokenKind.START_DICT) {
      // skip "/GlyphNames2HostCode << >> def"
      this.read(TokenKind.END_DICT);

      return value;
    }

    this.readPostScriptWrapper(value);

    return value;
  }

  private readPostScriptWrapper(value: Token[]): void {
    if (this.lexer.peekToken() === null) {
      throw new Error("Missing start token for the system dictionary");
    }
    // postscript wrapper (not in the Type 1 spec)
    if (this.lexer.peekToken()?.text === "systemdict") {
      this.read(TokenKind.NAME, "systemdict");
      this.read(TokenKind.LITERAL, "internaldict");
      this.read(TokenKind.NAME, "known");

      this.read(TokenKind.START_PROC);
      this.readProcVoid();

      this.read(TokenKind.START_PROC);
      this.readProcVoid();

      this.read(TokenKind.NAME, "ifelse");

      // replace value
      this.read(TokenKind.START_PROC);
      this.read(TokenKind.NAME, "pop");

      value.length = 0;
      value.push(...this.readValue());

      this.read(TokenKind.END_PROC);

      this.read(TokenKind.NAME, "if");
    }
  }

  /**
   * Reads a procedure.
   */
  private readProc(): Token[] {
    const value: Token[] = [];

    let openProc = 1;

    while (true) {
      if (this.lexer.peekToken() === null) {
        throw new Error("Malformed procedure: missing token");
      }

      if (this.lexer.peekKind(TokenKind.START_PROC)) {
        openProc++;
      }

      const token = this.lexer.nextToken();

      if (token === null) {
        break;
      }

      value.push(token);

      if (token.kind === TokenKind.END_PROC) {
        openProc--;

        if (openProc === 0) {
          break;
        }
      }
    }

    const executeonly = this.readMaybe(TokenKind.NAME, "executeonly");

    if (executeonly !== null) {
      value.push(executeonly);
    }

    return value;
  }

  /**
   * Reads a procedure but without returning anything.
   */
  private readProcVoid(): void {
    let openProc = 1;

    while (true) {
      if (this.lexer.peekToken() === null) {
        throw new Error("Malformed procedure: missing token");
      }

      if (this.lexer.peekKind(TokenKind.START_PROC)) {
        openProc++;
      }

      const token = this.lexer.nextToken();

      if (token === null) {
        break;
      }

      if (token.kind === TokenKind.END_PROC) {
        openProc--;

        if (openProc === 0) {
          break;
        }
      }
    }

    this.readMaybe(TokenKind.NAME, "executeonly");
  }

  /**
   * Parses the binary portion of a Type 1 font.
   */
  private parseBinary(bytes: Uint8Array): void {
    let decrypted: Uint8Array;

    // Sometimes, fonts use the hex format, so this needs to be converted before decryption
    if (this.isBinary(bytes)) {
      decrypted = this.decrypt(bytes, EEXEC_KEY, 4);
    } else {
      decrypted = this.decrypt(this.hexToBinary(bytes), EEXEC_KEY, 4);
    }

    this.lexer = new Type1Lexer(decrypted);

    // find /Private dict
    let peekToken = this.lexer.peekToken();

    while (peekToken !== null && peekToken.text !== "Private") {
      this.lexer.nextToken();

      peekToken = this.lexer.peekToken();
    }

    if (peekToken === null) {
      throw new Error("/Private token not found");
    }

    // Private dict
    this.read(TokenKind.LITERAL, "Private");
    const length = this.read(TokenKind.INTEGER).intValue();
    this.read(TokenKind.NAME, "dict");
    // actually could also be "/Private 10 dict def Private begin"
    // instead of the "dup"
    this.readMaybe(TokenKind.NAME, "dup");
    this.read(TokenKind.NAME, "begin");

    let lenIV = 4; // number of random bytes at start of charstring

    for (let i = 0; i < length; i++) {
      // premature end
      if (!this.lexer.peekKind(TokenKind.LITERAL)) {
        break;
      }

      // key/value
      const key = this.read(TokenKind.LITERAL).text;

      if (key === undefined) {
        throw new Error("Missing key in dictionary");
      }

      switch (key) {
        case "Subrs":
          this.readSubrs(lenIV);
          break;
        case "OtherSubrs":
          this.readOtherSubrs();
          break;
        case "lenIV":
          lenIV = this.readDictValue()[0].intValue();
          break;
        case "ND":
          this.read(TokenKind.START_PROC);
          // the access restrictions are not mandatory
          this.readMaybe(TokenKind.NAME, "noaccess");
          this.read(TokenKind.NAME, "def");
          this.read(TokenKind.END_PROC);
          this.readMaybe(TokenKind.NAME, "executeonly");
          this.readMaybe(TokenKind.NAME, "readonly");
          this.read(TokenKind.NAME, "def");
          break;
        case "NP":
          this.read(TokenKind.START_PROC);
          this.readMaybe(TokenKind.NAME, "noaccess");
          this.read(TokenKind.NAME);
          this.read(TokenKind.END_PROC);
          this.readMaybe(TokenKind.NAME, "executeonly");
          this.readMaybe(TokenKind.NAME, "readonly");
          this.read(TokenKind.NAME, "def");
          break;
        case "RD":
          // /RD {string currentfile exch readstring pop} bind executeonly def
          this.read(TokenKind.START_PROC);
          this.readProcVoid();
          this.readMaybe(TokenKind.NAME, "bind");
          this.readMaybe(TokenKind.NAME, "executeonly");
          this.readMaybe(TokenKind.NAME, "readonly");
          this.read(TokenKind.NAME, "def");
          break;
        default:
          this.readPrivate(key, this.readDictValue());
          break;
      }
    }

    // some fonts have "2 index" here, others have "end noaccess put"
    // sometimes followed by "put". Either way, we just skip until
    // the /CharStrings dict is found
    while (
      !(this.lexer.peekKind(TokenKind.LITERAL) && this.lexer.peekToken()?.text === "CharStrings")
    ) {
      if (this.lexer.nextToken() === null) {
        throw new Error("Missing 'CharStrings' dictionary in type 1 font");
      }
    }

    // CharStrings dict
    this.read(TokenKind.LITERAL, "CharStrings");
    this.readCharStrings(lenIV);
  }

  /**
   * Extracts values from the /Private dictionary.
   */
  private readPrivate(key: string, value: Token[]): void {
    switch (key) {
      case "BlueValues":
        this.font.blueValues = this.arrayToNumbers(value);
        break;
      case "OtherBlues":
        this.font.otherBlues = this.arrayToNumbers(value);
        break;
      case "FamilyBlues":
        this.font.familyBlues = this.arrayToNumbers(value);
        break;
      case "FamilyOtherBlues":
        this.font.familyOtherBlues = this.arrayToNumbers(value);
        break;
      case "BlueScale":
        this.font.blueScale = value[0].floatValue();
        break;
      case "BlueShift":
        this.font.blueShift = value[0].intValue();
        break;
      case "BlueFuzz":
        this.font.blueFuzz = value[0].intValue();
        break;
      case "StdHW":
        this.font.stdHW = this.arrayToNumbers(value);
        break;
      case "StdVW":
        this.font.stdVW = this.arrayToNumbers(value);
        break;
      case "StemSnapH":
        this.font.stemSnapH = this.arrayToNumbers(value);
        break;
      case "StemSnapV":
        this.font.stemSnapV = this.arrayToNumbers(value);
        break;
      case "ForceBold":
        this.font.forceBold = value[0].booleanValue();
        break;
      case "LanguageGroup":
        this.font.languageGroup = value[0].intValue();
        break;
    }
  }

  /**
   * Reads the /Subrs array.
   * @param lenIV The number of random bytes used in charstring encryption.
   */
  private readSubrs(lenIV: number): void {
    // allocate size (array indexes may not be in-order)
    const length = this.read(TokenKind.INTEGER).intValue();

    for (let i = 0; i < length; i++) {
      this.font.subrs.push(null);
    }

    this.read(TokenKind.NAME, "array");

    for (let i = 0; i < length; i++) {
      // premature end
      if (this.lexer.peekToken() === null) {
        break;
      }

      if (!(this.lexer.peekKind(TokenKind.NAME) && this.lexer.peekToken()?.text === "dup")) {
        break;
      }

      this.read(TokenKind.NAME, "dup");
      const index = this.read(TokenKind.INTEGER);
      this.read(TokenKind.INTEGER);

      // RD
      const charstring = this.read(TokenKind.CHARSTRING);
      const j = index.intValue();

      if (j < this.font.subrs.length) {
        const data = charstring.data;

        if (data === undefined) {
          throw new Error("Missing data in charstring");
        }

        this.font.subrs[j] = this.decrypt(data, CHARSTRING_KEY, lenIV);
      }

      this.readPut();
    }

    this.readDef();
  }

  /**
   * OtherSubrs are embedded PostScript procedures which we can safely ignore.
   */
  private readOtherSubrs(): void {
    if (this.lexer.peekToken() === null) {
      throw new Error("Missing start token of OtherSubrs procedure");
    }

    if (this.lexer.peekKind(TokenKind.START_ARRAY)) {
      this.readValue();
      this.readDef();
    } else {
      const length = this.read(TokenKind.INTEGER).intValue();
      this.read(TokenKind.NAME, "array");

      for (let i = 0; i < length; i++) {
        this.read(TokenKind.NAME, "dup");
        this.read(TokenKind.INTEGER); // index
        this.readValue(); // PostScript
        this.readPut();
      }

      this.readDef();
    }
  }

  /**
   * Reads the /CharStrings dictionary.
   * @param lenIV The number of random bytes used in charstring encryption.
   */
  private readCharStrings(lenIV: number): void {
    const length = this.read(TokenKind.INTEGER).intValue();

    this.read(TokenKind.NAME, "dict");
    // could actually be a sequence ending in "CharStrings begin", too
    // instead of the "dup begin"
    this.read(TokenKind.NAME, "dup");
    this.read(TokenKind.NAME, "begin");

    for (let i = 0; i < length; i++) {
      // premature end
      if (this.lexer.peekToken() === null) {
        break;
      }

      if (this.lexer.peekKind(TokenKind.NAME) && this.lexer.peekToken()?.text === "end") {
        break;
      }

      // key/value
      const name = this.read(TokenKind.LITERAL).text;

      if (name === undefined) {
        throw new Error("Missing name in charstrings");
      }

      // RD
      this.read(TokenKind.INTEGER);
      const charstring = this.read(TokenKind.CHARSTRING);

      const data = charstring.data;

      if (data === undefined) {
        throw new Error("Missing data in charstring");
      }

      this.font.charstrings.set(name, this.decrypt(data, CHARSTRING_KEY, lenIV));
      this.readDef();
    }

    // some fonts have one "end", others two
    this.read(TokenKind.NAME, "end");
  }

  /**
   * Reads the sequence "noaccess def" or equivalent.
   */
  private readDef(): void {
    this.readMaybe(TokenKind.NAME, "readonly");
    this.readMaybe(TokenKind.NAME, "noaccess"); // allows "noaccess ND"

    let token = this.read(TokenKind.NAME);
    switch (token.text) {
      case "ND":
      case "|-":
        return;
      case "noaccess":
        token = this.read(TokenKind.NAME);
        break;
    }

    if (token.text === "def") {
      return;
    }

    throw new Error(`Found ${token.kind}:${token.text} but expected ND`);
  }

  /**
   * Reads the sequence "noaccess put" or equivalent.
   */
  private readPut(): void {
    this.readMaybe(TokenKind.NAME, "readonly");

    let token = this.read(TokenKind.NAME);
    switch (token.text) {
      case "NP":
      case "|":
        return;
      case "noaccess":
        token = this.read(TokenKind.NAME);
        break;
    }

    if (token.text === "put") {
      return;
    }

    throw new Error(`Found ${token.kind}:${token.text} but expected NP`);
  }

  /**
   * Reads the next token and throws an exception if it is not of the given kind.
   * @returns token, never null
   */
  private read(kind: TokenKind, name?: string): Token {
    const token = this.lexer.nextToken();

    if (token === null || token.kind !== kind) {
      throw new Error(`Found ${token?.kind ?? "null"}:${token?.text ?? ""} but expected ${kind}`);
    }

    if (name !== undefined && token.text !== name) {
      throw new Error(`Found ${token.kind}:${token.text} but expected ${name}`);
    }

    return token;
  }

  /**
   * Reads the next token if and only if it is of the given kind and
   * has the given value.
   * @returns token or null if not the expected one
   */
  private readMaybe(kind: TokenKind, name: string): Token | null {
    if (this.lexer.peekKind(kind) && this.lexer.peekToken()?.text === name) {
      return this.lexer.nextToken();
    }

    return null;
  }

  /**
   * Type 1 Decryption (eexec, charstring).
   * @param cipherBytes cipher text
   * @param r key
   * @param n number of random bytes (lenIV)
   * @returns plain text
   */
  private decrypt(cipherBytes: Uint8Array, r: number, n: number): Uint8Array {
    // lenIV of -1 means no encryption (not documented)
    if (n === -1) {
      return cipherBytes;
    }

    // empty charstrings and charstrings of insufficient length
    if (cipherBytes.length === 0 || n > cipherBytes.length) {
      return new Uint8Array(0);
    }

    // decrypt
    const c1 = 52845;
    const c2 = 22719;
    const plainBytes = new Uint8Array(cipherBytes.length - n);

    let key = r;

    for (let i = 0; i < cipherBytes.length; i++) {
      const cipher = cipherBytes[i];
      const plain = cipher ^ (key >>> 8);

      if (i >= n) {
        plainBytes[i - n] = plain;
      }

      key = ((cipher + key) * c1 + c2) & 0xffff;
    }

    return plainBytes;
  }

  /**
   * Check whether binary or hex encoded.
   * See Adobe Type 1 Font Format specification 7.2 eexec encryption
   */
  private isBinary(bytes: Uint8Array): boolean {
    if (bytes.length < 4) {
      return true;
    }

    // "At least one of the first 4 ciphertext bytes must not be one of
    // the ASCII hexadecimal character codes (a code for 0-9, A-F, or a-f)."
    for (let i = 0; i < 4; i++) {
      const by = bytes[i];

      if (by !== 0x0a && by !== 0x0d && by !== 0x20 && by !== 0x09) {
        const hexDigit = this.hexDigitValue(by);

        if (hexDigit === -1) {
          return true;
        }
      }
    }

    return false;
  }

  private hexToBinary(bytes: Uint8Array): Uint8Array {
    // calculate needed length
    let len = 0;

    for (const by of bytes) {
      if (this.hexDigitValue(by) !== -1) {
        len++;
      }
    }

    const res = new Uint8Array(Math.floor(len / 2));

    let r = 0;
    let prev = -1;

    for (const by of bytes) {
      const digit = this.hexDigitValue(by);

      if (digit !== -1) {
        if (prev === -1) {
          prev = digit;
        } else {
          res[r++] = prev * 16 + digit;
          prev = -1;
        }
      }
    }

    return res;
  }

  private hexDigitValue(ch: number): number {
    // 0-9
    if (ch >= 0x30 && ch <= 0x39) {
      return ch - 0x30;
    }
    // A-F
    if (ch >= 0x41 && ch <= 0x46) {
      return ch - 0x41 + 10;
    }
    // a-f
    if (ch >= 0x61 && ch <= 0x66) {
      return ch - 0x61 + 10;
    }

    return -1;
  }
}
