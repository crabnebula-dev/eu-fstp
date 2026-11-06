/**
 * PDF token types returned by TokenReader.
 */

export type Token =
  | NumberToken
  | NameToken
  | StringToken
  | KeywordToken
  | DelimiterToken
  | EofToken;

export interface NumberToken {
  type: "number";
  value: number;
  isInteger: boolean;
  position: number;
}

export interface NameToken {
  type: "name";
  value: string; // Without leading /
  position: number;
}

export interface StringToken {
  type: "string";
  value: Uint8Array;
  format: "literal" | "hex";
  position: number;
}

export interface KeywordToken {
  type: "keyword";
  value: string;
  position: number;
}

export interface DelimiterToken {
  type: "delimiter";
  value: "[" | "]" | "<<" | ">>";
  position: number;
}

export interface EofToken {
  type: "eof";
  position: number;
}

// Type guards

export function isNumberToken(token: Token): token is NumberToken {
  return token.type === "number";
}

export function isNameToken(token: Token): token is NameToken {
  return token.type === "name";
}

export function isStringToken(token: Token): token is StringToken {
  return token.type === "string";
}

export function isKeywordToken(token: Token): token is KeywordToken {
  return token.type === "keyword";
}

export function isDelimiterToken(token: Token): token is DelimiterToken {
  return token.type === "delimiter";
}

export function isEofToken(token: Token): token is EofToken {
  return token.type === "eof";
}
