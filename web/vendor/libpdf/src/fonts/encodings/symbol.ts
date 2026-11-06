/**
 * SymbolEncoding - encoding for the Symbol font.
 *
 * This encoding contains Greek letters and mathematical symbols.
 */

import { SimpleEncoding } from "./encoding.ts";

// prettier-ignore
const SYMBOL_TO_UNICODE: (number | undefined)[] = [
  // 0x00-0x1F: Undefined
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  // 0x20-0x3F
  0x0020,
  0x0021,
  0x2200,
  0x0023,
  0x2203,
  0x0025,
  0x0026,
  0x220b, // space ! ∀ # ∃ % & ∋
  0x0028,
  0x0029,
  0x2217,
  0x002b,
  0x002c,
  0x2212,
  0x002e,
  0x002f, // ( ) ∗ + , − . /
  0x0030,
  0x0031,
  0x0032,
  0x0033,
  0x0034,
  0x0035,
  0x0036,
  0x0037, // 0 1 2 3 4 5 6 7
  0x0038,
  0x0039,
  0x003a,
  0x003b,
  0x003c,
  0x003d,
  0x003e,
  0x003f, // 8 9 : ; < = > ?
  // 0x40-0x5F: Greek uppercase
  0x2245,
  0x0391,
  0x0392,
  0x03a7,
  0x0394,
  0x0395,
  0x03a6,
  0x0393, // ≅ Α Β Χ Δ Ε Φ Γ
  0x0397,
  0x0399,
  0x03d1,
  0x039a,
  0x039b,
  0x039c,
  0x039d,
  0x039f, // Η Ι ϑ Κ Λ Μ Ν Ο
  0x03a0,
  0x0398,
  0x03a1,
  0x03a3,
  0x03a4,
  0x03a5,
  0x03c2,
  0x03a9, // Π Θ Ρ Σ Τ Υ ς Ω
  0x039e,
  0x03a8,
  0x0396,
  0x005b,
  0x2234,
  0x005d,
  0x22a5,
  0x005f, // Ξ Ψ Ζ [ ∴ ] ⊥ _
  // 0x60-0x7F: Greek lowercase
  0xf8e5,
  0x03b1,
  0x03b2,
  0x03c7,
  0x03b4,
  0x03b5,
  0x03c6,
  0x03b3, // radicalex α β χ δ ε φ γ
  0x03b7,
  0x03b9,
  0x03d5,
  0x03ba,
  0x03bb,
  0x03bc,
  0x03bd,
  0x03bf, // η ι ϕ κ λ μ ν ο
  0x03c0,
  0x03b8,
  0x03c1,
  0x03c3,
  0x03c4,
  0x03c5,
  0x03d6,
  0x03c9, // π θ ρ σ τ υ ϖ ω
  0x03be,
  0x03c8,
  0x03b6,
  0x007b,
  0x007c,
  0x007d,
  0x223c,
  undefined, // ξ ψ ζ { | } ∼
  // 0x80-0x9F: Undefined
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  // 0xA0-0xBF: Symbols
  0x20ac,
  0x03d2,
  0x2032,
  0x2264,
  0x2044,
  0x221e,
  0x0192,
  0x2663, // € ϒ ′ ≤ ⁄ ∞ ƒ ♣
  0x2666,
  0x2665,
  0x2660,
  0x2194,
  0x2190,
  0x2191,
  0x2192,
  0x2193, // ♦ ♥ ♠ ↔ ← ↑ → ↓
  0x00b0,
  0x00b1,
  0x2033,
  0x2265,
  0x00d7,
  0x221d,
  0x2202,
  0x2022, // ° ± ″ ≥ × ∝ ∂ •
  0x00f7,
  0x2260,
  0x2261,
  0x2248,
  0x2026,
  0xf8e6,
  0xf8e7,
  0x21b5, // ÷ ≠ ≡ ≈ … arrowvertex arrowhorizex ↵
  // 0xC0-0xDF: More symbols
  0x2135,
  0x2111,
  0x211c,
  0x2118,
  0x2297,
  0x2295,
  0x2205,
  0x2229, // ℵ ℑ ℜ ℘ ⊗ ⊕ ∅ ∩
  0x222a,
  0x2283,
  0x2287,
  0x2284,
  0x2282,
  0x2286,
  0x2208,
  0x2209, // ∪ ⊃ ⊇ ⊄ ⊂ ⊆ ∈ ∉
  0x2220,
  0x2207,
  0xf8e8,
  0xf8e9,
  0xf8ea,
  0x220f,
  0x221a,
  0x22c5, // ∠ ∇ registersans copyrightsans trademarksans ∏ √ ⋅
  0x00ac,
  0x2227,
  0x2228,
  0x21d4,
  0x21d0,
  0x21d1,
  0x21d2,
  0x21d3, // ¬ ∧ ∨ ⇔ ⇐ ⇑ ⇒ ⇓
  // 0xE0-0xFF: Extensible brackets and integrals
  0x25ca,
  0x2329,
  0xf8e8,
  0xf8e9,
  0xf8ea,
  0x2211,
  0xf8eb,
  0xf8ec, // ◊ 〈 registersans copyrightsans trademarksans ∑ parenlefttp parenleftex
  0xf8ed,
  0xf8ee,
  0xf8ef,
  0xf8f0,
  0xf8f1,
  0xf8f2,
  0xf8f3,
  0xf8f4, // parenleftbt bracketlefttp bracketleftex bracketleftbt bracelefttp braceleftmid braceleftbt braceex
  undefined,
  0x232a,
  0x222b,
  0x2320,
  0xf8f5,
  0x2321,
  0xf8f6,
  0xf8f7, // 〉 ∫ integraltp integralex integralbt parenrighttp parenrightex
  0xf8f8,
  0xf8f9,
  0xf8fa,
  0xf8fb,
  0xf8fc,
  0xf8fd,
  0xf8fe,
  undefined, // parenrightbt bracketrighttp bracketrightex bracketrightbt bracerighttp bracerightmid bracerightbt
];

/**
 * SymbolEncoding implementation.
 * Singleton instance available as `SymbolEncoding.instance`.
 */
export class SymbolEncoding extends SimpleEncoding {
  readonly name = "SymbolEncoding";
  protected readonly toUnicode = SYMBOL_TO_UNICODE;

  private static _instance: SymbolEncoding | null = null;

  static get instance(): SymbolEncoding {
    if (!SymbolEncoding._instance) {
      SymbolEncoding._instance = new SymbolEncoding();
    }
    return SymbolEncoding._instance;
  }
}
