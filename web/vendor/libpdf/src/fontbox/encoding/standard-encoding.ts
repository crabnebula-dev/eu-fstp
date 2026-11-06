/**
 * Adobe Standard Encoding.
 *
 * This is the standard encoding used by Type 1 PostScript fonts.
 *
 * Ported from Apache PDFBox's fontbox/encoding/StandardEncoding.java
 */

import { createEncodingFromEntries, type Encoding } from "./encoding.ts";

/**
 * Standard encoding character code to glyph name mappings.
 * Character codes are in decimal (converted from octal in the original).
 */
const STANDARD_ENCODING_TABLE: ReadonlyArray<readonly [number, string]> = [
  [0o101, "A"], // 65
  [0o341, "AE"], // 225
  [0o102, "B"], // 66
  [0o103, "C"], // 67
  [0o104, "D"], // 68
  [0o105, "E"], // 69
  [0o106, "F"], // 70
  [0o107, "G"], // 71
  [0o110, "H"], // 72
  [0o111, "I"], // 73
  [0o112, "J"], // 74
  [0o113, "K"], // 75
  [0o114, "L"], // 76
  [0o350, "Lslash"], // 232
  [0o115, "M"], // 77
  [0o116, "N"], // 78
  [0o117, "O"], // 79
  [0o352, "OE"], // 234
  [0o351, "Oslash"], // 233
  [0o120, "P"], // 80
  [0o121, "Q"], // 81
  [0o122, "R"], // 82
  [0o123, "S"], // 83
  [0o124, "T"], // 84
  [0o125, "U"], // 85
  [0o126, "V"], // 86
  [0o127, "W"], // 87
  [0o130, "X"], // 88
  [0o131, "Y"], // 89
  [0o132, "Z"], // 90
  [0o141, "a"], // 97
  [0o302, "acute"], // 194
  [0o361, "ae"], // 241
  [0o046, "ampersand"], // 38
  [0o136, "asciicircum"], // 94
  [0o176, "asciitilde"], // 126
  [0o052, "asterisk"], // 42
  [0o100, "at"], // 64
  [0o142, "b"], // 98
  [0o134, "backslash"], // 92
  [0o174, "bar"], // 124
  [0o173, "braceleft"], // 123
  [0o175, "braceright"], // 125
  [0o133, "bracketleft"], // 91
  [0o135, "bracketright"], // 93
  [0o306, "breve"], // 198
  [0o267, "bullet"], // 183
  [0o143, "c"], // 99
  [0o317, "caron"], // 207
  [0o313, "cedilla"], // 203
  [0o242, "cent"], // 162
  [0o303, "circumflex"], // 195
  [0o072, "colon"], // 58
  [0o054, "comma"], // 44
  [0o250, "currency"], // 168
  [0o144, "d"], // 100
  [0o262, "dagger"], // 178
  [0o263, "daggerdbl"], // 179
  [0o310, "dieresis"], // 200
  [0o044, "dollar"], // 36
  [0o307, "dotaccent"], // 199
  [0o365, "dotlessi"], // 245
  [0o145, "e"], // 101
  [0o070, "eight"], // 56
  [0o274, "ellipsis"], // 188
  [0o320, "emdash"], // 208
  [0o261, "endash"], // 177
  [0o075, "equal"], // 61
  [0o041, "exclam"], // 33
  [0o241, "exclamdown"], // 161
  [0o146, "f"], // 102
  [0o256, "fi"], // 174
  [0o065, "five"], // 53
  [0o257, "fl"], // 175
  [0o246, "florin"], // 166
  [0o064, "four"], // 52
  [0o244, "fraction"], // 164
  [0o147, "g"], // 103
  [0o373, "germandbls"], // 251
  [0o301, "grave"], // 193
  [0o076, "greater"], // 62
  [0o253, "guillemotleft"], // 171
  [0o273, "guillemotright"], // 187
  [0o254, "guilsinglleft"], // 172
  [0o255, "guilsinglright"], // 173
  [0o150, "h"], // 104
  [0o315, "hungarumlaut"], // 205
  [0o055, "hyphen"], // 45
  [0o151, "i"], // 105
  [0o152, "j"], // 106
  [0o153, "k"], // 107
  [0o154, "l"], // 108
  [0o074, "less"], // 60
  [0o370, "lslash"], // 248
  [0o155, "m"], // 109
  [0o305, "macron"], // 197
  [0o156, "n"], // 110
  [0o071, "nine"], // 57
  [0o043, "numbersign"], // 35
  [0o157, "o"], // 111
  [0o372, "oe"], // 250
  [0o316, "ogonek"], // 206
  [0o061, "one"], // 49
  [0o343, "ordfeminine"], // 227
  [0o353, "ordmasculine"], // 235
  [0o371, "oslash"], // 249
  [0o160, "p"], // 112
  [0o266, "paragraph"], // 182
  [0o050, "parenleft"], // 40
  [0o051, "parenright"], // 41
  [0o045, "percent"], // 37
  [0o056, "period"], // 46
  [0o264, "periodcentered"], // 180
  [0o275, "perthousand"], // 189
  [0o053, "plus"], // 43
  [0o161, "q"], // 113
  [0o077, "question"], // 63
  [0o277, "questiondown"], // 191
  [0o042, "quotedbl"], // 34
  [0o271, "quotedblbase"], // 185
  [0o252, "quotedblleft"], // 170
  [0o272, "quotedblright"], // 186
  [0o140, "quoteleft"], // 96
  [0o047, "quoteright"], // 39
  [0o270, "quotesinglbase"], // 184
  [0o251, "quotesingle"], // 169
  [0o162, "r"], // 114
  [0o312, "ring"], // 202
  [0o163, "s"], // 115
  [0o247, "section"], // 167
  [0o073, "semicolon"], // 59
  [0o067, "seven"], // 55
  [0o066, "six"], // 54
  [0o057, "slash"], // 47
  [0o040, "space"], // 32
  [0o243, "sterling"], // 163
  [0o164, "t"], // 116
  [0o063, "three"], // 51
  [0o304, "tilde"], // 196
  [0o062, "two"], // 50
  [0o165, "u"], // 117
  [0o137, "underscore"], // 95
  [0o166, "v"], // 118
  [0o167, "w"], // 119
  [0o170, "x"], // 120
  [0o171, "y"], // 121
  [0o245, "yen"], // 165
  [0o172, "z"], // 122
  [0o060, "zero"], // 48
];

/**
 * Singleton instance of StandardEncoding.
 */
export const STANDARD_ENCODING: Encoding = createEncodingFromEntries(STANDARD_ENCODING_TABLE);

/**
 * Get the StandardEncoding singleton.
 */
export function getStandardEncoding(): Encoding {
  return STANDARD_ENCODING;
}
