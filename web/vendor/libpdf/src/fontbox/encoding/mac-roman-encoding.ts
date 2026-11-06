/**
 * Mac Roman Encoding.
 *
 * This is the encoding used on classic Macintosh systems.
 *
 * Ported from Apache PDFBox's fontbox/encoding/MacRomanEncoding.java
 */

import { createEncodingFromEntries, type Encoding } from "./encoding.ts";

/**
 * Mac Roman encoding character code to glyph name mappings.
 * Character codes are in decimal (converted from octal in the original).
 */
const MAC_ROMAN_ENCODING_TABLE: ReadonlyArray<readonly [number, string]> = [
  [0o101, "A"], // 65
  [0o256, "AE"], // 174
  [0o347, "Aacute"], // 231
  [0o345, "Acircumflex"], // 229
  [0o200, "Adieresis"], // 128
  [0o313, "Agrave"], // 203
  [0o201, "Aring"], // 129
  [0o314, "Atilde"], // 204
  [0o102, "B"], // 66
  [0o103, "C"], // 67
  [0o202, "Ccedilla"], // 130
  [0o104, "D"], // 68
  [0o105, "E"], // 69
  [0o203, "Eacute"], // 131
  [0o346, "Ecircumflex"], // 230
  [0o350, "Edieresis"], // 232
  [0o351, "Egrave"], // 233
  [0o106, "F"], // 70
  [0o107, "G"], // 71
  [0o110, "H"], // 72
  [0o111, "I"], // 73
  [0o352, "Iacute"], // 234
  [0o353, "Icircumflex"], // 235
  [0o354, "Idieresis"], // 236
  [0o355, "Igrave"], // 237
  [0o112, "J"], // 74
  [0o113, "K"], // 75
  [0o114, "L"], // 76
  [0o115, "M"], // 77
  [0o116, "N"], // 78
  [0o204, "Ntilde"], // 132
  [0o117, "O"], // 79
  [0o316, "OE"], // 206
  [0o356, "Oacute"], // 238
  [0o357, "Ocircumflex"], // 239
  [0o205, "Odieresis"], // 133
  [0o361, "Ograve"], // 241
  [0o257, "Oslash"], // 175
  [0o315, "Otilde"], // 205
  [0o120, "P"], // 80
  [0o121, "Q"], // 81
  [0o122, "R"], // 82
  [0o123, "S"], // 83
  [0o124, "T"], // 84
  [0o125, "U"], // 85
  [0o362, "Uacute"], // 242
  [0o363, "Ucircumflex"], // 243
  [0o206, "Udieresis"], // 134
  [0o364, "Ugrave"], // 244
  [0o126, "V"], // 86
  [0o127, "W"], // 87
  [0o130, "X"], // 88
  [0o131, "Y"], // 89
  [0o331, "Ydieresis"], // 217
  [0o132, "Z"], // 90
  [0o141, "a"], // 97
  [0o207, "aacute"], // 135
  [0o211, "acircumflex"], // 137
  [0o253, "acute"], // 171
  [0o212, "adieresis"], // 138
  [0o276, "ae"], // 190
  [0o210, "agrave"], // 136
  [0o046, "ampersand"], // 38
  [0o214, "aring"], // 140
  [0o136, "asciicircum"], // 94
  [0o176, "asciitilde"], // 126
  [0o052, "asterisk"], // 42
  [0o100, "at"], // 64
  [0o213, "atilde"], // 139
  [0o142, "b"], // 98
  [0o134, "backslash"], // 92
  [0o174, "bar"], // 124
  [0o173, "braceleft"], // 123
  [0o175, "braceright"], // 125
  [0o133, "bracketleft"], // 91
  [0o135, "bracketright"], // 93
  [0o371, "breve"], // 249
  [0o245, "bullet"], // 165
  [0o143, "c"], // 99
  [0o377, "caron"], // 255
  [0o215, "ccedilla"], // 141
  [0o374, "cedilla"], // 252
  [0o242, "cent"], // 162
  [0o366, "circumflex"], // 246
  [0o072, "colon"], // 58
  [0o054, "comma"], // 44
  [0o251, "copyright"], // 169
  [0o333, "currency"], // 219
  [0o144, "d"], // 100
  [0o240, "dagger"], // 160
  [0o340, "daggerdbl"], // 224
  [0o241, "degree"], // 161
  [0o254, "dieresis"], // 172
  [0o326, "divide"], // 214
  [0o044, "dollar"], // 36
  [0o372, "dotaccent"], // 250
  [0o365, "dotlessi"], // 245
  [0o145, "e"], // 101
  [0o216, "eacute"], // 142
  [0o220, "ecircumflex"], // 144
  [0o221, "edieresis"], // 145
  [0o217, "egrave"], // 143
  [0o070, "eight"], // 56
  [0o311, "ellipsis"], // 201
  [0o321, "emdash"], // 209
  [0o320, "endash"], // 208
  [0o075, "equal"], // 61
  [0o041, "exclam"], // 33
  [0o301, "exclamdown"], // 193
  [0o146, "f"], // 102
  [0o336, "fi"], // 222
  [0o065, "five"], // 53
  [0o337, "fl"], // 223
  [0o304, "florin"], // 196
  [0o064, "four"], // 52
  [0o332, "fraction"], // 218
  [0o147, "g"], // 103
  [0o247, "germandbls"], // 167
  [0o140, "grave"], // 96
  [0o076, "greater"], // 62
  [0o307, "guillemotleft"], // 199
  [0o310, "guillemotright"], // 200
  [0o334, "guilsinglleft"], // 220
  [0o335, "guilsinglright"], // 221
  [0o150, "h"], // 104
  [0o375, "hungarumlaut"], // 253
  [0o055, "hyphen"], // 45
  [0o151, "i"], // 105
  [0o222, "iacute"], // 146
  [0o224, "icircumflex"], // 148
  [0o225, "idieresis"], // 149
  [0o223, "igrave"], // 147
  [0o152, "j"], // 106
  [0o153, "k"], // 107
  [0o154, "l"], // 108
  [0o074, "less"], // 60
  [0o302, "logicalnot"], // 194
  [0o155, "m"], // 109
  [0o370, "macron"], // 248
  [0o265, "mu"], // 181
  [0o156, "n"], // 110
  [0o071, "nine"], // 57
  [0o226, "ntilde"], // 150
  [0o043, "numbersign"], // 35
  [0o157, "o"], // 111
  [0o227, "oacute"], // 151
  [0o231, "ocircumflex"], // 153
  [0o232, "odieresis"], // 154
  [0o317, "oe"], // 207
  [0o376, "ogonek"], // 254
  [0o230, "ograve"], // 152
  [0o061, "one"], // 49
  [0o273, "ordfeminine"], // 187
  [0o274, "ordmasculine"], // 188
  [0o277, "oslash"], // 191
  [0o233, "otilde"], // 155
  [0o160, "p"], // 112
  [0o246, "paragraph"], // 166
  [0o050, "parenleft"], // 40
  [0o051, "parenright"], // 41
  [0o045, "percent"], // 37
  [0o056, "period"], // 46
  [0o341, "periodcentered"], // 225
  [0o344, "perthousand"], // 228
  [0o053, "plus"], // 43
  [0o261, "plusminus"], // 177
  [0o161, "q"], // 113
  [0o077, "question"], // 63
  [0o300, "questiondown"], // 192
  [0o042, "quotedbl"], // 34
  [0o343, "quotedblbase"], // 227
  [0o322, "quotedblleft"], // 210
  [0o323, "quotedblright"], // 211
  [0o324, "quoteleft"], // 212
  [0o325, "quoteright"], // 213
  [0o342, "quotesinglbase"], // 226
  [0o047, "quotesingle"], // 39
  [0o162, "r"], // 114
  [0o250, "registered"], // 168
  [0o373, "ring"], // 251
  [0o163, "s"], // 115
  [0o244, "section"], // 164
  [0o073, "semicolon"], // 59
  [0o067, "seven"], // 55
  [0o066, "six"], // 54
  [0o057, "slash"], // 47
  [0o040, "space"], // 32
  [0o243, "sterling"], // 163
  [0o164, "t"], // 116
  [0o063, "three"], // 51
  [0o367, "tilde"], // 247
  [0o252, "trademark"], // 170
  [0o062, "two"], // 50
  [0o165, "u"], // 117
  [0o234, "uacute"], // 156
  [0o236, "ucircumflex"], // 158
  [0o237, "udieresis"], // 159
  [0o235, "ugrave"], // 157
  [0o137, "underscore"], // 95
  [0o166, "v"], // 118
  [0o167, "w"], // 119
  [0o170, "x"], // 120
  [0o171, "y"], // 121
  [0o330, "ydieresis"], // 216
  [0o264, "yen"], // 180
  [0o172, "z"], // 122
  [0o060, "zero"], // 48
];

/**
 * Singleton instance of MacRomanEncoding.
 */
export const MAC_ROMAN_ENCODING: Encoding = createEncodingFromEntries(MAC_ROMAN_ENCODING_TABLE);

/**
 * Get the MacRomanEncoding singleton.
 */
export function getMacRomanEncoding(): Encoding {
  return MAC_ROMAN_ENCODING;
}
