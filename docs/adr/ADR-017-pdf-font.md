# ADR-017: The one embedded PDF font

Status: Accepted 2026-11-06 (Daniel Thompson-Yvetot). The `TODO(legal)` items on the OFL stay open.

## Context

M5 design section 3.4 asks `fstp-pdf` to embed one font under the SIL Open Font License 1.1, in full and without subsetting. The contract PDFs, the Guide PDF (R-GA-02) and the signature appearance streams all use it. Its glyph widths come from the in-house TrueType reader of `fstp-pdf`, which has a fuzz target.

Constraints:

- The writer must be deterministic (R-CT-01, R-GA-02, I-53), so the font bytes are part of the output and must never change silently.
- No third-party crate reads the font. The reader is in-house and bounded.
- Contracts carry names and places from every EU language. The writer refuses a character the font has no glyph for, with a typed error, rather than drawing a substitute.

## Decision

### Source and pin

| Item | Value |
| --- | --- |
| Font | IBM Plex Sans Regular, TrueType outlines (`glyf`), 1000 units per em |
| Repository | `https://github.com/IBM/plex` |
| Release tag | `@ibm/plex-sans@1.1.0`, published 2024-11-13. Annotated tag object `036e2d2a727bd6a378f69b7cde8d8dd20c472dae` |
| Commit | `1da12f02587b630c07e92692d21492d722f53614` |
| Upstream path | `packages/plex-sans/fonts/complete/ttf/IBMPlexSans-Regular.ttf` |
| Git blob | `bd6817d5202895da5ac4fad88de3da71e652881a` |
| Size | 200 500 bytes |
| SHA-256 | `975dcda37d80f038dcd143c22e33ca2d97a0cc5a929aace1c749153b0fe1afa5` |
| Licence file | `packages/plex-sans/LICENSE.txt`, blob `c35c4c618fab33da8695177b3a6cefe0810b7b28`, SHA-256 `7e6b2818edbd8f6a01ae80641cc8f16a51080d08fb4e532be3a0b6f74adb07da` |
| Fetched | 2026-11-06, through the GitHub API and raw file host |

Both files are stored byte for byte as upstream holds them:

- `crates/fstp-pdf/assets/IBMPlexSans-Regular.ttf`
- `crates/fstp-pdf/assets/IBMPlexSans-LICENSE.txt`

Their git blob hashes equal the upstream blobs above, so `git hash-object` checks the import without extra tools.

### Licence

- The licence file states copyright 2017 IBM Corp. with Reserved Font Name "Plex", under the SIL Open Font License 1.1. Its full text sits next to the font.
- The font is embedded unmodified and in full. No subset or derived font is made, so no renamed font is needed.
- The `OS/2` `fsType` is checked at every parse. A font that forbids embedding is refused.
- `TODO(legal)`: confirm that embedding the unmodified font in contract and Guide PDFs given to grantees and the public meets the OFL 1.1 conditions.
- `TODO(legal)`: confirm where the OFL text must travel with the platform build, for example in the third-party notices that ship with the web assets and the cell binary.
- `TODO(legal)`: confirm that the OFL sits with the platform licence (PolyForm-Noncommercial-1.0.0).

### How the writer uses it

- `fstp-pdf` includes the file at compile time. `embedded_font()` checks its SHA-256 against the pin before every parse, and a mismatch is refused.
- The writer embeds it as a `CIDFontType2` with `Identity-H` and an identity `CIDToGIDMap`, as `/FontFile2` without a filter. `/W` and `/ToUnicode` list only the glyphs a document uses, in glyph order.
- The reader reads `head`, `hhea`, `maxp`, `hmtx`, `cmap` (format 12, else format 4), `OS/2` and `post`. It never executes hinting code and never reads outlines.
- The fuzz target `truetype_decode` in `crates/fstp-pdf/fuzz` covers the reader.

### Change rule

A new font, a new version or any byte change is a new decision. It needs a new row here with the same fields, and a review of the rendered output, since every later rendering changes. A published Guide PDF stays as stored (I-53).

## Consequences

- Every PDF carries the full font, about 200 KB. Revision sizes grow by that much.
- Characters outside the font's coverage are refused with `WriteError::GlyphMissing`. A second font for other scripts needs a new decision.
- The signature appearance streams of revision 0 reuse this font, so LibPDF does no font work (ADR-016).
