# ADR-031: In-house PNG and DEFLATE codec

Status: Proposed. Drafted 2026-11-22 by lane L23 (`prod/png-codec`) before its code, as CLAUDE.md asks. Rows marked "Interim, pending Daniel" wait for his answer.

The number is the next free one: ADR-030 is lane L22's (`prod/branding-theme`, not merged yet).

## Context

- `SPEC/03-architecture/white-labelling.md` asks that images are re-encoded on upload. I-68 says branding is data only.
- ADR-030 (lane L22) accepts PNG and WebP logos and checks them by headers and chunks only. Without a pixel decoder, uploads keep the uploader's encoded pixel data. Logos with alpha, interlaced or 16-bit PNGs and all WebP stay out of PDFs, and contrast is only advised in the browser.
- The lead decided on 2026-11-22 (ADR-030, "Lead reading, 2026-11-22", item 3) that a follow-up writes an in-house inflate and a PNG decoder and encoder, with no new crate. Most real logos are transparent PNGs, so this is a usability need.
- CLAUDE.md: no third-party crate without an ADR allowlist, and every in-house parser gets a fuzz target from its first commit. A codec is not cryptography, so in-house code is allowed.

## Decision

| Topic | Decision |
| --- | --- |
| Crate | `crates/fstp-png`, in-house and pure: no I/O, no `unsafe`, no panic on any input, no float. Its only dependency is the workspace crate `fstp-creator`, for `Rgb` and the integer WCAG bounds `linear_bounds` behind `meets_aa`. No third-party crate |
| Inflate | RFC 1951 stored, fixed and dynamic blocks, and the RFC 1950 zlib wrapper with Adler-32. Strict: a bad block type, a stored length whose complement does not match, an over-subscribed or incomplete code (except a single code of one bit, as zlib allows), a code length repeat with no previous length, literal/length symbols 286 and 287, distance symbols 30 and 31, a distance before the start of the output or beyond the window that the zlib header declares, a preset dictionary, a bad header check, a bad Adler-32 and any byte after the stream are all refused |
| Inflate limits | The caller names the output cap. Output past the cap is refused when it would be written, so memory never exceeds the cap. Time is linear: each dynamic block builds tables of a fixed size, and each block consumes input. Interim, pending Daniel |
| Deflate | A deterministic encoder: LZ77 with hash chains over the 32 KiB window, then per block the smallest of stored, fixed Huffman and dynamic Huffman. Dynamic codes are length-limited by package-merge. Every code it writes is complete. Size matters little for logos, but the dynamic codes keep a re-encoded logo near the size of the upload |
| PNG decode | Every colour type and bit depth of PNG 1.2: grey 1, 2, 4, 8 and 16; RGB 8 and 16; palette 1, 2, 4 and 8; grey with alpha 8 and 16; RGBA 8 and 16. `PLTE` and `tRNS`, Adam7 interlace, all five filters, and a CRC-32 check on every chunk. The output is RGBA with 8 bits per channel |
| PNG rules | The signature; `IHDR` first with 13 bytes and a valid combination; `PLTE` at most once, before `IDAT`, required for palette images and refused for grey ones; `tRNS` at most once, after `PLTE` and before `IDAT`, with the length its colour type allows; contiguous `IDAT`; `IEND` empty and last, with nothing after it. An unknown critical chunk is refused. Ancillary chunks are checked by CRC, then dropped |
| PNG limits | ADR-030's logo limits: at most 256 KiB (262,144 bytes) of file, each side from 16 to 2048 pixels. The decompressed size is the exact size the header implies, at most 33,556,480 bytes (2048 rows of 1 + 2048 times 8 bytes). Short or long image data is refused. The limits are a value the caller passes, with `Limits::LOGO` as the default |
| Samples | A 16-bit sample becomes 8 bits by rounding (`(v * 255 + 32895) / 65535`). A sample under 8 bits is scaled exactly to 0 to 255. A `tRNS` key is compared with the full sample before scaling. A key outside the bit depth never matches. A palette index past the palette is refused. Interim, pending Daniel |
| Colour chunks | `gAMA`, `cHRM`, `sRGB` and `iCCP` are dropped with the other ancillary chunks. The pixels are read as sRGB, as browsers show most logos. A logo with an unusual gamma may shift slightly in tone. Interim, pending Daniel |
| PNG encode | One canonical shape (I-68: only the pixels survive). 8 bits per channel, not interlaced, `IHDR`, one `IDAT` and `IEND`, nothing else. RGB (colour type 2) when every pixel is opaque, RGBA (colour type 6) otherwise. Each row takes the filter with the smallest sum of absolute residuals. The same pixels always give the same bytes |
| Re-encode | `reencode(bytes, limits)` decodes and encodes again. The result passes the same decoder and the same limits. When the re-encoded file is bigger than the file limit it is refused with its own code, so the caller can say so in plain words. Interim, pending Daniel |
| PDF helpers | `flatten` composites the RGBA pixels over a given background colour in 8-bit sRGB with rounding, giving RGB. `pdf_rgb` gives the zlib stream of those rows with PNG filters, for `/FlateDecode` with `/DecodeParms << /Predictor 15 /Colors 3 /BitsPerComponent 8 /Columns w >>`. `pdf_alpha` gives the alpha plane the same way with `/Colors 1`, for an `/SMask` when a PDF wants real transparency. The wiring into `fstp-pdf` belongs to L22's follow-up |
| Contrast | `contrast(image, background)` composites each pixel with any opacity over the background, as a browser does. It takes the WCAG ratio of the result against the background with the lower and upper luminance bounds of `fstp_creator::linear_bounds`, so it never overstates a ratio. `meets_aa` uses the same bounds. It reports the median ratio of the logo's ink, weighted by opacity, in hundredths, and the share of ink, in thousandths, under 3:1. A fully transparent logo gives no estimate. Integer arithmetic only. The threshold and whether it advises or refuses stay with L22's follow-up. Interim, pending Daniel |
| WebP | Not decoded here (section "WebP") |
| Fuzzing | `crates/fstp-png/fuzz` with targets `inflate` (raw and zlib, any input, under a cap), `png_decode` (any input under `Limits::LOGO`, and every success re-encoded and decoded to the same pixels) and `roundtrip` (pixels from the input, encoded, decoded and compared; and deflate then inflate equals the input). The crate joins `deps/fuzz-required.txt` (TH-26, H-05) |
| Tests | Synthetic only: no image file is downloaded or committed. The PngSuite cases are rebuilt in tests from hand-built bytes and the crate's own encoder: every colour type and depth, `tRNS` in each form, all filters, Adam7 with sizes that leave passes empty, stored and fixed and dynamic blocks, and refusals of malformed streams, CRC errors, oversize and bomb inputs. Names carry I-68, R-WL-03 and TH-26 |

## WebP

This lane writes no VP8 or VP8L decoder, as its brief says. The work it would take, estimated:

- VP8L (lossless): prefix-code groups, the colour cache, LZ77 with two-dimensional distance codes, and four transforms. About 1,200 to 1,800 lines.
- VP8 (lossy): the boolean entropy decoder, the coefficient probability tables (about 1,000 lines of constants), intra prediction, the inverse DCT and Walsh-Hadamard transforms, the loop filters and YUV to RGB conversion. About 2,500 to 3,500 lines.
- `ALPH`: VP8L-compressed or raw alpha with its filters. About 200 lines.
- Tests are harder than for PNG. The crate has no WebP encoder, so synthetic fixtures for lossy images would need one, or vendored test files.

In total about 4,000 to 5,500 lines and a few lane-days, plus a fuzz target per decoder.

Options for the lead:

1. The admin page converts a WebP to PNG before upload. ADR-030 already draws the chosen file on a `canvas` through the browser's own decoder, and `canvas.toBlob` with `image/png` gives a PNG. The server then only ever stores PNG, re-encoded by this crate. This needs no new server code.
2. The server refuses WebP with a plain message asking for a PNG.
3. A later lane writes the decoders above.

Interim, pending Daniel: the lane recommends option 1, with option 2 for uploads that do not come through the admin page.

## Consequences

- L22's follow-up fills ADR-030's seam: `fstp_brand::image::reencode` calls `fstp_png::reencode`, `pdf_image` flattens alpha with `pdf_rgb` (or keeps it with `pdf_alpha`), and `header_contrast` calls `contrast`.
- No new third-party crate, no change to `deps/adr-roots.txt`.
- The crate is an untrusted-input parser, so it carries fuzz targets from its first commit (TH-26).

## Open questions for Daniel

1. Strictness: the decoder refuses streams that libpng and zlib would sometimes accept with a warning, such as trailing bytes after the zlib stream or a palette index past the palette. Interim, pending Daniel.
2. Colour chunks: `gAMA`, `cHRM`, `sRGB` and `iCCP` are dropped, and pixels are read as sRGB. Interim, pending Daniel.
3. Canonical shape: RGB when opaque, else RGBA, 8 bits, one `IDAT`. A palette form would be smaller but is a second shape. Interim, pending Daniel.
4. A re-encoded logo over 256 KiB is refused. The alternative is to store it anyway, since it was made by the platform. Interim, pending Daniel.
5. Contrast metric: the opacity-weighted median ratio and the share under 3:1. The threshold, and whether it advises or refuses, belong to L22's follow-up. Interim, pending Daniel.
6. WebP: section "WebP". Interim, pending Daniel.
7. The dependency on `fstp-creator` brings its in-house tree (`fstp-domain`, `fstp-ledger` and others) into the codec's build. The alternative is to move the luminance bounds into a small crate of their own. Interim, pending Daniel.
