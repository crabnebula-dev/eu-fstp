//! Tests of the logo check (ADR-030 section 3; I-68, R-WL-03).
//!
//! The fixtures are synthetic: chunk sequences built here, with image
//! data that is never decoded.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing,
    reason = "test code asserts on known-good values"
)]

use fstp_brand::image::{
    ADVICE_BELOW_X100, LogoFormat, LogoRefusal, MAX_DIMENSION, MAX_LOGO_BYTES, MIN_DIMENSION,
    header_contrast, inspect, pdf_image, png_of, reencode,
};
use fstp_prop::{check, prop_assert, prop_assert_eq};

// ------------------------------------------------------------ builders

/// CRC-32 of ISO 3309, written here apart from the crate's own.
fn crc(bytes: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for b in bytes {
        c ^= u32::from(*b);
        for _ in 0..8 {
            c = if c & 1 == 1 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut out = (data.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let mut covered = kind.to_vec();
    covered.extend_from_slice(data);
    out.extend_from_slice(&crc(&covered).to_be_bytes());
    out
}

const SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

fn ihdr(w: u32, h: u32, depth: u8, colour: u8, interlace: u8) -> Vec<u8> {
    let mut d = w.to_be_bytes().to_vec();
    d.extend_from_slice(&h.to_be_bytes());
    d.extend_from_slice(&[depth, colour, 0, 0, interlace]);
    chunk(b"IHDR", &d)
}

/// A PNG of the given chunks between the header and `IEND`.
fn png_with(w: u32, h: u32, depth: u8, colour: u8, interlace: u8, middle: &[Vec<u8>]) -> Vec<u8> {
    let mut out = SIG.to_vec();
    out.extend(ihdr(w, h, depth, colour, interlace));
    for c in middle {
        out.extend_from_slice(c);
    }
    out.extend(chunk(b"IEND", &[]));
    out
}

fn idat() -> Vec<u8> {
    chunk(b"IDAT", &[0x78, 0x9C, 0x01, 0x02, 0x03, 0x04])
}

fn rgb_png(w: u32, h: u32) -> Vec<u8> {
    png_with(w, h, 8, 2, 0, &[idat()])
}

fn riff(chunks: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = chunks.concat();
    let mut out = b"RIFF".to_vec();
    out.extend_from_slice(&((body.len() + 4) as u32).to_le_bytes());
    out.extend_from_slice(b"WEBP");
    out.extend(body);
    out
}

fn wchunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut out = kind.to_vec();
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    if data.len() % 2 == 1 {
        out.push(0);
    }
    out
}

fn vp8(w: u16, h: u16) -> Vec<u8> {
    // Frame tag: key frame, version 0, shown, partition length 0.
    let mut d = vec![0x10, 0x00, 0x00, 0x9D, 0x01, 0x2A];
    d.extend_from_slice(&w.to_le_bytes());
    d.extend_from_slice(&h.to_le_bytes());
    d.extend_from_slice(&[1, 2, 3, 4]);
    wchunk(b"VP8 ", &d)
}

fn vp8l(w: u32, h: u32, alpha: bool) -> Vec<u8> {
    let bits = (w - 1) | ((h - 1) << 14) | (u32::from(alpha) << 28);
    let mut d = vec![0x2F];
    d.extend_from_slice(&bits.to_le_bytes());
    d.extend_from_slice(&[9, 9, 9]);
    wchunk(b"VP8L", &d)
}

fn vp8x(flags: u8, w: u32, h: u32) -> Vec<u8> {
    let mut d = vec![flags, 0, 0, 0];
    d.extend_from_slice(&(w - 1).to_le_bytes()[..3]);
    d.extend_from_slice(&(h - 1).to_le_bytes()[..3]);
    wchunk(b"VP8X", &d)
}

fn has(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// ------------------------------------------------------------------ PNG

/// I-68, R-WL-03: a well-formed PNG is accepted with its size, and the
/// stored bytes keep only the chunks that draw the image. A text chunk
/// that holds markup is dropped.
#[test]
fn i68_png_is_accepted_and_text_chunks_are_dropped() {
    let text = chunk(b"tEXt", b"Comment\0<script>alert(1)</script>");
    let exif = chunk(b"eXIf", b"MM\0*synthetic");
    let gama = chunk(b"gAMA", &45_455u32.to_be_bytes());
    let png = png_with(320, 80, 8, 6, 0, &[text, gama.clone(), idat(), exif]);
    let logo = inspect(&png).expect("accepted");
    assert_eq!(logo.format, LogoFormat::Png);
    assert_eq!((logo.width, logo.height), (320, 80));
    assert!(logo.bytes.starts_with(&SIG));
    assert!(!has(&logo.bytes, b"<script>"));
    assert!(!has(&logo.bytes, b"tEXt"));
    assert!(!has(&logo.bytes, b"eXIf"));
    assert!(has(&logo.bytes, &gama));
    assert!(has(&logo.bytes, &idat()));
    assert!(logo.bytes.ends_with(&chunk(b"IEND", &[])));
    // The rewrite is stable: the stored bytes pass again unchanged.
    assert_eq!(inspect(&logo.bytes).expect("again").bytes, logo.bytes);
}

/// I-68: SVG, markup, GIF, JPEG and empty input are refused as a type no
/// logo may have. No SVG is ever stored.
#[test]
fn i68_svg_and_other_types_are_refused() {
    for bad in [
        b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>x</script></svg>".to_vec(),
        b"<?xml version=\"1.0\"?><svg/>".to_vec(),
        b"<html><body>x</body></html>".to_vec(),
        b"GIF89a\x10\x00\x10\x00".to_vec(),
        vec![0xFF, 0xD8, 0xFF, 0xE0, 0, 16, b'J', b'F', b'I', b'F'],
        Vec::new(),
    ] {
        assert_eq!(inspect(&bad).err(), Some(LogoRefusal::WrongType), "{bad:?}");
    }
}

/// I-68: a file over the size bound is refused before it is read.
#[test]
fn i68_logo_over_the_size_bound_is_refused() {
    let mut png = rgb_png(64, 64);
    png.resize(MAX_LOGO_BYTES + 1, 0);
    assert_eq!(inspect(&png).err(), Some(LogoRefusal::TooLarge));
}

/// I-68: width and height each lie from 16 to 2048 pixels.
#[test]
fn i68_logo_dimensions_are_bounded() {
    assert!(inspect(&rgb_png(MIN_DIMENSION, MIN_DIMENSION)).is_ok());
    assert!(inspect(&rgb_png(MAX_DIMENSION, MAX_DIMENSION)).is_ok());
    for (w, h) in [
        (MIN_DIMENSION - 1, 100),
        (100, MIN_DIMENSION - 1),
        (MAX_DIMENSION + 1, 100),
        (100, MAX_DIMENSION + 1),
    ] {
        assert_eq!(
            inspect(&rgb_png(w, h)).err(),
            Some(LogoRefusal::Dimensions),
            "{w}x{h}"
        );
    }
}

/// I-68: a PNG whose structure is wrong is refused.
#[test]
fn i68_malformed_png_is_refused() {
    let good = rgb_png(64, 64);
    // A flipped data byte breaks the chunk's CRC.
    let mut bad_crc = good.clone();
    bad_crc[SIG.len() + 8 + 1] ^= 0x01;
    // Bytes after IEND.
    let mut trailing = good.clone();
    trailing.extend_from_slice(b"<svg/>");
    // An unknown critical chunk.
    let critical = png_with(64, 64, 8, 2, 0, &[chunk(b"ABCD", b"x"), idat()]);
    // A palette image without PLTE.
    let no_palette = png_with(64, 64, 8, 3, 0, &[idat()]);
    // IDAT chunks that are not contiguous.
    let split = png_with(64, 64, 8, 2, 0, &[idat(), chunk(b"tEXt", b"a\0b"), idat()]);
    // No IDAT at all.
    let empty = png_with(64, 64, 8, 2, 0, &[]);
    // A bit depth the colour type does not allow.
    let depth = png_with(64, 64, 4, 2, 0, &[idat()]);
    // No IEND.
    let mut cut = good.clone();
    cut.truncate(cut.len() - 12);
    for (name, bad) in [
        ("crc", bad_crc),
        ("trailing", trailing),
        ("critical", critical),
        ("no_palette", no_palette),
        ("split", split),
        ("empty", empty),
        ("depth", depth),
        ("cut", cut),
    ] {
        assert_eq!(inspect(&bad).err(), Some(LogoRefusal::Malformed), "{name}");
    }
}

// ----------------------------------------------------------------- WebP

/// I-68, R-WL-03: simple lossy and lossless WebP files are accepted with
/// their size.
#[test]
fn i68_simple_webp_is_accepted() {
    let lossy = inspect(&riff(&[vp8(400, 100)])).expect("lossy");
    assert_eq!(lossy.format, LogoFormat::Webp);
    assert_eq!((lossy.width, lossy.height), (400, 100));
    let lossless = inspect(&riff(&[vp8l(200, 50, true)])).expect("lossless");
    assert_eq!((lossless.width, lossless.height), (200, 50));
    assert_eq!(
        inspect(&lossless.bytes).expect("again").bytes,
        lossless.bytes
    );
}

/// I-68: an extended WebP keeps its alpha and image chunks only. EXIF and
/// XMP chunks are dropped and their flags cleared.
#[test]
fn i68_extended_webp_drops_metadata() {
    let flags = 0x10 | 0x08 | 0x04;
    let file = riff(&[
        vp8x(flags, 400, 100),
        wchunk(b"ALPH", &[0, 1, 2]),
        vp8(400, 100),
        wchunk(b"EXIF", b"<script>x</script>"),
        wchunk(b"XMP ", b"<x:xmpmeta/>"),
    ]);
    let logo = inspect(&file).expect("accepted");
    assert!(!has(&logo.bytes, b"<script>"));
    assert!(!has(&logo.bytes, b"EXIF"));
    assert!(!has(&logo.bytes, b"XMP "));
    assert!(has(&logo.bytes, b"ALPH"));
    assert_eq!(logo.bytes.get(20), Some(&0x10), "only the alpha flag stays");
    let size = u32::from_le_bytes(logo.bytes[4..8].try_into().unwrap()) as usize;
    assert_eq!(size + 8, logo.bytes.len());
}

/// I-68: an animated WebP is refused, and so is a canvas that does not
/// match its bitstream or a RIFF length that does not match the file.
#[test]
fn i68_animated_or_inconsistent_webp_is_refused() {
    let animated = riff(&[vp8x(0x02, 400, 100), wchunk(b"ANIM", &[0; 6])]);
    assert_eq!(inspect(&animated).err(), Some(LogoRefusal::Animated));
    let mismatch = riff(&[vp8x(0, 400, 100), vp8(300, 100)]);
    assert_eq!(inspect(&mismatch).err(), Some(LogoRefusal::Malformed));
    let mut length = riff(&[vp8(400, 100)]);
    length.push(0);
    assert_eq!(inspect(&length).err(), Some(LogoRefusal::Malformed));
    let not_key = {
        let mut f = riff(&[vp8(400, 100)]);
        f[20] |= 0x01;
        f
    };
    assert_eq!(inspect(&not_key).err(), Some(LogoRefusal::Malformed));
}

// ------------------------------------------------------- re-encode, PDF

/// An RGBA image of `w` by `h`: a dark square on a transparent field when
/// `clear`, else white everywhere.
fn pixels(w: u32, h: u32, clear: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for y in 0..h {
        for x in 0..w {
            let ink = x >= w / 4 && x < 3 * w / 4 && y >= h / 4 && y < 3 * h / 4;
            out.extend_from_slice(&match (clear, ink) {
                (true, true) => [0x10, 0x20, 0x40, 0xFF],
                (true, false) => [0, 0, 0, 0],
                (false, _) => [0xFF, 0xFF, 0xFF, 0xFF],
            });
        }
    }
    out
}

fn real_png(w: u32, h: u32, clear: bool) -> Vec<u8> {
    png_of(w, h, pixels(w, h, clear)).expect("sizes match")
}

/// Inserts `extra` chunks after `IHDR` of a canonical PNG.
fn with_chunks(png: &[u8], extra: &[Vec<u8>]) -> Vec<u8> {
    let at = 8 + 25;
    let mut out = png[..at].to_vec();
    for c in extra {
        out.extend_from_slice(c);
    }
    out.extend_from_slice(&png[at..]);
    out
}

/// I-68, R-WL-03, ADR-031: an upload is re-encoded. Text, EXIF, colour
/// and unknown ancillary chunks are gone, the pixels stay, and the stored
/// file is the canonical PNG of those pixels.
#[test]
fn i68_reencode_drops_ancillary_chunks() {
    let canonical = real_png(64, 32, true);
    let upload = with_chunks(
        &canonical,
        &[
            chunk(b"tEXt", b"Comment\0<script>alert(1)</script>"),
            chunk(b"gAMA", &45_455u32.to_be_bytes()),
            chunk(b"zzZz", b"hidden payload"),
        ],
    );
    let logo = inspect(&upload).expect("accepted");
    assert!(has(&logo.bytes, b"gAMA"), "the chunk walk alone keeps gAMA");
    let stored = reencode(logo).expect("re-encoded");
    assert!(!has(&stored.bytes, b"tEXt"));
    assert!(!has(&stored.bytes, b"gAMA"));
    assert!(!has(&stored.bytes, b"zzZz"));
    assert!(!has(&stored.bytes, b"<script>"));
    assert_eq!(stored.bytes, canonical);
    assert_eq!((stored.width, stored.height), (64, 32));
}

/// ADR-030 lead reading of 2026-11-22: the cell takes PNG uploads only.
/// A WebP file is refused as the wrong type, so the branding page sends
/// it converted to PNG.
#[test]
fn adr030_webp_upload_is_refused_after_the_check() {
    let logo = inspect(&riff(&[vp8(400, 100)])).expect("a WebP passes the check");
    assert_eq!(reencode(logo).err(), Some(LogoRefusal::WrongType));
}

/// I-68, R-WL-03, ADR-030: a transparent PNG reaches a PDF as flattened
/// RGB with its alpha plane for an `/SMask`. An opaque one has no alpha
/// plane. WebP and a refused PNG have no PDF image.
#[test]
fn r_wl_03_transparent_png_reaches_pdf_with_alpha() {
    let clear = pdf_image(&real_png(64, 32, true)).expect("embeddable");
    assert_eq!((clear.width, clear.height), (64, 32));
    assert!(!clear.rgb.is_empty());
    assert!(
        clear.alpha.is_some(),
        "a transparent logo has an alpha plane"
    );
    let opaque = pdf_image(&real_png(64, 32, false)).expect("embeddable");
    assert_eq!(opaque.alpha, None);
    assert!(pdf_image(&riff(&[vp8(400, 100)])).is_none());
    assert!(
        pdf_image(&rgb_png(64, 32)).is_none(),
        "the fake IDAT is no image data"
    );
}

/// I-70, ADR-030 lead reading of 2026-11-22: the contrast advice of a
/// logo on each header colour. White on the light header is under the
/// 3:1 advice bound, and the same logo on the dark header is above it.
#[test]
fn i70_contrast_advice_on_each_header() {
    let white = real_png(64, 32, false);
    let light = fstp_creator::Rgb::hex(0xF8_FA_FC);
    let dark = fstp_creator::Rgb::hex(0x1E_29_3B);
    let on_light = header_contrast(&white, light).expect("ink");
    let on_dark = header_contrast(&white, dark).expect("ink");
    assert!(on_light < ADVICE_BELOW_X100, "{on_light}");
    assert!(on_dark >= ADVICE_BELOW_X100, "{on_dark}");
    let empty = png_of(16, 16, vec![0; 16 * 16 * 4]).expect("sizes");
    assert_eq!(header_contrast(&empty, light), None);
}

// ------------------------------------------------------------- property

/// I-68: the check is total. Random bytes and single-byte mutations of
/// valid files never panic. An accepted file is a PNG or WebP within the
/// bounds, its rewrite passes again unchanged, and it holds no markup
/// opener at its start.
#[test]
fn i68_fuzzed_logo_is_data() {
    check("i68_fuzzed_logo_is_data", |g| {
        let seeds = [
            rgb_png(64, 32),
            riff(&[vp8(64, 32)]),
            riff(&[vp8x(0x10, 64, 32), wchunk(b"ALPH", &[1]), vp8(64, 32)]),
        ];
        let bytes = if g.bool() {
            g.bytes(0..=300)
        } else {
            let mut b = g.pick(&seeds).clone();
            let n = b.len();
            let i = g.usize_in(0..=n - 1);
            b[i] = g.u8();
            b
        };
        if let Ok(logo) = inspect(&bytes) {
            prop_assert!(logo.bytes.len() <= MAX_LOGO_BYTES);
            prop_assert!((MIN_DIMENSION..=MAX_DIMENSION).contains(&logo.width));
            prop_assert!((MIN_DIMENSION..=MAX_DIMENSION).contains(&logo.height));
            prop_assert!(logo.bytes.starts_with(&SIG) || logo.bytes.starts_with(b"RIFF"));
            let again = inspect(&logo.bytes).map(|l| l.bytes);
            prop_assert_eq!(again.as_ref().ok(), Some(&logo.bytes));
            let _ = pdf_image(&logo.bytes);
        }
        Ok(())
    });
}

/// I-68: an upload is standard base64 of the file. Text that is not
/// base64 is no image, and text longer than the bound is too large
/// before it is decoded.
#[test]
fn i68_logo_upload_is_base64_of_a_checked_file() {
    use fstp_brand::image::{MAX_BASE64_CHARS, from_base64, sample_png};
    let png = sample_png(64, 32);
    let text = b64(&png);
    let logo = from_base64(&text).expect("accepted");
    assert_eq!((logo.width, logo.height), (64, 32));
    assert_eq!(logo.bytes, png);
    for bad in ["", "!!!!", "abc", "ab=c", "====", " QUJD", "QQ==QQ=="] {
        assert_eq!(
            from_base64(bad).err(),
            Some(LogoRefusal::WrongType),
            "{bad:?}"
        );
    }
    assert_eq!(fstp_brand::image::to_base64(&png), text);
    let svg = b64(b"<svg/>");
    assert_eq!(from_base64(&svg).err(), Some(LogoRefusal::WrongType));
    let long = "A".repeat(MAX_BASE64_CHARS + 4);
    assert_eq!(from_base64(&long).err(), Some(LogoRefusal::TooLarge));
}

/// Standard base64 with padding, written here apart from the crate's
/// decoder.
fn b64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// I-68: a logo path holds only hex digits of the digest and a fixed
/// extension, and only that form parses back.
#[test]
fn i68_logo_path_grammar_is_closed() {
    use fstp_brand::image::{logo_path, logo_path_digest};
    let d = [0xAB; 32];
    let p = logo_path(&d, LogoFormat::Webp);
    assert_eq!(p, format!("/brand/{}.webp", "ab".repeat(32)));
    assert_eq!(logo_path_digest(&p), Some((d, LogoFormat::Webp)));
    for bad in [
        format!("/brand/{}.svg", "ab".repeat(32)),
        format!("/brand/{}.png", "AB".repeat(32)),
        format!("/brand/{}.png", "ab".repeat(31)),
        format!("/brand/{}.css", "ab".repeat(32)),
        format!("/brand/{}.png/x", "ab".repeat(32)),
        format!("/brand/x/{}.png", "ab".repeat(32)),
    ] {
        assert_eq!(logo_path_digest(&bad), None, "{bad}");
    }
}
