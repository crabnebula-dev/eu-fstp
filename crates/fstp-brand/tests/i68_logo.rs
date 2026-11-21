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
    reason = "test code asserts on known-good values"
)]

use fstp_brand::image::{
    LogoFormat, LogoRefusal, MAX_DIMENSION, MAX_LOGO_BYTES, MIN_DIMENSION, PdfColours, inspect,
    pdf_image,
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

// ------------------------------------------------------------------ PDF

/// ADR-030 section 6: an opaque RGB PNG passes into a PDF as its IDAT
/// bytes, unchanged.
#[test]
fn adr030_opaque_png_passes_into_pdf() {
    let png = inspect(&rgb_png(120, 40)).expect("ok").bytes;
    let img = pdf_image(&png).expect("embeddable");
    assert_eq!((img.width, img.height, img.bits), (120, 40, 8));
    assert_eq!(img.colours, PdfColours::Rgb);
    assert_eq!(img.data, vec![0x78, 0x9C, 0x01, 0x02, 0x03, 0x04]);
    assert_eq!(img.mask, None);
}

/// ADR-030 section 6: a palette PNG with one fully transparent entry gets
/// a colour-key mask. Partial transparency, alpha channels, interlacing
/// and WebP are not embeddable.
#[test]
fn adr030_pdf_embedding_rules() {
    let plte = chunk(b"PLTE", &[0, 0, 0, 255, 255, 255, 200, 0, 0]);
    let one_clear = chunk(b"tRNS", &[255, 0]);
    let png = png_with(64, 64, 8, 3, 0, &[plte.clone(), one_clear, idat()]);
    let img = pdf_image(&png).expect("embeddable");
    assert_eq!(
        img.colours,
        PdfColours::Indexed(vec![0, 0, 0, 255, 255, 255, 200, 0, 0])
    );
    assert_eq!(img.mask, Some(vec![1, 1]));
    let partial = png_with(64, 64, 8, 3, 0, &[plte, chunk(b"tRNS", &[128]), idat()]);
    assert!(pdf_image(&partial).is_none());
    assert!(pdf_image(&png_with(64, 64, 8, 6, 0, &[idat()])).is_none());
    assert!(pdf_image(&png_with(64, 64, 8, 2, 1, &[idat()])).is_none());
    assert!(pdf_image(&png_with(64, 64, 16, 2, 0, &[idat()])).is_none());
    assert!(pdf_image(&riff(&[vp8(400, 100)])).is_none());
    let grey = png_with(64, 64, 8, 0, 0, &[chunk(b"tRNS", &[0, 7]), idat()]);
    let g = pdf_image(&grey).expect("grey");
    assert_eq!((g.colours, g.mask), (PdfColours::Gray, Some(vec![7, 7])));
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
