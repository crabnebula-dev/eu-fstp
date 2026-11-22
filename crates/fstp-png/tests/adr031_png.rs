//! PNG decoding and canonical re-encoding of `fstp-png` (ADR-031).
//!
//! I-68 and R-WL-03: a logo is decoded to pixels and written again in one
//! canonical shape, so only the pixels survive. TH-26: the decoder is an
//! untrusted-input parser, and every refusal row of ADR-031 "PNG rules"
//! has a hand-built file here. The PngSuite cases are rebuilt
//! synthetically by the reference writer of `common`.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

mod common;

use common::{
    FORMATS, LOOSE, Raw, build, chunk, chunk_types, cycle, expected_rgba, ihdr, palette, png,
    rgba_pattern, stored_zlib,
};
use fstp_png::{Image, Limits, PngError, decode, encode, reencode, zlib_compress};
use fstp_prop::{Config, check_with, prop_assert, prop_assert_eq};

fn plte_for(raw: &Raw) -> Option<Vec<u8>> {
    (raw.colour == 3).then(|| palette(1usize << raw.depth.min(8)))
}

/// TH-26, R-WL-03: every colour type and bit depth, plain and Adam7,
/// with every filter, decodes to the reference pixels.
#[test]
fn th26_r_wl_03_every_colour_type_depth_and_interlace_decodes() {
    for (colour, depth) in FORMATS {
        for interlace in [false, true] {
            for (w, h) in [(1, 1), (3, 5), (8, 8), (9, 3), (17, 13)] {
                let raw = Raw::pattern(w, h, colour, depth, interlace);
                let plte = plte_for(&raw);
                let file = build(&raw, plte.as_deref(), None, &cycle, &stored_zlib);
                let img = decode(&file, &LOOSE).unwrap_or_else(|e| {
                    panic!("colour {colour} depth {depth} interlace {interlace} {w}x{h}: {e:?}")
                });
                assert_eq!((img.width(), img.height()), (w as u32, h as u32));
                assert_eq!(
                    img.rgba(),
                    expected_rgba(&raw, plte.as_deref().unwrap_or(&[]), None).as_slice(),
                    "colour {colour} depth {depth} interlace {interlace} {w}x{h}"
                );
            }
        }
    }
}

/// TH-26: each filter type alone, on every pass and row, and the crate's
/// own deflate as the compressor.
#[test]
fn th26_each_filter_type_alone_decodes() {
    for ft in 0..5u8 {
        for (colour, depth) in [(0, 1), (0, 16), (2, 8), (3, 4), (6, 16), (4, 8)] {
            let raw = Raw::pattern(19, 11, colour, depth, ft % 2 == 1);
            let plte = plte_for(&raw);
            let file = build(&raw, plte.as_deref(), None, &|_, _| ft, &zlib_compress);
            let img = decode(&file, &LOOSE).unwrap();
            assert_eq!(
                img.rgba(),
                expected_rgba(&raw, plte.as_deref().unwrap_or(&[]), None).as_slice()
            );
        }
    }
}

/// TH-26: Adam7 sizes that leave passes empty, from 1x1 to 9x9.
#[test]
fn th26_adam7_small_sizes_with_empty_passes() {
    for w in 1..=9 {
        for h in 1..=9 {
            let raw = Raw::pattern(w, h, 6, 8, true);
            let file = build(&raw, None, None, &cycle, &stored_zlib);
            assert_eq!(
                decode(&file, &LOOSE).unwrap().rgba(),
                expected_rgba(&raw, &[], None).as_slice(),
                "{w}x{h}"
            );
        }
    }
}

/// TH-26, R-WL-03: `tRNS` in each form: a grey key at 1, 8 and 16 bits,
/// an RGB key at 8 and 16 bits, and partial palette transparency.
#[test]
fn th26_r_wl_03_transparency_chunk_forms() {
    for depth in [1u8, 2, 8, 16] {
        let raw = Raw::pattern(12, 7, 0, depth, false);
        let key = raw.samples[1];
        let t = key.to_be_bytes();
        let file = build(&raw, None, Some(&t), &cycle, &stored_zlib);
        let img = decode(&file, &LOOSE).unwrap();
        assert_eq!(img.rgba(), expected_rgba(&raw, &[], Some(&t)).as_slice());
        assert!(img.rgba().chunks(4).any(|p| p[3] == 0));
    }
    for depth in [8u8, 16] {
        let raw = Raw::pattern(12, 7, 2, depth, true);
        let t: Vec<u8> = raw.samples[3..6]
            .iter()
            .flat_map(|v| v.to_be_bytes())
            .collect();
        let file = build(&raw, None, Some(&t), &cycle, &stored_zlib);
        let img = decode(&file, &LOOSE).unwrap();
        assert_eq!(img.rgba(), expected_rgba(&raw, &[], Some(&t)).as_slice());
        assert!(img.rgba().chunks(4).any(|p| p[3] == 0));
    }
    let raw = Raw::pattern(16, 16, 3, 8, false);
    let plte = palette(256);
    let t: Vec<u8> = (0..100u8).map(|i| i.wrapping_mul(13)).collect();
    let file = build(&raw, Some(&plte), Some(&t), &cycle, &stored_zlib);
    let img = decode(&file, &LOOSE).unwrap();
    assert_eq!(img.rgba(), expected_rgba(&raw, &plte, Some(&t)).as_slice());
    // A key outside the bit depth never matches.
    let raw = Raw::pattern(4, 4, 0, 2, false);
    let file = build(&raw, None, Some(&[0, 9]), &cycle, &stored_zlib);
    assert!(decode(&file, &LOOSE).unwrap().is_opaque());
}

/// A valid file of the given chunks between `IHDR` and `IEND`.
fn file_with(head: &[u8], middle: Vec<Vec<u8>>) -> Vec<u8> {
    let mut chunks = vec![head.to_vec()];
    chunks.extend(middle);
    chunks.push(chunk(b"IEND", &[]));
    png(&chunks)
}

fn idat_of(raw: &Raw) -> Vec<u8> {
    chunk(b"IDAT", &zlib_compress(&raw.scanlines(&cycle)))
}

/// TH-26: each malformed file of ADR-031 "PNG rules" is refused with
/// its own error.
#[test]
fn th26_png_refuses_malformed_files() {
    let raw = Raw::pattern(4, 4, 2, 8, false);
    let head = ihdr(4, 4, 8, 2, false);
    let idat = idat_of(&raw);
    let good = file_with(&head, vec![idat.clone()]);
    assert!(decode(&good, &LOOSE).is_ok());

    let mut sig = good.clone();
    sig[1] = b'Q';
    assert_eq!(decode(&sig, &LOOSE), Err(PngError::Signature));
    assert_eq!(decode(&good[..7], &LOOSE), Err(PngError::Signature));

    // A CRC error in a critical and in an ancillary chunk.
    let mut crc = good.clone();
    crc[8 + 8 + 3] ^= 1;
    assert_eq!(decode(&crc, &LOOSE), Err(PngError::Crc));
    let text = chunk(b"tEXt", b"Comment\0synthetic");
    let mut bad_text = text.clone();
    let n = bad_text.len();
    bad_text[n - 1] ^= 0x80;
    assert_eq!(
        decode(&file_with(&head, vec![bad_text, idat.clone()]), &LOOSE),
        Err(PngError::Crc)
    );

    // IHDR not first, twice, or of the wrong length.
    assert_eq!(
        decode(
            &png(&[
                text.clone(),
                head.clone(),
                idat.clone(),
                chunk(b"IEND", &[])
            ]),
            &LOOSE
        ),
        Err(PngError::FirstNotHeader)
    );
    assert_eq!(
        decode(&file_with(&head, vec![head.clone(), idat.clone()]), &LOOSE),
        Err(PngError::Order)
    );
    let mut long_head = head[8..8 + 13].to_vec();
    long_head.push(0);
    assert_eq!(
        decode(
            &file_with(&chunk(b"IHDR", &long_head), vec![idat.clone()]),
            &LOOSE
        ),
        Err(PngError::Header)
    );

    // Bad combinations of depth and colour type, and bad methods.
    for (depth, colour) in [(16, 3), (4, 2), (1, 6), (3, 0), (8, 5), (8, 1)] {
        assert_eq!(
            decode(
                &file_with(&ihdr(4, 4, depth, colour, false), vec![idat.clone()]),
                &LOOSE
            ),
            Err(PngError::Header),
            "depth {depth} colour {colour}"
        );
    }
    for at in [10usize, 11, 12] {
        let mut h = head[8..8 + 13].to_vec();
        h[at] = 2;
        assert_eq!(
            decode(&file_with(&chunk(b"IHDR", &h), vec![idat.clone()]), &LOOSE),
            Err(PngError::Header)
        );
    }

    // PLTE rules.
    let pal_raw = Raw::pattern(4, 4, 3, 2, false);
    let pal_head = ihdr(4, 4, 2, 3, false);
    let pal_idat = idat_of(&pal_raw);
    assert_eq!(
        decode(&file_with(&pal_head, vec![pal_idat.clone()]), &LOOSE),
        Err(PngError::Palette),
        "missing PLTE"
    );
    let grey_head = ihdr(4, 4, 8, 0, false);
    let grey_idat = idat_of(&Raw::pattern(4, 4, 0, 8, false));
    assert_eq!(
        decode(
            &file_with(
                &grey_head,
                vec![chunk(b"PLTE", &palette(4)), grey_idat.clone()]
            ),
            &LOOSE
        ),
        Err(PngError::Palette),
        "PLTE in grey"
    );
    for bad in [palette(5), vec![1, 2], vec![]] {
        assert_eq!(
            decode(
                &file_with(&pal_head, vec![chunk(b"PLTE", &bad), pal_idat.clone()]),
                &LOOSE
            ),
            Err(PngError::Palette)
        );
    }
    assert_eq!(
        decode(
            &file_with(
                &pal_head,
                vec![
                    chunk(b"PLTE", &palette(4)),
                    chunk(b"PLTE", &palette(4)),
                    pal_idat.clone()
                ]
            ),
            &LOOSE
        ),
        Err(PngError::Order)
    );
    assert_eq!(
        decode(
            &file_with(
                &pal_head,
                vec![pal_idat.clone(), chunk(b"PLTE", &palette(4))]
            ),
            &LOOSE
        ),
        Err(PngError::Order),
        "PLTE after IDAT"
    );
    // A palette index past the palette.
    assert_eq!(
        decode(
            &file_with(
                &pal_head,
                vec![chunk(b"PLTE", &palette(2)), pal_idat.clone()]
            ),
            &LOOSE
        ),
        Err(PngError::PaletteIndex)
    );

    // tRNS rules.
    let rgba_head = ihdr(4, 4, 8, 6, false);
    let rgba_idat = idat_of(&Raw::pattern(4, 4, 6, 8, false));
    assert_eq!(
        decode(
            &file_with(&rgba_head, vec![chunk(b"tRNS", &[0, 0]), rgba_idat.clone()]),
            &LOOSE
        ),
        Err(PngError::Transparency)
    );
    assert_eq!(
        decode(
            &file_with(&head, vec![chunk(b"tRNS", &[0, 0]), idat.clone()]),
            &LOOSE
        ),
        Err(PngError::Transparency),
        "RGB key of two bytes"
    );
    assert_eq!(
        decode(
            &file_with(
                &pal_head,
                vec![
                    chunk(b"PLTE", &palette(4)),
                    chunk(b"tRNS", &[1, 2, 3, 4, 5]),
                    pal_idat.clone()
                ]
            ),
            &LOOSE
        ),
        Err(PngError::Transparency),
        "more alphas than palette entries"
    );
    assert_eq!(
        decode(
            &file_with(
                &pal_head,
                vec![
                    chunk(b"tRNS", &[1]),
                    chunk(b"PLTE", &palette(4)),
                    pal_idat.clone()
                ]
            ),
            &LOOSE
        ),
        Err(PngError::Order),
        "tRNS before PLTE"
    );
    assert_eq!(
        decode(
            &file_with(&grey_head, vec![grey_idat.clone(), chunk(b"tRNS", &[0, 1])]),
            &LOOSE
        ),
        Err(PngError::Order),
        "tRNS after IDAT"
    );

    // IDAT rules.
    let half = raw.scanlines(&cycle);
    let z = zlib_compress(&half);
    let (z1, z2) = z.split_at(z.len() / 2);
    let split = file_with(&head, vec![chunk(b"IDAT", z1), chunk(b"IDAT", z2)]);
    assert!(decode(&split, &LOOSE).is_ok(), "split IDAT is valid");
    let gap = file_with(
        &head,
        vec![chunk(b"IDAT", z1), text.clone(), chunk(b"IDAT", z2)],
    );
    assert_eq!(decode(&gap, &LOOSE), Err(PngError::NotContiguous));
    assert_eq!(
        decode(&file_with(&head, vec![]), &LOOSE),
        Err(PngError::NoImageData)
    );

    // An unknown critical chunk, and a chunk type that is not letters.
    assert_eq!(
        decode(
            &file_with(&head, vec![chunk(b"ZZZZ", b""), idat.clone()]),
            &LOOSE
        ),
        Err(PngError::UnknownCritical)
    );
    assert_eq!(
        decode(
            &file_with(&head, vec![chunk(b"zz1z", b""), idat.clone()]),
            &LOOSE
        ),
        Err(PngError::ChunkType)
    );

    // IEND rules.
    let mut no_end = good.clone();
    no_end.truncate(good.len() - 12);
    assert_eq!(decode(&no_end, &LOOSE), Err(PngError::MissingEnd));
    let mut after = good.clone();
    after.push(0);
    assert_eq!(decode(&after, &LOOSE), Err(PngError::TrailingBytes));
    let bad_end = png(&[head.clone(), idat.clone(), chunk(b"IEND", b"x")]);
    assert_eq!(decode(&bad_end, &LOOSE), Err(PngError::BadEnd));

    // A truncated chunk and a chunk length over 2^31 - 1.
    assert_eq!(
        decode(&good[..good.len() - 20], &LOOSE),
        Err(PngError::Truncated)
    );
    let mut huge = good.clone();
    huge[33..37].copy_from_slice(&0x8000_0000u32.to_be_bytes());
    assert_eq!(decode(&huge, &LOOSE), Err(PngError::ChunkLength));

    // A filter type of 5.
    let mut rows = raw.scanlines(&|_, _| 0);
    rows[0] = 5;
    let five = file_with(&head, vec![chunk(b"IDAT", &zlib_compress(&rows))]);
    assert_eq!(decode(&five, &LOOSE), Err(PngError::FilterType));

    // Image data short by one byte, long by one byte, and not zlib.
    let mut short = raw.scanlines(&cycle);
    short.pop();
    let s = file_with(&head, vec![chunk(b"IDAT", &zlib_compress(&short))]);
    assert_eq!(decode(&s, &LOOSE), Err(PngError::DataSize));
    let mut long = raw.scanlines(&cycle);
    long.push(0);
    let l = file_with(&head, vec![chunk(b"IDAT", &zlib_compress(&long))]);
    assert_eq!(decode(&l, &LOOSE), Err(PngError::DataSize));
    let junk = file_with(&head, vec![chunk(b"IDAT", b"not zlib")]);
    assert!(matches!(decode(&junk, &LOOSE), Err(PngError::Inflate(_))));
}

/// R-WL-03, ADR-030 limits: 256 KiB of file and 16 to 2048 pixels a side.
#[test]
fn r_wl_03_logo_limits_are_enforced() {
    assert_eq!(Limits::LOGO.max_file_bytes, 262_144);
    assert_eq!((Limits::LOGO.min_side, Limits::LOGO.max_side), (16, 2048));
    let ok = encode(&rgba_pattern(16, 16, 1));
    assert!(decode(&ok, &Limits::LOGO).is_ok());
    for (w, h) in [(15, 16), (16, 15), (2049, 16), (16, 2049), (0, 16)] {
        let file = file_with(&ihdr(w, h, 8, 6, false), vec![chunk(b"IDAT", &[])]);
        assert_eq!(
            decode(&file, &Limits::LOGO),
            Err(PngError::Dimensions),
            "{w}x{h}"
        );
    }
    let mut big = ok.clone();
    let iend = big.split_off(big.len() - 12);
    big.extend(chunk(b"tEXt", &vec![b'a'; 262_144]));
    big.extend(iend);
    assert_eq!(decode(&big, &Limits::LOGO), Err(PngError::FileTooLarge));
}

/// TH-26: a bomb that declares 2048 x 2048 RGBA16 but whose data
/// inflates past that is refused at the cap, and so is a small header
/// over a large stream.
#[test]
fn th26_png_bomb_is_refused_at_the_exact_size() {
    let head = ihdr(16, 16, 8, 6, false);
    let zeros = vec![0u8; 2 * 1024 * 1024];
    let file = file_with(&head, vec![chunk(b"IDAT", &zlib_compress(&zeros))]);
    assert!(file.len() < 64 * 1024);
    assert_eq!(decode(&file, &Limits::LOGO), Err(PngError::DataSize));
    // The largest declared size is accepted when the data matches it.
    let rows = 2048 * (1 + 2048 * 8);
    let big = vec![0u8; rows];
    let file = file_with(
        &ihdr(2048, 2048, 16, 6, false),
        vec![chunk(b"IDAT", &zlib_compress(&big))],
    );
    assert!(file.len() < Limits::LOGO.max_file_bytes);
    let img = decode(&file, &Limits::LOGO).unwrap();
    assert_eq!(img.rgba().len(), 2048 * 2048 * 4);
}

/// I-68, R-WL-03: re-encoding keeps only the pixels. The output holds
/// `IHDR`, `IDAT` and `IEND` only, 8 bits, not interlaced; ancillary
/// chunks and their bytes are gone; the pixels are unchanged.
#[test]
fn i68_r_wl_03_reencode_keeps_only_the_pixels() {
    let raw = Raw::pattern(20, 18, 6, 16, true);
    let head = ihdr(20, 18, 16, 6, true);
    let secret = b"Comment\0<script>alert(1)</script> hidden payload";
    let file = file_with(
        &head,
        vec![
            chunk(b"tEXt", secret),
            chunk(b"gAMA", &45_455u32.to_be_bytes()),
            chunk(b"IDAT", &zlib_compress(&raw.scanlines(&cycle))),
            chunk(b"zTXt", b"k\0\0xx"),
        ],
    );
    let before = decode(&file, &LOOSE).unwrap();
    let out = reencode(&file, &LOOSE).unwrap();
    assert_eq!(chunk_types(&out), vec![*b"IHDR", *b"IDAT", *b"IEND"]);
    assert!(!out.windows(8).any(|w| w == b"<script>"));
    assert_eq!(out[24], 8, "bit depth");
    assert_eq!(out[25], 6, "RGBA with transparency");
    assert_eq!(out[28], 0, "not interlaced");
    assert_eq!(decode(&out, &LOOSE).unwrap(), before);
    // Idempotent: the canonical shape re-encodes to the same bytes.
    assert_eq!(reencode(&out, &LOOSE).unwrap(), out);
}

/// I-68: an opaque logo is written as RGB (colour type 2), a transparent
/// one as RGBA (colour type 6), whatever the input shape was.
#[test]
fn i68_canonical_colour_type_follows_the_pixels() {
    for (colour, depth) in FORMATS {
        let raw = Raw::pattern(16, 16, colour, depth, false);
        let plte = plte_for(&raw);
        let file = build(&raw, plte.as_deref(), None, &cycle, &zlib_compress);
        let img = decode(&file, &Limits::LOGO).unwrap();
        let out = reencode(&file, &Limits::LOGO).unwrap();
        let want = if img.is_opaque() { 2 } else { 6 };
        assert_eq!(out[25], want, "colour {colour} depth {depth}");
        assert_eq!(decode(&out, &Limits::LOGO).unwrap(), img);
    }
}

/// R-WL-03: a re-encoded logo over the file limit is refused with its
/// own error (ADR-031 open question 4).
#[test]
fn r_wl_03_reencoded_logo_over_the_limit_is_refused() {
    // Twenty rows of palette noise, repeated. In palette form the repeat
    // lies inside the 32 KiB window; in RGB form it is three times as far
    // and outside it, so only the RGB form stays large.
    let (w, h) = (1024usize, 512usize);
    let mut samples = Vec::with_capacity(w * h);
    for y in 0..h {
        for x in 0..w {
            let mut s = (x as u32) ^ ((y % 20) as u32) << 10;
            s = (s ^ (s >> 16)).wrapping_mul(0x7FEB_352D);
            s = (s ^ (s >> 15)).wrapping_mul(0x846C_A68B);
            s ^= s >> 16;
            samples.push(u16::from((s >> 24) as u8));
        }
    }
    let raw = Raw {
        width: w,
        height: h,
        colour: 3,
        depth: 8,
        interlace: false,
        samples,
    };
    let plte = palette(256);
    let file = build(&raw, Some(&plte), None, &|_, _| 0, &zlib_compress);
    assert!(file.len() <= Limits::LOGO.max_file_bytes, "{}", file.len());
    assert!(decode(&file, &Limits::LOGO).is_ok());
    assert_eq!(
        reencode(&file, &Limits::LOGO),
        Err(PngError::ReencodedTooLarge)
    );
}

fn image_from(g: &mut fstp_prop::Gen) -> Image {
    let w = g.u32_in(1..=40);
    let h = g.u32_in(1..=40);
    let opaque = g.bool();
    let flat = g.bool();
    let base = [g.u8(), g.u8(), g.u8(), g.u8()];
    let mut px = Vec::new();
    for i in 0..(w * h) as usize {
        let mut p = if flat && i % 5 != 0 {
            base
        } else {
            [g.u8(), g.u8(), g.u8(), g.u8()]
        };
        if opaque {
            p[3] = 255;
        }
        px.extend(p);
    }
    Image::new(w, h, px).unwrap()
}

/// I-68: encode then decode gives the same pixels, for any image.
#[test]
fn i68_encode_decode_round_trip() {
    check_with(
        "i68_encode_decode_round_trip",
        Config::default().with_cases(200),
        |g| {
            let img = image_from(g);
            let out = encode(&img);
            prop_assert_eq!(decode(&out, &LOOSE), Ok(img.clone()));
            prop_assert_eq!(encode(&img), out);
            Ok(())
        },
    );
}

/// TH-26: decoding never panics on mutated or truncated files of every
/// format, and every success re-encodes to the same pixels.
#[test]
fn th26_png_decode_never_panics_on_mutations() {
    check_with(
        "th26_png_decode_never_panics_on_mutations",
        Config::default().with_cases(400),
        |g| {
            let (colour, depth) = *g.pick(&FORMATS);
            let interlace = g.bool();
            let w = g.usize_in(1..=12);
            let h = g.usize_in(1..=12);
            let raw = Raw::pattern(w, h, colour, depth, interlace);
            let plte = plte_for(&raw);
            let mut file = build(&raw, plte.as_deref(), None, &cycle, &zlib_compress);
            let flips = g.vec(0..=3, |g| (g.usize(), g.u8_in(1..=255)));
            for (at, x) in flips {
                let n = file.len();
                file[at % n] ^= x;
            }
            if g.bool() {
                let cut = g.usize_in(0..=file.len());
                file.truncate(cut);
            }
            if let Ok(img) = decode(&file, &LOOSE) {
                prop_assert!(img.rgba().len() == img.width() as usize * img.height() as usize * 4);
                let again = encode(&img);
                prop_assert_eq!(decode(&again, &LOOSE), Ok(img));
            }
            Ok(())
        },
    );
}
