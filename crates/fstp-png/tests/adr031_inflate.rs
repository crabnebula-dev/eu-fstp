//! Inflate, deflate and the checksums of `fstp-png` (ADR-031, TH-26).
//!
//! The decoder is an untrusted-input parser (TH-26): every refusal row of
//! ADR-031 "Inflate" has a hand-built stream here. Reference streams come
//! from RFC 1951 by hand and from one dynamic-block stream written once
//! by the system `gzip -9 -n` over synthetic text.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

mod common;

use common::{adler, stored_zlib};
use fstp_png::{
    Blocks, InflateError, adler32, crc32, deflate, deflate_with, inflate, zlib_compress,
    zlib_compress_with, zlib_decompress,
};
use fstp_prop::{Config, Gen, check_with, prop_assert_eq};

fn hex(lines: &[&str]) -> Vec<u8> {
    let s: String = lines.concat();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The synthetic text of the `gzip -9 -n` reference stream.
fn gzip_text() -> Vec<u8> {
    let mut t = String::new();
    for i in 1u64..=40 {
        t.push_str(&format!(
            "Row {i} of the synthetic fixture: {} apples, {} pears; zzzz qqqq xxxx {}.\n",
            i * i,
            i * 7 % 13,
            i * i * i
        ));
    }
    t.into_bytes()
}

/// The raw DEFLATE data of `gzip -9 -n` over [`gzip_text`]: one dynamic
/// block. The gzip trailer gave CRC-32 0x57B90328 and size 3001.
const GZIP_DYNAMIC: [&str; 18] = [
    "8d964b6e1b311044f739050f1004ec0f9b647c0bdfc00864c440102b960c",
    "db397d884c6b869b2e7a365a0878e0b05f55cffdf35ba2f4fc98ae3f4fe9",
    "f2f17bfc5c9f7ea4c7a7f7ebebcbe9fbf8efe17cfe75ba7c4d359d4f0f2f",
    "97bbf4773ce9cf78d2fb78127dfb723f200c20ba432880b40d2200d27748",
    "0b205c378aa2f7b11dc301c674c31480e1b2637a742f5c368e018e1cc791",
    "e8adc8364e45377cdc0ee500242a1ba801901db3d2805388374e079c7688",
    "43d1d02bf70d348e0c2696f38e2ad15de79c1d0565e6e954d1f849c49526",
    "e434e9715316a12abbd824d0c9637a39b4a0bbdd04f5eeb60c2c5775c309",
    "2a3e391e4d50a4bae464302db60cafe6ee9e13129d5b5f06583bb9e98454",
    "17d665884b13979d3a8c312d736cadb8ee8c74d749f730ca6df79d91efaa",
    "b44c7367bb3538acf0a6eb40533675e119095fb8af233d7acf8d67647ca9",
    "f6994c3776e719396f93f361a88bdd9a9d91f4361d2c8705318eef2c647d",
    "9d2e2cdcc3dd9a6bcf48fbdad6eb78b44d71ef19b6fc2458b895559a8b2f",
    "48fc3e89cf6175ede20b12bf4f798ca2cdbd76375f60d1e7a927a2700b57",
    "bb7dc3c0aacfed339bba7471f705b63d4dc51a055cba64775f0a5c8e73e1",
    "476628b75be58b41dab489a28cab5971fd05e94f326dc830e4255bf10048",
    "c39b7bbdba8bb6ea091094002ad3374534cf314ef20828fcd4b1290335fc",
    "3cfd9f817f",
];

/// A zlib stream around raw DEFLATE data, with its Adler-32.
fn wrap(raw: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut z = vec![0x78, 0x9C];
    z.extend(raw);
    z.extend(adler(plain).to_be_bytes());
    z
}

/// Bits written least significant first, as RFC 1951 packs them.
struct Bits {
    out: Vec<u8>,
    n: u32,
}

impl Bits {
    fn new() -> Bits {
        Bits {
            out: Vec::new(),
            n: 0,
        }
    }
    fn put(&mut self, v: u32, len: u32) {
        for i in 0..len {
            if self.n.is_multiple_of(8) {
                self.out.push(0);
            }
            let bit = ((v >> i) & 1) as u8;
            *self.out.last_mut().unwrap() |= bit << (self.n % 8);
            self.n += 1;
        }
    }
    /// A Huffman code, most significant bit first.
    fn code(&mut self, code: u32, len: u32) {
        for i in (0..len).rev() {
            self.put((code >> i) & 1, 1);
        }
    }
}

/// TH-26: the checksums match their published check values.
#[test]
fn th26_crc32_and_adler32_check_values() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(b""), 0);
    assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    assert_eq!(adler32(b""), 1);
    let big: Vec<u8> = (0..100_000u32).map(|i| (i * 7 + i / 13) as u8).collect();
    assert_eq!(adler32(&big), adler(&big));
    assert_eq!(crc32(&gzip_text()), 0x57B9_0328);
}

/// TH-26: stored, fixed and dynamic blocks of known streams.
#[test]
fn th26_inflate_reads_stored_fixed_and_dynamic_blocks() {
    // zlib of the empty string, as RFC 1950 tools write it.
    assert_eq!(
        zlib_decompress(&[0x78, 0x9C, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01], 16).unwrap(),
        b""
    );
    // One fixed block holding the literal "a".
    assert_eq!(inflate(&[0x4B, 0x04, 0x00], 16).unwrap(), b"a");
    // A stored block holding "hello".
    assert_eq!(
        inflate(
            &[0x01, 0x05, 0x00, 0xFA, 0xFF, b'h', b'e', b'l', b'l', b'o'],
            16
        )
        .unwrap(),
        b"hello"
    );
    // A stored block written by the tests, through zlib.
    let data: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(zlib_decompress(&stored_zlib(&data), 70_000).unwrap(), data);
    // gzip's dynamic block.
    let raw = hex(&GZIP_DYNAMIC);
    assert_eq!(raw[0] & 0b111, 0b101, "final dynamic block");
    assert_eq!(inflate(&raw, 3001).unwrap(), gzip_text());
    assert_eq!(
        zlib_decompress(&wrap(&raw, &gzip_text()), 3001).unwrap(),
        gzip_text()
    );
}

/// TH-26: a fixed-block match that copies over itself (distance 1).
#[test]
fn th26_inflate_overlapping_copy() {
    let mut b = Bits::new();
    b.put(1, 1);
    b.put(1, 2);
    b.code(0x30 + u32::from(b'x'), 8); // literal 'x'
    b.code(0b000_0001 + 9, 7); // length symbol 266: 13..14, one extra bit
    b.put(1, 1); // length 14
    b.code(0, 5); // distance symbol 0: distance 1
    b.code(0, 7); // end of block
    assert_eq!(inflate(&b.out, 64).unwrap(), vec![b'x'; 15]);
    assert_eq!(inflate(&b.out, 14), Err(InflateError::OutputLimit));
}

fn fixed_with(symbol_bits: impl Fn(&mut Bits)) -> Vec<u8> {
    let mut b = Bits::new();
    b.put(1, 1);
    b.put(1, 2);
    symbol_bits(&mut b);
    b.out
}

/// TH-26: each malformed stream of ADR-031 "Inflate" is refused.
#[test]
fn th26_inflate_refuses_malformed_streams() {
    // Block type 3.
    assert_eq!(inflate(&[0b111], 16), Err(InflateError::BlockType));
    // A stored length whose complement does not match.
    assert_eq!(
        inflate(&[0x01, 0x05, 0x00, 0xFA, 0xFE, 1, 2, 3, 4, 5], 16),
        Err(InflateError::StoredLength)
    );
    // Truncated: stored data shorter than its length, and no final block.
    assert_eq!(
        inflate(&[0x01, 0x05, 0x00, 0xFA, 0xFF, 1, 2], 16),
        Err(InflateError::Truncated)
    );
    assert_eq!(
        inflate(&[0x00, 0x00, 0x00, 0xFF, 0xFF], 16),
        Err(InflateError::Truncated)
    );
    assert_eq!(inflate(&[], 16), Err(InflateError::Truncated));
    // Literal/length symbol 286 (fixed code 11000110).
    let s286 = fixed_with(|b| b.code(0b1100_0110, 8));
    assert_eq!(inflate(&s286, 16), Err(InflateError::BadSymbol));
    // Distance symbol 30.
    let d30 = fixed_with(|b| {
        b.code(0x30 + u32::from(b'x'), 8);
        b.code(1, 7); // length 3
        b.code(30, 5);
    });
    assert_eq!(inflate(&d30, 16), Err(InflateError::BadSymbol));
    // A distance before the start of the output.
    let far = fixed_with(|b| {
        b.code(0x30 + u32::from(b'x'), 8);
        b.code(1, 7); // length 3
        b.code(1, 5); // distance 2
        b.code(0, 7);
    });
    assert_eq!(inflate(&far, 16), Err(InflateError::Distance));
    // Trailing bytes after the final block.
    assert_eq!(
        inflate(&[0x4B, 0x04, 0x00, 0x00], 16),
        Err(InflateError::TrailingData)
    );
}

/// A dynamic block header with the given code length code lengths and
/// code lengths, written with the tests' own canonical coder.
fn dynamic(
    hlit: u32,
    hdist: u32,
    cl: &[u32; 19],
    seq: &[(u32, u32, u32)],
    tail: &[(u32, u32)],
) -> Vec<u8> {
    const ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let mut b = Bits::new();
    b.put(1, 1);
    b.put(2, 2);
    b.put(hlit - 257, 5);
    b.put(hdist - 1, 5);
    b.put(15, 4);
    for &i in &ORDER {
        b.put(cl[i], 3);
    }
    // Canonical codes of `cl`.
    let mut codes = [0u32; 19];
    let mut code = 0u32;
    for len in 1..=7 {
        for s in 0..19 {
            if cl[s] == len {
                codes[s] = code;
                code += 1;
            }
        }
        code <<= 1;
    }
    for &(sym, extra, extra_bits) in seq {
        b.code(codes[sym as usize], cl[sym as usize]);
        b.put(extra, extra_bits);
    }
    for &(code, len) in tail {
        b.code(code, len);
    }
    b.out
}

/// TH-26: bad dynamic code descriptions are refused.
#[test]
fn th26_inflate_refuses_bad_dynamic_codes() {
    // Code length codes 0, 1, 2, 3, 8, 16, 17 and 18 at length 3: complete.
    let mut cl = [0u32; 19];
    for s in [0, 1, 2, 3, 8, 16, 17, 18] {
        cl[s] = 3;
    }
    // Each sequence below gives exactly 258 lengths (HLIT 257, HDIST 1),
    // so only the named defect is wrong.
    // A repeat with no previous length.
    let first_repeat = dynamic(257, 1, &cl, &[(16, 0, 2)], &[]);
    assert_eq!(inflate(&first_repeat, 16), Err(InflateError::BadCode));
    // A repeat past the end of the lengths.
    let past = dynamic(257, 1, &cl, &[(18, 127, 7), (18, 127, 7)], &[]);
    assert_eq!(inflate(&past, 16), Err(InflateError::BadCode));
    // Over-subscribed: three codes of length 1 (0, 1 and 256).
    let over = dynamic(
        257,
        1,
        &cl,
        &[
            (1, 0, 0),
            (1, 0, 0),
            (18, 127, 7),
            (18, 105, 7),
            (1, 0, 0),
            (0, 0, 0),
        ],
        &[],
    );
    assert_eq!(inflate(&over, 16), Err(InflateError::BadCode));
    // Incomplete: two codes of length 2 (0 and 256).
    let incomplete = dynamic(
        257,
        1,
        &cl,
        &[(2, 0, 0), (18, 127, 7), (18, 106, 7), (2, 0, 0), (0, 0, 0)],
        &[],
    );
    assert_eq!(inflate(&incomplete, 16), Err(InflateError::BadCode));
    // No length for end of block (symbol 256): literals 0 and 1 only.
    let no_end = dynamic(
        257,
        1,
        &cl,
        &[(1, 0, 0), (1, 0, 0), (18, 127, 7), (18, 106, 7), (0, 0, 0)],
        &[],
    );
    assert_eq!(inflate(&no_end, 16), Err(InflateError::BadCode));
    // An over-subscribed distance code: three distance codes of length 1.
    let dist_over = dynamic(
        257,
        3,
        &cl,
        &[
            (1, 0, 0),
            (18, 127, 7),
            (18, 106, 7),
            (1, 0, 0),
            (1, 0, 0),
            (1, 0, 0),
            (1, 0, 0),
        ],
        &[],
    );
    assert_eq!(inflate(&dist_over, 16), Err(InflateError::BadCode));
    // HLIT of 287 and HDIST of 31.
    let mut big = Bits::new();
    big.put(1, 1);
    big.put(2, 2);
    big.put(30, 5);
    big.put(0, 5);
    big.put(0, 4);
    assert_eq!(inflate(&big.out, 16), Err(InflateError::BadCode));
    let mut big = Bits::new();
    big.put(1, 1);
    big.put(2, 2);
    big.put(0, 5);
    big.put(30, 5);
    big.put(0, 4);
    assert_eq!(inflate(&big.out, 16), Err(InflateError::BadCode));
    // An incomplete code length code: one code of length 2.
    let mut lone = [0u32; 19];
    lone[8] = 2;
    let bad_cl = dynamic(257, 1, &lone, &[], &[]);
    assert_eq!(inflate(&bad_cl, 16), Err(InflateError::BadCode));
}

/// TH-26: one literal code of length 1 is an allowed incomplete code,
/// as zlib allows; and a distance code with no codes at all is allowed
/// while no distance is used.
#[test]
fn th26_inflate_allows_single_one_bit_codes() {
    let mut cl = [0u32; 19];
    for s in [0, 1, 2, 18] {
        cl[s] = 2;
    }
    // Literals 0..=255 unused, 256 has length 1; one distance, unused.
    let seq = [(18, 127, 7), (18, 107, 7), (1, 0, 0), (0, 0, 0)];
    // End of block is code 0 of length 1.
    let raw = dynamic(257, 1, &cl, &seq, &[(0, 1)]);
    assert_eq!(inflate(&raw, 16).unwrap(), b"");
    // A second end of block code would be a literal of a code that does
    // not exist: bit 1 is unused.
    let raw = dynamic(257, 1, &cl, &seq, &[(1, 1)]);
    assert!(inflate(&raw, 16).is_err());
}

/// A zlib FLG byte with the bits `top` and a valid check for `cmf`.
fn flg(cmf: u8, top: u8) -> u8 {
    let base = (u32::from(cmf) << 8) | u32::from(top);
    top + ((31 - base % 31) % 31) as u8
}

/// TH-26: the zlib wrapper is checked.
#[test]
fn th26_zlib_refuses_bad_wrappers() {
    let good = zlib_compress(b"logo pixels");
    assert_eq!(zlib_decompress(&good, 64).unwrap(), b"logo pixels");
    // Compression method other than 8.
    let mut m = good.clone();
    m[0] = 0x77;
    m[1] = flg(0x77, 0);
    assert_eq!(zlib_decompress(&m, 64), Err(InflateError::Header));
    // Header check not a multiple of 31.
    let mut c = good.clone();
    c[1] ^= 1;
    assert_eq!(zlib_decompress(&c, 64), Err(InflateError::Header));
    // Window over 32 KiB (CINFO 8).
    let mut w = good.clone();
    w[0] = 0x88;
    w[1] = flg(0x88, 0);
    assert_eq!(zlib_decompress(&w, 64), Err(InflateError::Header));
    // A preset dictionary.
    let mut d = vec![0x78, flg(0x78, 0x20)];
    d.extend(&good[2..]);
    assert_eq!(zlib_decompress(&d, 64), Err(InflateError::Dictionary));
    // A bad Adler-32.
    let mut a = good.clone();
    *a.last_mut().unwrap() ^= 1;
    assert_eq!(zlib_decompress(&a, 64), Err(InflateError::Checksum));
    // Missing Adler-32, and a byte after it.
    assert_eq!(
        zlib_decompress(&good[..good.len() - 1], 64),
        Err(InflateError::Truncated)
    );
    let mut t = good.clone();
    t.push(0);
    assert_eq!(zlib_decompress(&t, 64), Err(InflateError::TrailingData));
    // A distance beyond the declared window: CINFO 0 is a 256-byte window.
    let data: Vec<u8> = (0..300u32).map(|i| (i % 300 / 2) as u8).collect();
    let mut repeat = data.clone();
    repeat.extend(&data);
    let raw = deflate_with(&repeat, Blocks::Fixed);
    let mut small = vec![0x08, 0x00];
    small[1] = flg(0x08, 0);
    small.extend(&raw);
    small.extend(adler(&repeat).to_be_bytes());
    assert_eq!(zlib_decompress(&small, 1000), Err(InflateError::Distance));
}

/// TH-26: a decompression bomb stops at the cap.
#[test]
fn th26_inflate_bomb_stops_at_cap() {
    let zeros = vec![0u8; 4 * 1024 * 1024];
    let z = zlib_compress(&zeros);
    assert!(z.len() < 16 * 1024, "{} bytes", z.len());
    assert_eq!(zlib_decompress(&z, 65_536), Err(InflateError::OutputLimit));
    assert_eq!(zlib_decompress(&z, zeros.len()).unwrap().len(), zeros.len());
    // Many empty stored blocks consume input and give nothing.
    let mut empty = Vec::new();
    for _ in 0..10_000 {
        empty.extend([0x00, 0x00, 0x00, 0xFF, 0xFF]);
    }
    empty.extend([0x01, 0x00, 0x00, 0xFF, 0xFF]);
    assert_eq!(inflate(&empty, 0).unwrap(), b"");
}

fn sample_data(g: &mut Gen) -> Vec<u8> {
    match g.u8_in(0..=3) {
        0 => g.bytes(0..=2000),
        1 => {
            // Runs, as flat logos give.
            let runs = g.vec(0..=40, |g| (g.u8(), g.usize_in(1..=600)));
            runs.into_iter()
                .flat_map(|(b, n)| std::iter::repeat_n(b, n))
                .collect()
        }
        2 => {
            // A short alphabet with repeats at many distances.
            let alphabet = g.bytes(1..=4);
            let n = g.usize_in(0..=5000);
            (0..n)
                .map(|i| alphabet[(i * 7 + i / 11) % alphabet.len()])
                .collect()
        }
        _ => {
            let unit = g.bytes(1..=40);
            let n = g.usize_in(0..=70_000 / unit.len());
            unit.iter().copied().cycle().take(unit.len() * n).collect()
        }
    }
}

/// TH-26, I-68: every block choice of the encoder inflates to its input.
#[test]
fn th26_deflate_then_inflate_is_identity() {
    check_with(
        "th26_deflate_then_inflate_is_identity",
        Config::default().with_cases(160),
        |g| {
            let data = sample_data(g);
            for blocks in [Blocks::Stored, Blocks::Fixed, Blocks::Dynamic, Blocks::Best] {
                let raw = deflate_with(&data, blocks);
                prop_assert_eq!(inflate(&raw, data.len()), Ok(data.clone()));
                let z = zlib_compress_with(&data, blocks);
                prop_assert_eq!(zlib_decompress(&z, data.len()), Ok(data.clone()));
            }
            Ok(())
        },
    );
}

/// TH-26: the encoder is deterministic and `Best` is never larger than
/// stored blocks.
#[test]
fn th26_deflate_is_deterministic_and_bounded() {
    let text = gzip_text();
    assert_eq!(deflate(&text), deflate(&text));
    assert!(deflate(&text).len() <= deflate_with(&text, Blocks::Stored).len());
    assert!(deflate(&text).len() < 700, "{} bytes", deflate(&text).len());
    let noise: Vec<u8> = (0..100_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    assert!(deflate(&noise).len() <= noise.len() + 5 * (noise.len() / 65_535 + 1) + 8);
    // The dynamic encoder reaches the right block type.
    assert_eq!(deflate_with(&text, Blocks::Dynamic)[0] & 0b111, 0b101);
    assert_eq!(deflate_with(&text, Blocks::Fixed)[0] & 0b111, 0b011);
    assert_eq!(deflate_with(&text, Blocks::Stored)[0] & 0b111, 0b001);
}

/// TH-26: inflate never panics, on random bytes and on mutations of
/// valid streams, and never returns more than its cap.
#[test]
fn th26_inflate_never_panics_on_any_input() {
    check_with(
        "th26_inflate_never_panics_on_any_input",
        Config::default().with_cases(600),
        |g| {
            let data = sample_data(g);
            let mut z = if g.bool() {
                zlib_compress(&data)
            } else {
                zlib_compress_with(&data, Blocks::Dynamic)
            };
            let flips = g.vec(0..=4, |g| (g.usize(), g.u8_in(1..=255)));
            for (at, x) in flips {
                if !z.is_empty() {
                    let n = z.len();
                    z[at % n] ^= x;
                }
            }
            if g.bool() {
                let cut = g.usize_in(0..=z.len());
                z.truncate(cut);
            }
            let cap = g.usize_in(0..=data.len() + 10);
            if let Ok(out) = zlib_decompress(&z, cap) {
                fstp_prop::prop_assert!(out.len() <= cap);
            }
            let raw = g.bytes(0..=300);
            if let Ok(out) = inflate(&raw, cap) {
                fstp_prop::prop_assert!(out.len() <= cap);
            }
            Ok(())
        },
    );
}
