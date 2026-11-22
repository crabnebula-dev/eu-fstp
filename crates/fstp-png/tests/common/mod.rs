//! Shared helpers of the `fstp-png` tests (ADR-031).
//!
//! A reference PNG writer of the tests' own: it packs samples of any
//! colour type and bit depth, applies a chosen filter to each row, lays
//! out Adam7 passes and wraps the result in chunks. Its zlib stream uses
//! stored blocks with an Adler-32 of the tests' own, so the decoder is
//! checked against code it does not share. No image file is downloaded.

#![allow(dead_code, reason = "each test file uses a part")]
#![allow(
    unreachable_pub,
    reason = "a test module shared by several test crates"
)]
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers"
)]

use fstp_png::{Limits, crc32};

/// The PNG signature.
pub const SIGNATURE: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];

/// Limits for tests of shapes below the logo minimum.
pub const LOOSE: Limits = Limits {
    max_file_bytes: 4 * 1024 * 1024,
    min_side: 1,
    max_side: 2048,
};

/// Adam7: x start, y start, x step, y step.
pub const ADAM7: [(usize, usize, usize, usize); 7] = [
    (0, 0, 8, 8),
    (4, 0, 8, 8),
    (0, 4, 4, 8),
    (2, 0, 4, 4),
    (0, 2, 2, 4),
    (1, 0, 2, 2),
    (0, 1, 1, 2),
];

/// Every valid colour type and bit depth of PNG 1.2.
pub const FORMATS: [(u8, u8); 15] = [
    (0, 1),
    (0, 2),
    (0, 4),
    (0, 8),
    (0, 16),
    (2, 8),
    (2, 16),
    (3, 1),
    (3, 2),
    (3, 4),
    (3, 8),
    (4, 8),
    (4, 16),
    (6, 8),
    (6, 16),
];

/// The samples per pixel of a colour type.
pub fn channels(colour: u8) -> usize {
    match colour {
        0 | 3 => 1,
        2 => 3,
        4 => 2,
        6 => 4,
        _ => panic!("colour type {colour}"),
    }
}

/// An image as raw samples, row-major, `channels(colour)` per pixel.
#[derive(Clone, Debug)]
pub struct Raw {
    pub width: usize,
    pub height: usize,
    pub colour: u8,
    pub depth: u8,
    pub interlace: bool,
    pub samples: Vec<u16>,
}

impl Raw {
    /// A deterministic pattern that uses the whole sample range.
    pub fn pattern(width: usize, height: usize, colour: u8, depth: u8, interlace: bool) -> Raw {
        let c = channels(colour);
        let max: u32 = if colour == 3 {
            (1u32 << depth).min(256) - 1
        } else {
            (1u32 << depth) - 1
        };
        let mut samples = Vec::with_capacity(width * height * c);
        let mut s: u32 = 0x1234_5678;
        for y in 0..height {
            for x in 0..width {
                for k in 0..c {
                    s = s.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    let v = if (x + y) % 3 == 0 {
                        ((x * 7 + y * 13 + k * 31) as u32) % (max + 1)
                    } else {
                        (s >> 8) % (max + 1)
                    };
                    samples.push(v as u16);
                }
            }
        }
        Raw {
            width,
            height,
            colour,
            depth,
            interlace,
            samples,
        }
    }

    fn sample(&self, x: usize, y: usize, k: usize) -> u16 {
        self.samples[(y * self.width + x) * channels(self.colour) + k]
    }

    /// The bits per pixel.
    pub fn bits_per_pixel(&self) -> usize {
        channels(self.colour) * usize::from(self.depth)
    }

    /// The passes as (x start, y start, x step, y step).
    pub fn passes(&self) -> Vec<(usize, usize, usize, usize)> {
        if self.interlace {
            ADAM7.to_vec()
        } else {
            vec![(0, 0, 1, 1)]
        }
    }

    /// The filtered scanlines. `filter(pass, row)` picks each row's filter.
    pub fn scanlines(&self, filter: &dyn Fn(usize, usize) -> u8) -> Vec<u8> {
        let mut out = Vec::new();
        let bpp = self.bits_per_pixel().div_ceil(8).max(1);
        for (p, (xs, ys, dx, dy)) in self.passes().into_iter().enumerate() {
            let pw = if self.width > xs {
                (self.width - xs).div_ceil(dx)
            } else {
                0
            };
            let ph = if self.height > ys {
                (self.height - ys).div_ceil(dy)
            } else {
                0
            };
            if pw == 0 || ph == 0 {
                continue;
            }
            let row_bytes = (pw * self.bits_per_pixel()).div_ceil(8);
            let mut prev = vec![0u8; row_bytes];
            for r in 0..ph {
                let mut row = vec![0u8; row_bytes];
                let mut bit = 0usize;
                for i in 0..pw {
                    let (x, y) = (xs + i * dx, ys + r * dy);
                    for k in 0..channels(self.colour) {
                        let v = self.sample(x, y, k);
                        match self.depth {
                            16 => {
                                row[bit / 8] = (v >> 8) as u8;
                                row[bit / 8 + 1] = v as u8;
                            }
                            8 => row[bit / 8] = v as u8,
                            d => {
                                let shift = 8 - usize::from(d) - bit % 8;
                                row[bit / 8] |= (v as u8) << shift;
                            }
                        }
                        bit += usize::from(self.depth);
                    }
                }
                let ft = filter(p, r);
                out.push(ft);
                out.extend(apply_filter(ft, &row, &prev, bpp));
                prev = row;
            }
        }
        out
    }
}

/// The Paeth predictor of the PNG specification.
pub fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let p = i16::from(a) + i16::from(b) - i16::from(c);
    let (pa, pb, pc) = (
        (p - i16::from(a)).abs(),
        (p - i16::from(b)).abs(),
        (p - i16::from(c)).abs(),
    );
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

/// Filters one row with filter type `ft`.
pub fn apply_filter(ft: u8, row: &[u8], prev: &[u8], bpp: usize) -> Vec<u8> {
    (0..row.len())
        .map(|i| {
            let a = if i >= bpp { row[i - bpp] } else { 0 };
            let b = prev[i];
            let c = if i >= bpp { prev[i - bpp] } else { 0 };
            let pred = match ft {
                0 => 0,
                1 => a,
                2 => b,
                3 => ((u16::from(a) + u16::from(b)) / 2) as u8,
                4 => paeth(a, b, c),
                _ => 0,
            };
            row[i].wrapping_sub(pred)
        })
        .collect()
}

/// The 8-bit value of a sample, as ADR-031 row "Samples" defines it.
pub fn scale(v: u16, depth: u8) -> u8 {
    match depth {
        16 => ((u32::from(v) * 255 + 32_895) / 65_535) as u8,
        8 => v as u8,
        4 => (v * 17) as u8,
        2 => (v * 85) as u8,
        1 => (v * 255) as u8,
        _ => panic!("depth {depth}"),
    }
}

/// The RGBA pixels a decoder must give for `raw` with this `PLTE` and
/// `tRNS` content.
pub fn expected_rgba(raw: &Raw, palette: &[u8], trns: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    let key16 = |t: &[u8], i: usize| u16::from_be_bytes([t[2 * i], t[2 * i + 1]]);
    for y in 0..raw.height {
        for x in 0..raw.width {
            let s = |k| raw.sample(x, y, k);
            let d = raw.depth;
            let px = match raw.colour {
                0 => {
                    let g = scale(s(0), d);
                    let a = match trns {
                        Some(t) if key16(t, 0) == s(0) => 0,
                        _ => 255,
                    };
                    [g, g, g, a]
                }
                2 => {
                    let a = match trns {
                        Some(t) if (0..3).all(|k| key16(t, k) == s(k)) => 0,
                        _ => 255,
                    };
                    [scale(s(0), d), scale(s(1), d), scale(s(2), d), a]
                }
                3 => {
                    let i = usize::from(s(0));
                    let a = trns.and_then(|t| t.get(i).copied()).unwrap_or(255);
                    [palette[3 * i], palette[3 * i + 1], palette[3 * i + 2], a]
                }
                4 => {
                    let g = scale(s(0), d);
                    [g, g, g, scale(s(1), d)]
                }
                6 => [
                    scale(s(0), d),
                    scale(s(1), d),
                    scale(s(2), d),
                    scale(s(3), d),
                ],
                _ => panic!("colour"),
            };
            out.extend(px);
        }
    }
    out
}

/// A palette of `n` entries.
pub fn palette(n: usize) -> Vec<u8> {
    (0..n)
        .flat_map(|i| [(i * 37) as u8, (255 - i) as u8, (i * 11 + 5) as u8])
        .collect()
}

/// The tests' own Adler-32 (RFC 1950 section 9).
pub fn adler(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + u32::from(x)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

/// A zlib stream of stored blocks, written by the tests.
pub fn stored_zlib(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01];
    let mut chunks: Vec<&[u8]> = data.chunks(65_535).collect();
    if chunks.is_empty() {
        chunks.push(&[]);
    }
    let last = chunks.len() - 1;
    for (i, c) in chunks.iter().enumerate() {
        out.push(u8::from(i == last));
        let len = c.len() as u16;
        out.extend(len.to_le_bytes());
        out.extend((!len).to_le_bytes());
        out.extend(*c);
    }
    out.extend(adler(data).to_be_bytes());
    out
}

/// One chunk with its CRC.
pub fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut out = (data.len() as u32).to_be_bytes().to_vec();
    out.extend(kind);
    out.extend(data);
    let mut crc_input = kind.to_vec();
    crc_input.extend(data);
    out.extend(crc32(&crc_input).to_be_bytes());
    out
}

/// An `IHDR` chunk.
pub fn ihdr(width: u32, height: u32, depth: u8, colour: u8, interlace: bool) -> Vec<u8> {
    let mut d = width.to_be_bytes().to_vec();
    d.extend(height.to_be_bytes());
    d.extend([depth, colour, 0, 0, u8::from(interlace)]);
    chunk(b"IHDR", &d)
}

/// A PNG file from its chunks.
pub fn png(chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut out = SIGNATURE.to_vec();
    for c in chunks {
        out.extend(c);
    }
    out
}

/// A whole PNG of `raw` with optional `PLTE` and `tRNS`, rows filtered by
/// `filter`, compressed with `zlib`.
pub fn build(
    raw: &Raw,
    plte: Option<&[u8]>,
    trns: Option<&[u8]>,
    filter: &dyn Fn(usize, usize) -> u8,
    zlib: &dyn Fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let mut chunks = vec![ihdr(
        raw.width as u32,
        raw.height as u32,
        raw.depth,
        raw.colour,
        raw.interlace,
    )];
    if let Some(p) = plte {
        chunks.push(chunk(b"PLTE", p));
    }
    if let Some(t) = trns {
        chunks.push(chunk(b"tRNS", t));
    }
    chunks.push(chunk(b"IDAT", &zlib(&raw.scanlines(filter))));
    chunks.push(chunk(b"IEND", &[]));
    png(&chunks)
}

/// The filter of each row cycles through all five.
pub fn cycle(pass: usize, row: usize) -> u8 {
    ((pass + row) % 5) as u8
}

/// The chunk types of a PNG file, in order.
pub fn chunk_types(bytes: &[u8]) -> Vec<[u8; 4]> {
    let mut out = Vec::new();
    let mut pos = 8;
    while pos + 12 <= bytes.len() {
        let len = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        out.push(bytes[pos + 4..pos + 8].try_into().unwrap());
        pos += 12 + len;
    }
    out
}

/// A deterministic RGBA image with transparent, half and opaque pixels.
pub fn rgba_pattern(width: u32, height: u32, seed: u32) -> fstp_png::Image {
    let mut s = seed;
    let mut px = Vec::new();
    for y in 0..height {
        for x in 0..width {
            s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let flat = (x / 4 + y / 4) % 2 == 0;
            let v = if flat {
                [200, 30, 60]
            } else {
                s.to_be_bytes()[..3].try_into().unwrap()
            };
            let a = match (x + y) % 7 {
                0 => 0,
                1 => 128,
                _ => 255,
            };
            px.extend(v);
            px.push(a);
        }
    }
    fstp_png::Image::new(width, height, px).expect("pattern size")
}
