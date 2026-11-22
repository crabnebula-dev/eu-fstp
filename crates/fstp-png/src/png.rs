//! The PNG decoder (ADR-031 rows "PNG decode", "PNG rules", "PNG limits"
//! and "Samples").

use std::fmt;

use crate::check::Crc;
use crate::image::Image;
use crate::inflate::{InflateError, zlib_with};

/// The PNG signature.
pub(crate) const SIGNATURE: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];

/// The most decompressed bytes any accepted header implies: 2048 rows of
/// one filter byte and 2048 pixels of 8 bytes.
pub const MAX_RAW_BYTES: usize = 2048 * (1 + 2048 * 8);

/// The limits a decode runs under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Limits {
    /// The longest file, in bytes.
    pub max_file_bytes: usize,
    /// The shortest side, in pixels.
    pub min_side: u32,
    /// The longest side, in pixels.
    pub max_side: u32,
}

impl Limits {
    /// The logo limits of ADR-030: 256 KiB, 16 to 2048 pixels a side.
    pub const LOGO: Limits = Limits {
        max_file_bytes: 256 * 1024,
        min_side: 16,
        max_side: 2048,
    };
}

/// Why a PNG file was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PngError {
    /// The file is longer than the limit.
    FileTooLarge,
    /// The file does not start with the PNG signature.
    Signature,
    /// A chunk runs past the end of the file.
    Truncated,
    /// A chunk length over 2^31 - 1.
    ChunkLength,
    /// A chunk type that is not four ASCII letters.
    ChunkType,
    /// A chunk whose CRC-32 does not match.
    Crc,
    /// The first chunk is not `IHDR`.
    FirstNotHeader,
    /// An `IHDR` of the wrong length, with a bad combination of bit depth
    /// and colour type, or a method other than 0 (interlace 0 or 1).
    Header,
    /// A side of 0, or outside the limits.
    Dimensions,
    /// A chunk out of order or repeated.
    Order,
    /// A missing, forbidden or malformed `PLTE`.
    Palette,
    /// A `tRNS` that the colour type forbids or of the wrong length.
    Transparency,
    /// A critical chunk this decoder does not know.
    UnknownCritical,
    /// `IDAT` chunks with another chunk between them.
    NotContiguous,
    /// No `IDAT` chunk.
    NoImageData,
    /// An `IEND` with data.
    BadEnd,
    /// No `IEND` chunk.
    MissingEnd,
    /// Bytes after `IEND`.
    TrailingBytes,
    /// The image data is not a valid zlib stream.
    Inflate(InflateError),
    /// The image data inflates to more or fewer bytes than the header
    /// implies.
    DataSize,
    /// A row filter type over 4.
    FilterType,
    /// A palette index past the palette.
    PaletteIndex,
    /// The re-encoded file is longer than the file limit.
    ReencodedTooLarge,
}

impl PngError {
    /// A stable machine code.
    pub const fn code(self) -> &'static str {
        match self {
            PngError::FileTooLarge => "file_too_large",
            PngError::Signature => "signature",
            PngError::Truncated => "truncated",
            PngError::ChunkLength => "chunk_length",
            PngError::ChunkType => "chunk_type",
            PngError::Crc => "crc",
            PngError::FirstNotHeader => "first_not_header",
            PngError::Header => "header",
            PngError::Dimensions => "dimensions",
            PngError::Order => "chunk_order",
            PngError::Palette => "palette",
            PngError::Transparency => "transparency",
            PngError::UnknownCritical => "unknown_critical_chunk",
            PngError::NotContiguous => "idat_not_contiguous",
            PngError::NoImageData => "no_image_data",
            PngError::BadEnd => "bad_end",
            PngError::MissingEnd => "missing_end",
            PngError::TrailingBytes => "trailing_bytes",
            PngError::Inflate(_) => "image_data",
            PngError::DataSize => "image_data_size",
            PngError::FilterType => "filter_type",
            PngError::PaletteIndex => "palette_index",
            PngError::ReencodedTooLarge => "reencoded_too_large",
        }
    }
}

impl fmt::Display for PngError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            PngError::FileTooLarge => "This file is too big.",
            PngError::Dimensions => "This image is too small or too large.",
            PngError::ReencodedTooLarge => {
                "This image is too big once saved again. Please use a smaller or simpler image."
            }
            _ => "This file is not a valid PNG image.",
        };
        write!(f, "{text} ({})", self.code())
    }
}

impl std::error::Error for PngError {}

type R<T> = Result<T, PngError>;

fn at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

fn be32(s: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([
        at(s, i),
        at(s, i.wrapping_add(1)),
        at(s, i.wrapping_add(2)),
        at(s, i.wrapping_add(3)),
    ])
}

/// The fields of `IHDR` that decoding needs.
#[derive(Clone, Copy)]
struct Header {
    width: usize,
    height: usize,
    depth: u8,
    colour: u8,
    interlace: bool,
}

/// Adam7: x start, y start, x step, y step.
const ADAM7: [(usize, usize, usize, usize); 7] = [
    (0, 0, 8, 8),
    (4, 0, 8, 8),
    (0, 4, 4, 8),
    (2, 0, 4, 4),
    (0, 2, 2, 4),
    (1, 0, 2, 2),
    (0, 1, 1, 2),
];
const PLAIN: [(usize, usize, usize, usize); 1] = [(0, 0, 1, 1)];

fn span(size: usize, start: usize, step: usize) -> usize {
    size.saturating_sub(start).div_ceil(step.max(1))
}

impl Header {
    fn parse(data: &[u8], limits: &Limits) -> R<Header> {
        if data.len() != 13 {
            return Err(PngError::Header);
        }
        let (w, h) = (be32(data, 0), be32(data, 4));
        let (depth, colour) = (at(data, 8), at(data, 9));
        let valid = match colour {
            0 => matches!(depth, 1 | 2 | 4 | 8 | 16),
            3 => matches!(depth, 1 | 2 | 4 | 8),
            2 | 4 | 6 => matches!(depth, 8 | 16),
            _ => false,
        };
        if !valid || at(data, 10) != 0 || at(data, 11) != 0 || at(data, 12) > 1 {
            return Err(PngError::Header);
        }
        let side_ok = |s: u32| s > 0 && s >= limits.min_side && s <= limits.max_side;
        if !side_ok(w) || !side_ok(h) {
            return Err(PngError::Dimensions);
        }
        Ok(Header {
            width: usize::try_from(w).map_err(|_| PngError::Dimensions)?,
            height: usize::try_from(h).map_err(|_| PngError::Dimensions)?,
            depth,
            colour,
            interlace: at(data, 12) == 1,
        })
    }

    fn channels(&self) -> usize {
        match self.colour {
            2 => 3,
            4 => 2,
            6 => 4,
            _ => 1,
        }
    }

    fn bits_per_pixel(&self) -> usize {
        self.channels().wrapping_mul(usize::from(self.depth))
    }

    fn passes(&self) -> &'static [(usize, usize, usize, usize)] {
        if self.interlace { &ADAM7 } else { &PLAIN }
    }

    /// The bytes of one row of `pixels` pixels, without the filter byte.
    fn row_bytes(&self, pixels: usize) -> Option<usize> {
        Some(pixels.checked_mul(self.bits_per_pixel())?.div_ceil(8))
    }

    /// The exact decompressed size.
    fn raw_len(&self) -> Option<usize> {
        let mut total = 0usize;
        for &(xs, ys, dx, dy) in self.passes() {
            let (pw, ph) = (span(self.width, xs, dx), span(self.height, ys, dy));
            if pw == 0 || ph == 0 {
                continue;
            }
            let row = self.row_bytes(pw)?.checked_add(1)?;
            total = total.checked_add(row.checked_mul(ph)?)?;
        }
        Some(total)
    }
}

/// The transparency of `tRNS`, by colour type.
enum Trns<'a> {
    None,
    Grey(u16),
    Rgb([u16; 3]),
    Palette(&'a [u8]),
}

/// What the chunk walk found.
struct Parts<'a> {
    header: Header,
    palette: &'a [u8],
    trns: Trns<'a>,
    idat: Vec<u8>,
}

fn walk<'a>(bytes: &'a [u8], limits: &Limits) -> R<Parts<'a>> {
    if bytes.len() > limits.max_file_bytes {
        return Err(PngError::FileTooLarge);
    }
    if bytes.get(..8) != Some(&SIGNATURE[..]) {
        return Err(PngError::Signature);
    }
    let mut pos = 8usize;
    let mut header: Option<Header> = None;
    let mut palette: Option<&[u8]> = None;
    let mut trns: Option<&[u8]> = None;
    let mut idat: Vec<u8> = Vec::new();
    // 0: no IDAT yet, 1: inside the IDAT run, 2: after it.
    let mut idat_state = 0u8;
    loop {
        if pos == bytes.len() {
            return Err(PngError::MissingEnd);
        }
        let head = bytes
            .get(pos..pos.saturating_add(8))
            .ok_or(PngError::Truncated)?;
        let len = be32(head, 0);
        if len > 0x7FFF_FFFF {
            return Err(PngError::ChunkLength);
        }
        let kind = [at(head, 4), at(head, 5), at(head, 6), at(head, 7)];
        if !kind.iter().all(u8::is_ascii_alphabetic) {
            return Err(PngError::ChunkType);
        }
        let len = usize::try_from(len).map_err(|_| PngError::ChunkLength)?;
        let data_start = pos.saturating_add(8);
        let data_end = data_start.saturating_add(len);
        let crc_end = data_end.saturating_add(4);
        let data = bytes.get(data_start..data_end).ok_or(PngError::Truncated)?;
        let stored = bytes.get(data_end..crc_end).ok_or(PngError::Truncated)?;
        let mut crc = Crc::new();
        crc.update(&kind);
        crc.update(data);
        if crc.finish() != be32(stored, 0) {
            return Err(PngError::Crc);
        }
        if header.is_none() && &kind != b"IHDR" {
            return Err(PngError::FirstNotHeader);
        }
        if idat_state == 1 && &kind != b"IDAT" {
            idat_state = 2;
        }
        match &kind {
            b"IHDR" => {
                if header.is_some() {
                    return Err(PngError::Order);
                }
                header = Some(Header::parse(data, limits)?);
            }
            b"PLTE" => {
                let h = header.ok_or(PngError::FirstNotHeader)?;
                if idat_state != 0 || palette.is_some() || trns.is_some() {
                    return Err(PngError::Order);
                }
                let entries = data.len() / 3;
                let max = if h.colour == 3 {
                    1usize << h.depth.min(8)
                } else {
                    256
                };
                if matches!(h.colour, 0 | 4) || data.len() % 3 != 0 || entries == 0 || entries > max
                {
                    return Err(PngError::Palette);
                }
                palette = Some(data);
            }
            b"tRNS" => {
                let h = header.ok_or(PngError::FirstNotHeader)?;
                if idat_state != 0 || trns.is_some() {
                    return Err(PngError::Order);
                }
                let ok = match h.colour {
                    0 => data.len() == 2,
                    2 => data.len() == 6,
                    3 => {
                        let p = palette.ok_or(PngError::Order)?;
                        data.len() <= p.len() / 3
                    }
                    _ => false,
                };
                if !ok {
                    return Err(PngError::Transparency);
                }
                trns = Some(data);
            }
            b"IDAT" => {
                if idat_state == 2 {
                    return Err(PngError::NotContiguous);
                }
                idat_state = 1;
                idat.extend_from_slice(data);
            }
            b"IEND" => {
                if !data.is_empty() {
                    return Err(PngError::BadEnd);
                }
                if crc_end != bytes.len() {
                    return Err(PngError::TrailingBytes);
                }
                break;
            }
            _ => {
                if at(&kind, 0).is_ascii_uppercase() {
                    return Err(PngError::UnknownCritical);
                }
            }
        }
        pos = crc_end;
    }
    let header = header.ok_or(PngError::FirstNotHeader)?;
    if idat_state == 0 {
        return Err(PngError::NoImageData);
    }
    if header.colour == 3 && palette.is_none() {
        return Err(PngError::Palette);
    }
    let trns = match (header.colour, trns) {
        (_, None) => Trns::None,
        (0, Some(t)) => Trns::Grey(u16::from_be_bytes([at(t, 0), at(t, 1)])),
        (2, Some(t)) => {
            Trns::Rgb([0, 2, 4].map(|i| u16::from_be_bytes([at(t, i), at(t, i.wrapping_add(1))])))
        }
        (_, Some(t)) => Trns::Palette(t),
    };
    Ok(Parts {
        header,
        palette: palette.unwrap_or(&[]),
        trns,
        idat,
    })
}

/// The Paeth predictor of the PNG specification.
pub(crate) fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let (ia, ib, ic) = (i16::from(a), i16::from(b), i16::from(c));
    let p = ia.wrapping_add(ib).wrapping_sub(ic);
    let pa = p.wrapping_sub(ia).unsigned_abs();
    let pb = p.wrapping_sub(ib).unsigned_abs();
    let pc = p.wrapping_sub(ic).unsigned_abs();
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

/// The predictor of filter `ft` for left `a`, up `b` and up-left `c`.
pub(crate) fn predict(ft: u8, a: u8, b: u8, c: u8) -> u8 {
    match ft {
        1 => a,
        2 => b,
        3 => (u16::from(a).wrapping_add(u16::from(b)) >> 1) as u8,
        4 => paeth(a, b, c),
        _ => 0,
    }
}

fn unfilter(ft: u8, line: &[u8], prev: &[u8], cur: &mut [u8], bpp: usize) -> R<()> {
    if ft > 4 {
        return Err(PngError::FilterType);
    }
    for i in 0..cur.len() {
        let (a, c) = match i.checked_sub(bpp) {
            Some(j) => (at(cur, j), at(prev, j)),
            None => (0, 0),
        };
        let v = at(line, i).wrapping_add(predict(ft, a, at(prev, i), c));
        if let Some(slot) = cur.get_mut(i) {
            *slot = v;
        }
    }
    Ok(())
}

/// Sample `index` of a row at bit depth `depth`.
fn sample(row: &[u8], index: usize, depth: u8) -> u16 {
    match depth {
        16 => {
            let i = index.wrapping_mul(2);
            u16::from_be_bytes([at(row, i), at(row, i.wrapping_add(1))])
        }
        8 => u16::from(at(row, index)),
        d => {
            let bit = index.wrapping_mul(usize::from(d));
            let byte = at(row, bit >> 3);
            let shift = 8u8.wrapping_sub(d).wrapping_sub((bit & 7) as u8);
            let mask = (1u8 << d.min(7)).wrapping_sub(1);
            u16::from(byte.checked_shr(u32::from(shift)).unwrap_or(0) & mask)
        }
    }
}

/// A sample scaled to 8 bits (ADR-031 row "Samples").
fn scale(v: u16, depth: u8) -> u8 {
    match depth {
        16 => {
            let s = u32::from(v).wrapping_mul(255).wrapping_add(32_895) / 65_535;
            u8::try_from(s).unwrap_or(u8::MAX)
        }
        8 => u8::try_from(v).unwrap_or(u8::MAX),
        4 => (v as u8).wrapping_mul(17),
        2 => (v as u8).wrapping_mul(85),
        _ => (v as u8).wrapping_mul(255),
    }
}

fn pixel(row: &[u8], i: usize, h: &Header, palette: &[u8], trns: &Trns<'_>) -> R<[u8; 4]> {
    let c = h.channels();
    let d = h.depth;
    let s = |k: usize| sample(row, i.wrapping_mul(c).wrapping_add(k), d);
    Ok(match h.colour {
        0 => {
            let v = s(0);
            let g = scale(v, d);
            let a = if matches!(trns, Trns::Grey(k) if *k == v) {
                0
            } else {
                255
            };
            [g, g, g, a]
        }
        2 => {
            let rgb = [s(0), s(1), s(2)];
            let a = if matches!(trns, Trns::Rgb(k) if *k == rgb) {
                0
            } else {
                255
            };
            [scale(rgb[0], d), scale(rgb[1], d), scale(rgb[2], d), a]
        }
        3 => {
            let idx = usize::from(s(0));
            let o = idx.wrapping_mul(3);
            let entry = palette
                .get(o..o.wrapping_add(3))
                .ok_or(PngError::PaletteIndex)?;
            let a = match trns {
                Trns::Palette(t) => t.get(idx).copied().unwrap_or(255),
                _ => 255,
            };
            [at(entry, 0), at(entry, 1), at(entry, 2), a]
        }
        4 => {
            let g = scale(s(0), d);
            [g, g, g, scale(s(1), d)]
        }
        _ => [
            scale(s(0), d),
            scale(s(1), d),
            scale(s(2), d),
            scale(s(3), d),
        ],
    })
}

/// Decodes a PNG file to 8-bit RGBA under `limits`.
///
/// Every chunk's CRC is checked. Ancillary chunks are then dropped. The
/// image data must inflate to exactly the size the header implies, which
/// is at most [`MAX_RAW_BYTES`].
pub fn decode(bytes: &[u8], limits: &Limits) -> Result<Image, PngError> {
    let parts = walk(bytes, limits)?;
    let h = parts.header;
    let raw_len = h.raw_len().ok_or(PngError::Dimensions)?;
    if raw_len > MAX_RAW_BYTES {
        return Err(PngError::Dimensions);
    }
    let raw = zlib_with(&parts.idat, raw_len, raw_len).map_err(|e| match e {
        InflateError::OutputLimit => PngError::DataSize,
        e => PngError::Inflate(e),
    })?;
    if raw.len() != raw_len {
        return Err(PngError::DataSize);
    }
    let out_len = h
        .width
        .checked_mul(h.height)
        .and_then(|n| n.checked_mul(4))
        .ok_or(PngError::Dimensions)?;
    let mut out = vec![0u8; out_len];
    let bpp = h.bits_per_pixel().div_ceil(8).max(1);
    let mut off = 0usize;
    for &(xs, ys, dx, dy) in h.passes() {
        let (pw, ph) = (span(h.width, xs, dx), span(h.height, ys, dy));
        if pw == 0 || ph == 0 {
            continue;
        }
        let row = h.row_bytes(pw).ok_or(PngError::Dimensions)?;
        let mut prev = vec![0u8; row];
        let mut cur = vec![0u8; row];
        for r in 0..ph {
            let ft = at(&raw, off);
            let start = off.wrapping_add(1);
            let line = raw
                .get(start..start.wrapping_add(row))
                .ok_or(PngError::DataSize)?;
            off = start.wrapping_add(row);
            unfilter(ft, line, &prev, &mut cur, bpp)?;
            let y = ys.wrapping_add(r.wrapping_mul(dy));
            for i in 0..pw {
                let x = xs.wrapping_add(i.wrapping_mul(dx));
                let px = pixel(&cur, i, &h, parts.palette, &parts.trns)?;
                let o = y.wrapping_mul(h.width).wrapping_add(x).wrapping_mul(4);
                if let Some(slot) = out.get_mut(o..o.wrapping_add(4)) {
                    slot.copy_from_slice(&px);
                }
            }
            std::mem::swap(&mut prev, &mut cur);
        }
    }
    let width = u32::try_from(h.width).map_err(|_| PngError::Dimensions)?;
    let height = u32::try_from(h.height).map_err(|_| PngError::Dimensions)?;
    Image::new(width, height, out).ok_or(PngError::Dimensions)
}
