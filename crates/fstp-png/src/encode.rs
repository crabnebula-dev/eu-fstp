//! The canonical PNG encoder, re-encoding and the PDF helpers (ADR-031
//! rows "PNG encode", "Re-encode" and "PDF helpers").

use fstp_creator::Rgb;

use crate::check::Crc;
use crate::deflate::zlib_compress;
use crate::image::{Image, blend};
use crate::png::{Limits, PngError, SIGNATURE, decode, predict};

fn at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

/// Rows of `channels` bytes a pixel, each led by the PNG filter that
/// gives the smallest sum of absolute residuals (ties to the lowest
/// type). This is the `IDAT` payload of a non-interlaced 8-bit PNG, and
/// a PDF `/FlateDecode` stream with `/Predictor 15` once compressed.
pub(crate) fn filter_rows(width: usize, height: usize, channels: usize, data: &[u8]) -> Vec<u8> {
    let row = width.saturating_mul(channels);
    let mut out = Vec::with_capacity(height.saturating_mul(row.saturating_add(1)));
    let zero = vec![0u8; row];
    let mut prev: &[u8] = &zero;
    let mut best = vec![0u8; row];
    let mut cand = vec![0u8; row];
    for r in 0..height {
        let start = r.saturating_mul(row);
        let Some(cur) = data.get(start..start.saturating_add(row)) else {
            break;
        };
        let mut best_ft = 0u8;
        let mut best_sum = u64::MAX;
        for ft in 0..5u8 {
            let mut sum = 0u64;
            for (i, slot) in cand.iter_mut().enumerate() {
                let (a, c) = match i.checked_sub(channels) {
                    Some(j) => (at(cur, j), at(prev, j)),
                    None => (0, 0),
                };
                let v = at(cur, i).wrapping_sub(predict(ft, a, at(prev, i), c));
                *slot = v;
                sum = sum.saturating_add(u64::from((v as i8).unsigned_abs()));
            }
            if sum < best_sum {
                best_sum = sum;
                best_ft = ft;
                std::mem::swap(&mut best, &mut cand);
            }
        }
        out.push(best_ft);
        out.extend_from_slice(&best);
        prev = cur;
    }
    out
}

fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    out.extend(len.to_be_bytes());
    out.extend(kind);
    out.extend(data);
    let mut crc = Crc::new();
    crc.update(kind);
    crc.update(data);
    out.extend(crc.finish().to_be_bytes());
}

fn rgb_plane(img: &Image) -> Vec<u8> {
    img.rgba()
        .chunks_exact(4)
        .flat_map(|p| [at(p, 0), at(p, 1), at(p, 2)])
        .collect()
}

/// The canonical PNG of `img` (I-68): 8 bits a channel, not interlaced,
/// `IHDR`, one `IDAT` and `IEND`. RGB (colour type 2) when every pixel is
/// opaque, RGBA (colour type 6) otherwise. The same pixels always give
/// the same bytes.
pub fn encode(img: &Image) -> Vec<u8> {
    let (w, h) = (img.width_usize(), img.height_usize());
    let opaque = img.is_opaque();
    let rows = if opaque {
        filter_rows(w, h, 3, &rgb_plane(img))
    } else {
        filter_rows(w, h, 4, img.rgba())
    };
    let z = zlib_compress(&rows);
    let mut ihdr = img.width().to_be_bytes().to_vec();
    ihdr.extend(img.height().to_be_bytes());
    ihdr.extend([8, if opaque { 2 } else { 6 }, 0, 0, 0]);
    let mut out = Vec::with_capacity(z.len().saturating_add(64));
    out.extend(SIGNATURE);
    chunk(&mut out, b"IHDR", &ihdr);
    chunk(&mut out, b"IDAT", &z);
    chunk(&mut out, b"IEND", &[]);
    out
}

/// Decodes `bytes` under `limits` and writes the canonical PNG of its
/// pixels (I-68). A result longer than `limits.max_file_bytes` is
/// refused with [`PngError::ReencodedTooLarge`].
pub fn reencode(bytes: &[u8], limits: &Limits) -> Result<Vec<u8>, PngError> {
    let out = encode(&decode(bytes, limits)?);
    if out.len() > limits.max_file_bytes {
        return Err(PngError::ReencodedTooLarge);
    }
    Ok(out)
}

/// The pixels of `img` composited over `background`, as 8-bit RGB. Each
/// channel is `(f * a + b * (255 - a) + 127) / 255`.
pub fn flatten(img: &Image, background: Rgb) -> Vec<u8> {
    img.rgba()
        .chunks_exact(4)
        .flat_map(|p| {
            let a = at(p, 3);
            [
                blend(at(p, 0), background.r, a),
                blend(at(p, 1), background.g, a),
                blend(at(p, 2), background.b, a),
            ]
        })
        .collect()
}

/// A PDF image stream: zlib data of rows led by PNG filter bytes, for
/// `/FlateDecode` with `/DecodeParms << /Predictor 15 /Colors colours
/// /BitsPerComponent 8 /Columns width >>`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PdfStream {
    /// The width in pixels: `/Width` and `/Columns`.
    pub width: u32,
    /// The height in pixels.
    pub height: u32,
    /// The components a pixel: 3 for `/DeviceRGB`, 1 for `/DeviceGray`.
    pub colours: u8,
    /// The zlib stream.
    pub data: Vec<u8>,
}

/// The pixels of `img` flattened over `background`, as a `/DeviceRGB`
/// stream.
pub fn pdf_rgb(img: &Image, background: Rgb) -> PdfStream {
    let rows = filter_rows(
        img.width_usize(),
        img.height_usize(),
        3,
        &flatten(img, background),
    );
    PdfStream {
        width: img.width(),
        height: img.height(),
        colours: 3,
        data: zlib_compress(&rows),
    }
}

/// The alpha plane of `img` as a `/DeviceGray` stream, for an `/SMask`.
/// `None` when every pixel is opaque.
pub fn pdf_alpha(img: &Image) -> Option<PdfStream> {
    if img.is_opaque() {
        return None;
    }
    let alpha: Vec<u8> = img.rgba().chunks_exact(4).map(|p| at(p, 3)).collect();
    let rows = filter_rows(img.width_usize(), img.height_usize(), 1, &alpha);
    Some(PdfStream {
        width: img.width(),
        height: img.height(),
        colours: 1,
        data: zlib_compress(&rows),
    })
}
