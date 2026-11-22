//! The logo check (ADR-030 section 3; I-68, R-WL-03).
//!
//! A logo is a PNG or WebP file. [`inspect`] walks its header and chunks,
//! never its pixel data, and returns the file rewritten with only the
//! chunks that draw the image. Text, EXIF, XMP, ICC and animation chunks
//! are dropped. Every other format, SVG included, is refused. Fuzz target
//! `logo_inspect`.
//!
//! An upload then passes [`reencode`]: `fstp-png` decodes the PNG and
//! writes it again in one canonical shape (ADR-031). The cell takes PNG
//! uploads only. [`pdf_image`] gives a PDF the flattened pixels and the
//! alpha plane for an `/SMask`, and [`header_contrast`] the contrast
//! advice (ADR-030 lead reading of 2026-11-22).

/// The largest logo file, in bytes (256 KiB).
pub const MAX_LOGO_BYTES: usize = 256 * 1024;

/// The smallest width or height, in pixels.
pub const MIN_DIMENSION: u32 = 16;

/// The largest width or height, in pixels.
pub const MAX_DIMENSION: u32 = 2048;

/// The most chunks one file may hold.
const MAX_CHUNKS: usize = 4096;

/// A logo's format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogoFormat {
    /// PNG.
    Png,
    /// WebP.
    Webp,
}

impl LogoFormat {
    /// Both formats.
    pub const ALL: [LogoFormat; 2] = [LogoFormat::Png, LogoFormat::Webp];

    /// The format's name, which is also its file extension.
    pub const fn name(self) -> &'static str {
        match self {
            LogoFormat::Png => "png",
            LogoFormat::Webp => "webp",
        }
    }

    /// The fixed content type a served logo carries.
    pub const fn media_type(self) -> &'static str {
        match self {
            LogoFormat::Png => "image/png",
            LogoFormat::Webp => "image/webp",
        }
    }

    /// The format named `s`.
    pub fn from_name(s: &str) -> Option<LogoFormat> {
        LogoFormat::ALL.into_iter().find(|f| f.name() == s)
    }

    /// Whether emails show the format (ADR-030 section 5).
    pub const fn in_email(self) -> bool {
        matches!(self, LogoFormat::Png)
    }
}

/// Why a file is not a logo. Each code is fixed and quotes no input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LogoRefusal {
    /// Larger than [`MAX_LOGO_BYTES`].
    TooLarge,
    /// Neither PNG nor WebP, such as SVG, GIF or JPEG.
    WrongType,
    /// Width or height outside [`MIN_DIMENSION`] to [`MAX_DIMENSION`].
    Dimensions,
    /// An animated WebP.
    Animated,
    /// A PNG or WebP whose structure is wrong.
    Malformed,
}

impl LogoRefusal {
    /// The refusal's stable code.
    pub const fn code(self) -> &'static str {
        match self {
            LogoRefusal::TooLarge => "too_large",
            LogoRefusal::WrongType => "wrong_type",
            LogoRefusal::Dimensions => "dimensions",
            LogoRefusal::Animated => "animated",
            LogoRefusal::Malformed => "malformed",
        }
    }
}

/// An accepted logo: its format, its size and the rewritten bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Logo {
    /// The format.
    pub format: LogoFormat,
    /// The width in pixels.
    pub width: u32,
    /// The height in pixels.
    pub height: u32,
    /// The file with only the chunks that draw the image.
    pub bytes: Vec<u8>,
}

type R<T> = Result<T, LogoRefusal>;

const BAD: LogoRefusal = LogoRefusal::Malformed;

/// Checks `bytes` and rewrites them (module documentation).
///
/// # Errors
///
/// A [`LogoRefusal`] naming the first rule the file breaks.
pub fn inspect(bytes: &[u8]) -> R<Logo> {
    if bytes.len() > MAX_LOGO_BYTES {
        return Err(LogoRefusal::TooLarge);
    }
    let logo = if bytes.starts_with(&PNG_SIGNATURE) {
        png(bytes)?
    } else if bytes.len() >= 12
        && bytes.get(..4) == Some(b"RIFF".as_slice())
        && bytes.get(8..12) == Some(b"WEBP".as_slice())
    {
        webp(bytes)?
    } else {
        return Err(LogoRefusal::WrongType);
    };
    let ok = |d: u32| (MIN_DIMENSION..=MAX_DIMENSION).contains(&d);
    if !ok(logo.width) || !ok(logo.height) {
        return Err(LogoRefusal::Dimensions);
    }
    Ok(logo)
}

// ------------------------------------------------------------------ PNG

const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

/// CRC-32 of ISO 3309 as PNG uses it. A checksum, not cryptography.
fn crc32(parts: &[&[u8]]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for part in parts {
        for b in *part {
            c ^= u32::from(*b);
            for _ in 0..8 {
                c = if c & 1 == 1 {
                    (c >> 1) ^ 0xEDB8_8320
                } else {
                    c >> 1
                };
            }
        }
    }
    !c
}

fn four(b: &[u8], at: usize) -> Option<[u8; 4]> {
    b.get(at..at.checked_add(4)?)?.try_into().ok()
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    four(b, at).map(u32::from_be_bytes)
}

fn byte(b: &[u8], at: usize) -> R<u8> {
    b.get(at).copied().ok_or(BAD)
}

/// One PNG chunk: its type, its data and its whole encoding.
struct Chunk<'a> {
    kind: [u8; 4],
    data: &'a [u8],
    raw: &'a [u8],
}

/// The chunks of a PNG after its signature, each with a checked CRC.
fn png_chunks(bytes: &[u8]) -> R<Vec<Chunk<'_>>> {
    let mut out = Vec::new();
    let mut at = PNG_SIGNATURE.len();
    while at < bytes.len() {
        if out.len() >= MAX_CHUNKS {
            return Err(BAD);
        }
        let len = usize::try_from(be32(bytes, at).ok_or(BAD)?).map_err(|_| BAD)?;
        let kind_at = at.checked_add(4).ok_or(BAD)?;
        let data_at = kind_at.checked_add(4).ok_or(BAD)?;
        let end = data_at.checked_add(len).ok_or(BAD)?;
        let next = end.checked_add(4).ok_or(BAD)?;
        let kind: [u8; 4] = bytes
            .get(kind_at..data_at)
            .and_then(|k| k.try_into().ok())
            .ok_or(BAD)?;
        if !kind.iter().all(u8::is_ascii_alphabetic) {
            return Err(BAD);
        }
        let data = bytes.get(data_at..end).ok_or(BAD)?;
        if crc32(&[&kind, data]) != be32(bytes, end).ok_or(BAD)? {
            return Err(BAD);
        }
        out.push(Chunk {
            kind,
            data,
            raw: bytes.get(at..next).ok_or(BAD)?,
        });
        at = next;
    }
    Ok(out)
}

/// The header fields of `IHDR`.
#[derive(Clone, Copy)]
struct Header {
    width: u32,
    height: u32,
    depth: u8,
    colour: u8,
    interlace: u8,
}

fn header(c: &Chunk<'_>) -> R<Header> {
    if &c.kind != b"IHDR" || c.data.len() != 13 {
        return Err(BAD);
    }
    let d = c.data;
    let h = Header {
        width: be32(d, 0).ok_or(BAD)?,
        height: be32(d, 4).ok_or(BAD)?,
        depth: byte(d, 8)?,
        colour: byte(d, 9)?,
        interlace: byte(d, 12)?,
    };
    let depth_ok = match h.colour {
        0 => matches!(h.depth, 1 | 2 | 4 | 8 | 16),
        3 => matches!(h.depth, 1 | 2 | 4 | 8),
        2 | 4 | 6 => matches!(h.depth, 8 | 16),
        _ => false,
    };
    if !depth_ok
        || byte(d, 10)? != 0
        || byte(d, 11)? != 0
        || h.interlace > 1
        || h.width == 0
        || h.height == 0
    {
        return Err(BAD);
    }
    Ok(h)
}

/// A walked PNG: its header, the chunks it keeps and the image data.
struct Walked<'a> {
    header: Header,
    kept: Vec<&'a [u8]>,
    palette: Option<&'a [u8]>,
    transparency: Option<&'a [u8]>,
    data: Vec<u8>,
}

/// Walks a PNG by the rules of ADR-030 section 3.
fn walk_png(bytes: &[u8]) -> R<Walked<'_>> {
    let chunks = png_chunks(bytes)?;
    let (first, rest) = chunks.split_first().ok_or(BAD)?;
    let h = header(first)?;
    let mut w = Walked {
        header: h,
        kept: vec![first.raw],
        palette: None,
        transparency: None,
        data: Vec::new(),
    };
    // 0: before IDAT, 1: in the IDAT run, 2: after it, 3: after IEND.
    let mut phase = 0u8;
    for c in rest {
        if phase == 3 {
            return Err(BAD);
        }
        match &c.kind {
            b"IHDR" => return Err(BAD),
            b"PLTE" => {
                let n = c.data.len() / 3;
                if phase != 0
                    || w.palette.is_some()
                    || w.transparency.is_some()
                    || matches!(h.colour, 0 | 4)
                    || c.data.len() % 3 != 0
                    || n == 0
                    || n > 256
                    || (h.colour == 3 && n > 1usize << h.depth)
                {
                    return Err(BAD);
                }
                w.palette = Some(c.data);
                w.kept.push(c.raw);
            }
            b"tRNS" => {
                let ok = match h.colour {
                    0 => c.data.len() == 2,
                    2 => c.data.len() == 6,
                    3 => w.palette.is_some_and(|p| c.data.len() <= p.len() / 3),
                    _ => false,
                };
                if phase != 0 || w.transparency.is_some() || !ok {
                    return Err(BAD);
                }
                w.transparency = Some(c.data);
                w.kept.push(c.raw);
            }
            b"gAMA" | b"sRGB" => {
                let len = if &c.kind == b"gAMA" { 4 } else { 1 };
                if phase != 0 || c.data.len() != len {
                    return Err(BAD);
                }
                w.kept.push(c.raw);
            }
            b"IDAT" => {
                if phase == 2 {
                    return Err(BAD);
                }
                phase = 1;
                w.data.extend_from_slice(c.data);
                w.kept.push(c.raw);
            }
            b"IEND" => {
                if phase == 0 || !c.data.is_empty() {
                    return Err(BAD);
                }
                phase = 3;
                w.kept.push(c.raw);
            }
            k if k[0].is_ascii_uppercase() => return Err(BAD),
            _ => {
                // An ancillary chunk is dropped. One between IDAT chunks
                // ends the run.
                if phase == 1 {
                    phase = 2;
                }
            }
        }
    }
    if phase != 3 || (h.colour == 3 && w.palette.is_none()) {
        return Err(BAD);
    }
    Ok(w)
}

fn png(bytes: &[u8]) -> R<Logo> {
    let w = walk_png(bytes)?;
    let mut out = PNG_SIGNATURE.to_vec();
    for raw in &w.kept {
        out.extend_from_slice(raw);
    }
    Ok(Logo {
        format: LogoFormat::Png,
        width: w.header.width,
        height: w.header.height,
        bytes: out,
    })
}

// ----------------------------------------------------------------- WebP

fn le24(b: &[u8], at: usize) -> Option<u32> {
    let s: [u8; 3] = b.get(at..at.checked_add(3)?)?.try_into().ok()?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], 0]))
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    four(b, at).map(u32::from_le_bytes)
}

/// The chunks of a WebP file after its RIFF header: type and payload.
fn riff_chunks(bytes: &[u8]) -> R<Vec<([u8; 4], &[u8])>> {
    let size = usize::try_from(le32(bytes, 4).ok_or(BAD)?).map_err(|_| BAD)?;
    if size.checked_add(8) != Some(bytes.len()) {
        return Err(BAD);
    }
    let mut out = Vec::new();
    let mut at = 12usize;
    while at < bytes.len() {
        if out.len() >= MAX_CHUNKS {
            return Err(BAD);
        }
        let kind: [u8; 4] = bytes
            .get(at..at.checked_add(4).ok_or(BAD)?)
            .and_then(|k| k.try_into().ok())
            .ok_or(BAD)?;
        let len = usize::try_from(le32(bytes, at.checked_add(4).ok_or(BAD)?).ok_or(BAD)?)
            .map_err(|_| BAD)?;
        let data_at = at.checked_add(8).ok_or(BAD)?;
        let end = data_at.checked_add(len).ok_or(BAD)?;
        let padded = end.checked_add(len % 2).ok_or(BAD)?;
        let data = bytes.get(data_at..end).ok_or(BAD)?;
        if padded > bytes.len() {
            return Err(BAD);
        }
        out.push((kind, data));
        at = padded;
    }
    Ok(out)
}

/// The size of a lossy key frame.
fn vp8_size(d: &[u8]) -> R<(u32, u32)> {
    if d.len() < 10 || byte(d, 0)? & 0x01 != 0 || d.get(3..6) != Some([0x9D, 0x01, 0x2A].as_slice())
    {
        return Err(BAD);
    }
    let w = u32::from(u16::from_le_bytes([byte(d, 6)?, byte(d, 7)?]) & 0x3FFF);
    let h = u32::from(u16::from_le_bytes([byte(d, 8)?, byte(d, 9)?]) & 0x3FFF);
    Ok((w, h))
}

/// The size of a lossless bitstream.
fn vp8l_size(d: &[u8]) -> R<(u32, u32)> {
    if d.len() < 5 || byte(d, 0)? != 0x2F {
        return Err(BAD);
    }
    let bits = le32(d, 1).ok_or(BAD)?;
    if bits >> 29 != 0 {
        return Err(BAD);
    }
    let w = (bits & 0x3FFF).checked_add(1).ok_or(BAD)?;
    let h = ((bits >> 14) & 0x3FFF).checked_add(1).ok_or(BAD)?;
    Ok((w, h))
}

fn image_size(kind: &[u8; 4], d: &[u8]) -> R<(u32, u32)> {
    match kind {
        b"VP8 " => vp8_size(d),
        b"VP8L" => vp8l_size(d),
        _ => Err(BAD),
    }
}

fn push_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) -> R<()> {
    out.extend_from_slice(kind);
    out.extend_from_slice(&u32::try_from(data.len()).map_err(|_| BAD)?.to_le_bytes());
    out.extend_from_slice(data);
    if data.len() % 2 == 1 {
        out.push(0);
    }
    Ok(())
}

const VP8X_ALPHA: u8 = 0x10;
const VP8X_ANIMATION: u8 = 0x02;

fn webp(bytes: &[u8]) -> R<Logo> {
    let chunks = riff_chunks(bytes)?;
    let ((first_kind, first), rest) = chunks.split_first().ok_or(BAD)?;
    let mut body = Vec::with_capacity(bytes.len());
    let (width, height) = match first_kind {
        b"VP8 " | b"VP8L" => {
            // Simple format: the image chunk alone. Anything after it is
            // dropped.
            let size = image_size(first_kind, first)?;
            push_chunk(&mut body, first_kind, first)?;
            size
        }
        b"VP8X" => {
            if first.len() != 10 {
                return Err(BAD);
            }
            let flags = byte(first, 0)?;
            if flags & VP8X_ANIMATION != 0 {
                return Err(LogoRefusal::Animated);
            }
            let cw = le24(first, 4).and_then(|x| x.checked_add(1)).ok_or(BAD)?;
            let ch = le24(first, 7).and_then(|x| x.checked_add(1)).ok_or(BAD)?;
            let mut alpha: Option<&[u8]> = None;
            let mut image: Option<([u8; 4], &[u8])> = None;
            for (kind, data) in rest {
                match kind {
                    b"ANIM" | b"ANMF" => return Err(LogoRefusal::Animated),
                    b"ALPH" if image.is_none() && alpha.is_none() => alpha = Some(data),
                    b"VP8 " | b"VP8L" if image.is_none() => image = Some((*kind, data)),
                    b"ALPH" | b"VP8 " | b"VP8L" | b"VP8X" => return Err(BAD),
                    // ICCP before the image, EXIF, XMP and unknown chunks
                    // after it: dropped.
                    _ => {}
                }
            }
            let (kind, data) = image.ok_or(BAD)?;
            if alpha.is_some() && &kind != b"VP8 " {
                return Err(BAD);
            }
            if image_size(&kind, data)? != (cw, ch) {
                return Err(BAD);
            }
            let mut x = [0u8; 10];
            x[0] = flags & VP8X_ALPHA;
            let canvas: [u8; 6] = first
                .get(4..10)
                .and_then(|c| c.try_into().ok())
                .ok_or(BAD)?;
            x[4..].copy_from_slice(&canvas);
            push_chunk(&mut body, b"VP8X", &x)?;
            if let Some(a) = alpha {
                push_chunk(&mut body, b"ALPH", a)?;
            }
            push_chunk(&mut body, &kind, data)?;
            (cw, ch)
        }
        _ => return Err(BAD),
    };
    let mut out = b"RIFF".to_vec();
    let size = body.len().checked_add(4).ok_or(BAD)?;
    out.extend_from_slice(&u32::try_from(size).map_err(|_| BAD)?.to_le_bytes());
    out.extend_from_slice(b"WEBP");
    out.extend(body);
    Ok(Logo {
        format: LogoFormat::Webp,
        width,
        height,
        bytes: out,
    })
}

// ------------------------------------------------------------------ PDF

/// What a PDF needs to show a PNG logo (ADR-030 section 6, ADR-031): the
/// pixels flattened over white as one `/DeviceRGB` stream and, for a logo
/// with transparency, its alpha plane as a `/DeviceGray` stream for an
/// `/SMask`. Both are zlib data of rows led by PNG filter bytes, for
/// `/FlateDecode` with `/Predictor 15` and 8 bits a component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdfImage {
    /// The width in pixels: `/Width` and `/Columns`.
    pub width: u32,
    /// The height in pixels.
    pub height: u32,
    /// The RGB stream, three components a pixel.
    pub rgb: Vec<u8>,
    /// The alpha stream, one component a pixel, when any pixel is not
    /// opaque.
    pub alpha: Option<Vec<u8>>,
}

/// The white page a PDF logo is flattened over.
const PAGE_WHITE: fstp_creator::Rgb = fstp_creator::Rgb::hex(0xFF_FF_FF);

/// The PDF image of a PNG logo, decoded by `fstp-png` under the logo
/// limits: every colour type, bit depth, interlace and transparency
/// (lead reading of 2026-11-22). `None` for a WebP file or a PNG the
/// decoder refuses.
pub fn pdf_image(bytes: &[u8]) -> Option<PdfImage> {
    if !bytes.starts_with(&PNG_SIGNATURE) {
        return None;
    }
    let img = fstp_png::decode(bytes, &fstp_png::Limits::LOGO).ok()?;
    let rgb = fstp_png::pdf_rgb(&img, PAGE_WHITE);
    Some(PdfImage {
        width: rgb.width,
        height: rgb.height,
        rgb: rgb.data,
        alpha: fstp_png::pdf_alpha(&img).map(|a| a.data),
    })
}

// --------------------------------------------------------------- upload

/// The longest base64 text of a logo: four characters per three bytes
/// of [`MAX_LOGO_BYTES`], rounded up.
pub const MAX_BASE64_CHARS: usize = MAX_LOGO_BYTES.div_ceil(3) * 4;

fn sextet(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c.checked_sub(b'A')?,
        b'a'..=b'z' => c.checked_sub(b'a')?.checked_add(26)?,
        b'0'..=b'9' => c.checked_sub(b'0')?.checked_add(52)?,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

/// The bytes of standard base64 text with padding (RFC 4648 section 4),
/// as the web page sends a file. No white space is allowed.
fn base64(text: &[u8]) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len());
    let groups = text.chunks_exact(4);
    let last = groups.len().checked_sub(1)?;
    for (i, g) in groups.enumerate() {
        let pad = g.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && i != last) {
            return None;
        }
        let mut n = 0u32;
        for (j, c) in g.iter().enumerate() {
            let v = if j.saturating_add(pad) >= 4 {
                0
            } else {
                sextet(*c)?
            };
            n = n << 6 | v;
        }
        let [_, a, b, c] = n.to_be_bytes();
        out.push(a);
        if pad < 2 {
            out.push(b);
        }
        if pad < 1 {
            out.push(c);
        }
    }
    Some(out)
}

/// The logo of an upload: standard base64 text of the file, checked by
/// [`inspect`]. Text longer than the base64 of [`MAX_LOGO_BYTES`] is too
/// large before it is decoded. Text that is not base64 is no image.
///
/// # Errors
///
/// A [`LogoRefusal`] as [`inspect`] gives, or [`LogoRefusal::WrongType`]
/// for text that is not base64.
pub fn from_base64(text: &str) -> R<Logo> {
    if text.len() > MAX_BASE64_CHARS {
        return Err(LogoRefusal::TooLarge);
    }
    let bytes = base64(text.as_bytes()).ok_or(LogoRefusal::WrongType)?;
    inspect(&bytes)
}

/// A synthetic, valid, opaque mid-grey PNG of `width` by `height` pixels
/// for tests, the matrix harness and the demo, in the canonical shape of
/// `fstp-png`, so it passes [`reencode`] unchanged.
pub fn sample_png(width: u32, height: u32) -> Vec<u8> {
    let n = usize::try_from(width)
        .unwrap_or(0)
        .saturating_mul(usize::try_from(height).unwrap_or(0));
    let rgba: Vec<u8> = (0..n).flat_map(|_| [0x80, 0x80, 0x80, 0xFF]).collect();
    png_of(width, height, rgba).unwrap_or_default()
}

// ---------------------------------------------------------------- paths

/// The same-origin path a logo is served at: `/brand/`, the 64 lower-case
/// hex digits of its digest, then `.png` or `.webp` (ADR-030 section 3).
/// Only digits and a fixed extension, so no tenant text reaches a page.
pub fn logo_path(digest: &[u8; 32], format: LogoFormat) -> String {
    let mut out = String::with_capacity(80);
    out.push_str("/brand/");
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out.push('.');
    out.push_str(format.name());
    out
}

const HEX: [u8; 16] = *b"0123456789abcdef";

/// The digest and format a logo path names, if `path` has exactly the
/// form [`logo_path`] writes.
pub fn logo_path_digest(path: &str) -> Option<([u8; 32], LogoFormat)> {
    let rest = path.strip_prefix("/brand/")?;
    let (hex, ext) = rest.split_once('.')?;
    let format = LogoFormat::from_name(ext)?;
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (o, pair) in out.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        let n = |c: u8| {
            HEX.iter()
                .position(|h| *h == c)
                .and_then(|i| u8::try_from(i).ok())
        };
        let (hi, lo) = (n(*pair.first()?)?, n(*pair.get(1)?)?);
        *o = hi.checked_mul(16)?.checked_add(lo)?;
    }
    Some((out, format))
}

/// Standard base64 with padding of `bytes`, the form [`from_base64`]
/// reads: for tests, the matrix harness and the demo.
pub fn to_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for c in bytes.chunks(3) {
        let b = |i: usize| u32::from(c.get(i).copied().unwrap_or(0));
        let n = b(0) << 16 | b(1) << 8 | b(2);
        for i in 0..4usize {
            if i <= c.len() {
                let shift =
                    18u32.saturating_sub(6u32.saturating_mul(u32::try_from(i).unwrap_or(0)));
                let k = usize::try_from(n >> shift & 63).unwrap_or(0);
                out.push(char::from(ALPHABET.get(k).copied().unwrap_or(b'A')));
            } else {
                out.push('=');
            }
        }
    }
    out
}

// ------------------------------------------------------------ re-encode

/// Re-encodes an accepted logo with `fstp-png` (ADR-030 lead reading of
/// 2026-11-22, ADR-031; I-68): the file is decoded to pixels and written
/// again in one canonical shape, so no ancillary chunk and no encoded
/// byte of the uploader's file is stored. The cell accepts PNG uploads
/// only: the branding page converts a WebP file to PNG in the browser
/// before it sends it, so a WebP upload is refused as the wrong type.
///
/// # Errors
///
/// [`LogoRefusal::WrongType`] for WebP, [`LogoRefusal::TooLarge`] when
/// the re-encoded file passes the size bound, and the refusal of the
/// decoder as [`LogoRefusal::Malformed`] or [`LogoRefusal::Dimensions`].
pub fn reencode(logo: Logo) -> R<Logo> {
    if logo.format != LogoFormat::Png {
        return Err(LogoRefusal::WrongType);
    }
    let bytes = fstp_png::reencode(&logo.bytes, &fstp_png::Limits::LOGO).map_err(|e| match e {
        fstp_png::PngError::ReencodedTooLarge | fstp_png::PngError::FileTooLarge => {
            LogoRefusal::TooLarge
        }
        fstp_png::PngError::Dimensions => LogoRefusal::Dimensions,
        _ => LogoRefusal::Malformed,
    })?;
    Ok(Logo { bytes, ..logo })
}

/// The contrast advice of a PNG logo on a header colour (ADR-030 lead
/// reading of 2026-11-22; I-70): the WCAG ratio, in hundredths, that at
/// least half of the logo's ink reaches, from `fstp_png::contrast`. It is
/// advice only and never refuses a logo. `None` for WebP, a fully
/// transparent logo, or a file the decoder refuses.
pub fn header_contrast(bytes: &[u8], header: fstp_creator::Rgb) -> Option<u32> {
    if !bytes.starts_with(&PNG_SIGNATURE) {
        return None;
    }
    let img = fstp_png::decode(bytes, &fstp_png::Limits::LOGO).ok()?;
    fstp_png::contrast(&img, header).map(|c| c.median_x100)
}

/// The ratio, in hundredths, under which a logo gets the advice that it
/// may be hard to see: 3:1, the bound of non-text content (WCAG 2.2 SC
/// 1.4.11).
pub const ADVICE_BELOW_X100: u32 = 300;

/// A PNG of `width` by `height` pixels of 8-bit RGBA `rgba`, in the
/// canonical shape of `fstp-png`, or `None` when the sizes do not match:
/// for tests, the matrix harness and the demo. Synthetic only.
pub fn png_of(width: u32, height: u32, rgba: Vec<u8>) -> Option<Vec<u8>> {
    fstp_png::Image::new(width, height, rgba).map(|i| fstp_png::encode(&i))
}
