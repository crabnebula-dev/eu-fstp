//! The logo check (ADR-030 section 3; I-68, R-WL-03).
//!
//! A logo is a PNG or WebP file. [`inspect`] walks its header and chunks,
//! never its pixel data, and returns the file rewritten with only the
//! chunks that draw the image. Text, EXIF, XMP, ICC and animation chunks
//! are dropped. Every other format, SVG included, is refused. Fuzz target
//! `logo_inspect`.
//!
//! [`pdf_image`] reads the parameters a PDF needs to show a PNG without
//! decoding it (ADR-030 section 6): the `IDAT` bytes pass through as one
//! `/FlateDecode` stream with the PNG predictor.

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

/// The colour space of a PDF image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PdfColours {
    /// `/DeviceGray`, one component.
    Gray,
    /// `/DeviceRGB`, three components.
    Rgb,
    /// `/Indexed` over `/DeviceRGB` with this palette, three bytes per
    /// entry.
    Indexed(Vec<u8>),
}

impl PdfColours {
    /// The components per sample in the stream.
    pub const fn components(&self) -> u8 {
        match self {
            PdfColours::Rgb => 3,
            PdfColours::Gray | PdfColours::Indexed(_) => 1,
        }
    }
}

/// What a PDF needs to show a PNG without decoding it (ADR-030 section 6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdfImage {
    /// The width in pixels: `/Columns` and `/Width`.
    pub width: u32,
    /// The height in pixels.
    pub height: u32,
    /// The colour space.
    pub colours: PdfColours,
    /// Bits per component: 1, 2, 4 or 8.
    pub bits: u8,
    /// A colour-key `/Mask`: a min and max per component.
    pub mask: Option<Vec<u16>>,
    /// The zlib stream of the `IDAT` chunks, unchanged.
    pub data: Vec<u8>,
}

/// The PDF image of `bytes`, or `None` when it cannot be shown without
/// a decoder: any WebP, a PNG with an alpha channel, partial palette
/// transparency, interlacing or 16-bit samples.
pub fn pdf_image(bytes: &[u8]) -> Option<PdfImage> {
    if bytes.len() > MAX_LOGO_BYTES || !bytes.starts_with(&PNG_SIGNATURE) {
        return None;
    }
    let w = walk_png(bytes).ok()?;
    let h = w.header;
    if h.interlace != 0 || h.depth > 8 {
        return None;
    }
    let max = (1u16 << h.depth).checked_sub(1)?;
    let key = |d: &[u8], at: usize| -> Option<u16> {
        let v = u16::from_be_bytes([*d.get(at)?, *d.get(at.checked_add(1)?)?]);
        (v <= max).then_some(v)
    };
    let (colours, mask) = match h.colour {
        0 => {
            let mask = match w.transparency {
                Some(t) => {
                    let g = key(t, 0)?;
                    Some(vec![g, g])
                }
                None => None,
            };
            (PdfColours::Gray, mask)
        }
        2 => {
            let mask = match w.transparency {
                Some(t) => {
                    let (r, g, b) = (key(t, 0)?, key(t, 2)?, key(t, 4)?);
                    Some(vec![r, r, g, g, b, b])
                }
                None => None,
            };
            (PdfColours::Rgb, mask)
        }
        3 => {
            let palette = w.palette?.to_vec();
            let mask = match w.transparency {
                Some(t) => {
                    let clear: Vec<usize> = t
                        .iter()
                        .enumerate()
                        .filter(|(_, a)| **a == 0)
                        .map(|(i, _)| i)
                        .collect();
                    if t.iter().any(|a| *a != 0 && *a != 255) || clear.len() > 1 {
                        return None;
                    }
                    match clear.first() {
                        Some(i) => {
                            let i = u16::try_from(*i).ok()?;
                            Some(vec![i, i])
                        }
                        None => None,
                    }
                }
                None => None,
            };
            (PdfColours::Indexed(palette), mask)
        }
        _ => return None,
    };
    Some(PdfImage {
        width: h.width,
        height: h.height,
        colours,
        bits: h.depth,
        mask,
        data: w.data,
    })
}
