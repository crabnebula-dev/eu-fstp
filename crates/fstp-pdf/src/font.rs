//! A bounded TrueType table reader for the one embedded font (M5 design
//! section 3.4, ADR-017).
//!
//! It reads only what the writer needs: `head`, `hhea`, `maxp`, `hmtx`,
//! `cmap` (format 4 or 12), `OS/2` and `post`. Every offset is checked
//! before use. Lookups never fail once [`TrueType::parse`] accepted the
//! file.

/// The embedded font: IBM Plex Sans Regular, pinned by ADR-017.
pub const EMBEDDED_FONT: &[u8] = include_bytes!("../assets/IBMPlexSans-Regular.ttf");

/// The SHA-256 of [`EMBEDDED_FONT`], as ADR-017 records it.
pub const EMBEDDED_FONT_SHA256: [u8; 32] = [
    0x97, 0x5d, 0xcd, 0xa3, 0x7d, 0x80, 0xf0, 0x38, 0xdc, 0xd1, 0x43, 0xc2, 0x2e, 0x33, 0xca, 0x2d,
    0x97, 0xa0, 0xcc, 0x5a, 0x92, 0x9a, 0xac, 0xe1, 0xc7, 0x49, 0x15, 0x3b, 0x0f, 0xe1, 0xaf, 0xa5,
];

/// The PostScript name of the embedded font, written as `/BaseFont`.
pub const EMBEDDED_FONT_NAME: &str = "IBMPlexSans";

/// Largest font file the reader accepts, in bytes.
pub const MAX_FONT: usize = 16 * 1024 * 1024;
/// Most tables in the table directory.
const MAX_TABLES: u16 = 64;

/// Why a font was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FontError {
    /// The file is larger than [`MAX_FONT`].
    TooLarge,
    /// The sfnt version is not TrueType outlines (`0x00010000` or `true`).
    NotTrueType,
    /// The table directory is malformed or a table lies out of bounds.
    Directory,
    /// A required table is missing. It names the tag.
    MissingTable(&'static str),
    /// A table is too short or holds a value outside its range. It names
    /// the tag.
    Table(&'static str),
    /// No usable Unicode `cmap` subtable.
    NoUnicodeCmap,
    /// The `OS/2` `fsType` forbids embedding.
    EmbeddingRestricted,
    /// The bytes are not the pinned font of ADR-017.
    NotPinned,
}

impl std::fmt::Display for FontError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "font refused: {self:?}")
    }
}

impl std::error::Error for FontError {}

/// The Unicode mapping the font uses.
#[derive(Clone, Debug)]
enum Cmap {
    /// Format 4: segments of `(end, start, delta, range offset position)`
    /// and the subtable bytes.
    Format4 {
        segments: Vec<(u16, u16, u16, u16, usize)>,
        data: Vec<u8>,
    },
    /// Format 12: groups of `(start, end, first glyph)`.
    Format12 { groups: Vec<(u32, u32, u32)> },
}

/// The metrics and mapping of a parsed TrueType font.
#[derive(Clone, Debug)]
pub struct TrueType {
    /// Font units per em.
    pub units_per_em: u16,
    /// `xMin`, `yMin`, `xMax`, `yMax` from `head`.
    pub bbox: [i16; 4],
    /// Typographic ascender from `hhea`.
    pub ascent: i16,
    /// Typographic descender from `hhea`, negative.
    pub descent: i16,
    /// Cap height from `OS/2` version 2 or later, else the ascender.
    pub cap_height: i16,
    /// The integer part of `post` `italicAngle`.
    pub italic_angle: i16,
    /// The glyph count from `maxp`.
    pub num_glyphs: u16,
    advances: Vec<u16>,
    cmap: Cmap,
}

fn be16(d: &[u8], at: usize) -> Option<u16> {
    let b = d.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([*b.first()?, *b.get(1)?]))
}

fn be32(d: &[u8], at: usize) -> Option<u32> {
    let b = d.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([
        *b.first()?,
        *b.get(1)?,
        *b.get(2)?,
        *b.get(3)?,
    ]))
}

fn i16_at(d: &[u8], at: usize) -> Option<i16> {
    be16(d, at).map(|v| i16::from_be_bytes(v.to_be_bytes()))
}

fn usize32(v: u32) -> Option<usize> {
    usize::try_from(v).ok()
}

/// Returns the bytes of table `tag`, if present.
fn table<'a>(font: &'a [u8], dir: &[([u8; 4], usize, usize)], tag: &[u8; 4]) -> Option<&'a [u8]> {
    let (_, off, len) = dir.iter().find(|(t, _, _)| t == tag)?;
    font.get(*off..off.checked_add(*len)?)
}

fn required<'a>(
    font: &'a [u8],
    dir: &[([u8; 4], usize, usize)],
    tag: &'static str,
) -> Result<&'a [u8], FontError> {
    let mut t = [0u8; 4];
    for (dst, src) in t.iter_mut().zip(tag.bytes()) {
        *dst = src;
    }
    table(font, dir, &t).ok_or(FontError::MissingTable(tag))
}

impl TrueType {
    /// Parses `font`.
    ///
    /// # Errors
    ///
    /// A [`FontError`] naming the first fault found.
    pub fn parse(font: &[u8]) -> Result<TrueType, FontError> {
        if font.len() > MAX_FONT {
            return Err(FontError::TooLarge);
        }
        let version = be32(font, 0).ok_or(FontError::NotTrueType)?;
        if version != 0x0001_0000 && version != 0x7472_7565 {
            return Err(FontError::NotTrueType);
        }
        let num_tables = be16(font, 4).ok_or(FontError::Directory)?;
        if num_tables == 0 || num_tables > MAX_TABLES {
            return Err(FontError::Directory);
        }
        let mut dir = Vec::with_capacity(usize::from(num_tables));
        for i in 0..usize::from(num_tables) {
            let rec = i.checked_mul(16).and_then(|r| r.checked_add(12));
            let rec = rec.ok_or(FontError::Directory)?;
            let tag = font
                .get(rec..rec.saturating_add(4))
                .and_then(|t| <[u8; 4]>::try_from(t).ok())
                .ok_or(FontError::Directory)?;
            let off = be32(font, rec.saturating_add(8))
                .and_then(usize32)
                .ok_or(FontError::Directory)?;
            let len = be32(font, rec.saturating_add(12))
                .and_then(usize32)
                .ok_or(FontError::Directory)?;
            if off.checked_add(len).is_none_or(|e| e > font.len()) {
                return Err(FontError::Directory);
            }
            if dir.iter().any(|(t, _, _)| *t == tag) {
                return Err(FontError::Directory);
            }
            dir.push((tag, off, len));
        }

        let head = required(font, &dir, "head")?;
        let units_per_em = be16(head, 18)
            .filter(|u| (16..=16384).contains(u))
            .ok_or(FontError::Table("head"))?;
        let bbox = [
            i16_at(head, 36).ok_or(FontError::Table("head"))?,
            i16_at(head, 38).ok_or(FontError::Table("head"))?,
            i16_at(head, 40).ok_or(FontError::Table("head"))?,
            i16_at(head, 42).ok_or(FontError::Table("head"))?,
        ];

        let maxp = required(font, &dir, "maxp")?;
        let num_glyphs = be16(maxp, 4)
            .filter(|&n| n > 0)
            .ok_or(FontError::Table("maxp"))?;

        let hhea = required(font, &dir, "hhea")?;
        let ascent = i16_at(hhea, 4).ok_or(FontError::Table("hhea"))?;
        let descent = i16_at(hhea, 6).ok_or(FontError::Table("hhea"))?;
        let n_hmetrics = be16(hhea, 34)
            .filter(|&n| n > 0 && n <= num_glyphs)
            .ok_or(FontError::Table("hhea"))?;

        let hmtx = required(font, &dir, "hmtx")?;
        let need = usize::from(n_hmetrics)
            .checked_mul(4)
            .and_then(|a| {
                usize::from(num_glyphs.saturating_sub(n_hmetrics))
                    .checked_mul(2)
                    .and_then(|b| a.checked_add(b))
            })
            .ok_or(FontError::Table("hmtx"))?;
        if hmtx.len() < need {
            return Err(FontError::Table("hmtx"));
        }
        let mut advances = Vec::with_capacity(usize::from(n_hmetrics));
        for i in 0..usize::from(n_hmetrics) {
            let at = i.checked_mul(4).ok_or(FontError::Table("hmtx"))?;
            advances.push(be16(hmtx, at).ok_or(FontError::Table("hmtx"))?);
        }

        let os2 = required(font, &dir, "OS/2")?;
        let os2_version = be16(os2, 0).ok_or(FontError::Table("OS/2"))?;
        let fs_type = be16(os2, 8).ok_or(FontError::Table("OS/2"))?;
        // Bit 1: restricted licence embedding. Bit 9: bitmap embedding only.
        if fs_type & 0x0202 != 0 {
            return Err(FontError::EmbeddingRestricted);
        }
        let cap_height = if os2_version >= 2 {
            i16_at(os2, 88).ok_or(FontError::Table("OS/2"))?
        } else {
            ascent
        };

        let post = required(font, &dir, "post")?;
        let italic_angle = i16_at(post, 4).ok_or(FontError::Table("post"))?;

        let cmap = parse_cmap(required(font, &dir, "cmap")?)?;

        Ok(TrueType {
            units_per_em,
            bbox,
            ascent,
            descent,
            cap_height,
            italic_angle,
            num_glyphs,
            advances,
            cmap,
        })
    }

    /// The glyph for `c`, or `None` when the font maps it to no glyph.
    #[must_use]
    pub fn glyph(&self, c: char) -> Option<u16> {
        let code = u32::from(c);
        let gid = match &self.cmap {
            Cmap::Format4 { segments, data } => {
                let c16 = u16::try_from(code).ok()?;
                let (end, start, delta, range_offset, ro_pos) =
                    *segments.iter().find(|s| c16 <= s.0)?;
                if c16 < start || c16 > end {
                    return None;
                }
                if range_offset == 0 {
                    c16.wrapping_add(delta)
                } else {
                    let at = ro_pos
                        .checked_add(usize::from(range_offset))?
                        .checked_add(usize::from(c16.checked_sub(start)?).checked_mul(2)?)?;
                    let g = be16(data, at)?;
                    if g == 0 {
                        return None;
                    }
                    g.wrapping_add(delta)
                }
            }
            Cmap::Format12 { groups } => {
                let (start, _, first) = *groups.iter().find(|g| g.0 <= code && code <= g.1)?;
                u16::try_from(first.checked_add(code.checked_sub(start)?)?).ok()?
            }
        };
        (gid != 0 && gid < self.num_glyphs).then_some(gid)
    }

    /// The advance width of glyph `gid` in font units.
    #[must_use]
    pub fn advance(&self, gid: u16) -> u16 {
        self.advances
            .get(usize::from(gid))
            .or(self.advances.last())
            .copied()
            .unwrap_or(0)
    }

    /// `v` font units scaled to the 1000-unit glyph space of PDF.
    #[must_use]
    pub fn to_pdf_units(&self, v: i32) -> i64 {
        i64::from(v)
            .saturating_mul(1000)
            .checked_div(i64::from(self.units_per_em))
            .unwrap_or(0)
    }
}

fn parse_cmap(cmap: &[u8]) -> Result<Cmap, FontError> {
    let count = be16(cmap, 2).ok_or(FontError::Table("cmap"))?;
    let mut fmt4: Option<usize> = None;
    let mut fmt12: Option<usize> = None;
    for i in 0..usize::from(count) {
        let rec = i
            .checked_mul(8)
            .and_then(|r| r.checked_add(4))
            .ok_or(FontError::Table("cmap"))?;
        let platform = be16(cmap, rec).ok_or(FontError::Table("cmap"))?;
        let encoding = be16(cmap, rec.saturating_add(2)).ok_or(FontError::Table("cmap"))?;
        let off = be32(cmap, rec.saturating_add(4))
            .and_then(usize32)
            .ok_or(FontError::Table("cmap"))?;
        match (platform, encoding) {
            (3, 10) | (0, 4) => fmt12 = fmt12.or(Some(off)),
            (3, 1) | (0, 3) => fmt4 = fmt4.or(Some(off)),
            _ => {}
        }
    }
    if let Some(off) = fmt12
        && be16(cmap, off) == Some(12)
    {
        return parse_format12(cmap, off);
    }
    match fmt4 {
        Some(off) if be16(cmap, off) == Some(4) => parse_format4(cmap, off),
        _ => Err(FontError::NoUnicodeCmap),
    }
}

fn parse_format4(cmap: &[u8], off: usize) -> Result<Cmap, FontError> {
    let bad = FontError::Table("cmap");
    let len = usize::from(be16(cmap, off.saturating_add(2)).ok_or(bad)?);
    let data = cmap.get(off..off.checked_add(len).ok_or(bad)?).ok_or(bad)?;
    let seg_x2 = usize::from(be16(data, 6).ok_or(bad)?);
    if seg_x2 == 0 || seg_x2 % 2 != 0 {
        return Err(bad);
    }
    let ends = 14usize;
    let starts = ends
        .checked_add(seg_x2)
        .and_then(|s| s.checked_add(2))
        .ok_or(bad)?;
    let deltas = starts.checked_add(seg_x2).ok_or(bad)?;
    let ranges = deltas.checked_add(seg_x2).ok_or(bad)?;
    if ranges.checked_add(seg_x2).is_none_or(|e| e > data.len()) {
        return Err(bad);
    }
    let mut segments = Vec::with_capacity(seg_x2 / 2);
    let mut last_end: Option<u16> = None;
    for i in (0..seg_x2).step_by(2) {
        let end = be16(data, ends.saturating_add(i)).ok_or(bad)?;
        let start = be16(data, starts.saturating_add(i)).ok_or(bad)?;
        let delta = be16(data, deltas.saturating_add(i)).ok_or(bad)?;
        let ro_pos = ranges.saturating_add(i);
        let range_offset = be16(data, ro_pos).ok_or(bad)?;
        if start > end || last_end.is_some_and(|l| end <= l) {
            return Err(bad);
        }
        last_end = Some(end);
        segments.push((end, start, delta, range_offset, ro_pos));
    }
    if last_end != Some(0xffff) {
        return Err(bad);
    }
    Ok(Cmap::Format4 {
        segments,
        data: data.to_vec(),
    })
}

fn parse_format12(cmap: &[u8], off: usize) -> Result<Cmap, FontError> {
    let bad = FontError::Table("cmap");
    let n = be32(cmap, off.saturating_add(12))
        .and_then(usize32)
        .ok_or(bad)?;
    let avail = cmap.len().saturating_sub(off.saturating_add(16)) / 12;
    if n > avail {
        return Err(bad);
    }
    let mut groups = Vec::with_capacity(n);
    let mut last: Option<u32> = None;
    for i in 0..n {
        let at = i
            .checked_mul(12)
            .and_then(|a| a.checked_add(off))
            .and_then(|a| a.checked_add(16))
            .ok_or(bad)?;
        let start = be32(cmap, at).ok_or(bad)?;
        let end = be32(cmap, at.saturating_add(4)).ok_or(bad)?;
        let first = be32(cmap, at.saturating_add(8)).ok_or(bad)?;
        if start > end || end > 0x10_ffff || last.is_some_and(|l| start <= l) {
            return Err(bad);
        }
        last = Some(end);
        groups.push((start, end, first));
    }
    Ok(Cmap::Format12 { groups })
}

/// Parses [`EMBEDDED_FONT`] after checking it against
/// [`EMBEDDED_FONT_SHA256`].
///
/// # Errors
///
/// [`FontError::NotPinned`] when the bytes differ from the pin, and any
/// parse error.
pub fn embedded_font() -> Result<TrueType, FontError> {
    if fstp_crypto::sha256(EMBEDDED_FONT) != EMBEDDED_FONT_SHA256 {
        return Err(FontError::NotPinned);
    }
    TrueType::parse(EMBEDDED_FONT)
}
