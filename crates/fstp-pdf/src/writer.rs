//! The deterministic PDF writer for contracts and the Guide (M5 design
//! sections 3.1 step 1, 3.3 and 3.4; R-CT-01, R-GA-02).
//!
//! Equal input gives equal bytes. The output has one classic xref table,
//! no object streams, no xref streams and no filters. It embeds the one
//! font of ADR-017 in full as a `CIDFontType2` with `Identity-H`, so every
//! glyph the font has can be shown. It is tagged: a structure tree, marked
//! content, `/MarkInfo` and `/Lang` (design section 3.3).
//!
//! Each signature field is a merged field and widget with a pre-rendered
//! appearance stream. `/SigFlags 3` is set in revision 0, so a signature
//! increment changes no object but the party's field (ADR-016).

use std::collections::{BTreeMap, BTreeSet};

use crate::font::{EMBEDDED_FONT, EMBEDDED_FONT_NAME, FontError, TrueType, embedded_font};
use crate::object::write_hex_string;

/// Page width in points (A4).
pub const PAGE_WIDTH: i64 = 595;
/// Page height in points (A4).
pub const PAGE_HEIGHT: i64 = 842;
/// Margin on every side, in points.
pub const MARGIN: i64 = 72;
/// Width of a signature field, in points.
pub const FIELD_WIDTH: i64 = 240;
/// Height of a signature field, in points.
pub const FIELD_HEIGHT: i64 = 60;
const FIELD_GAP: i64 = 18;
const FIELD_LABEL_SIZE: i64 = 9;
const TEXT_WIDTH: i64 = PAGE_WIDTH - 2 * MARGIN;
const TOP: i64 = PAGE_HEIGHT - MARGIN;

/// Most blocks in one document.
pub const MAX_BLOCKS: usize = 20_000;
/// Most characters in one block.
pub const MAX_BLOCK_CHARS: usize = 100_000;
/// Most signature fields in one document.
pub const MAX_FIELDS: usize = 64;

/// The kind of a block of text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockKind {
    /// A first-level heading, tagged `/H1`.
    Heading1,
    /// A second-level heading, tagged `/H2`.
    Heading2,
    /// A paragraph, tagged `/P`.
    Paragraph,
}

impl BlockKind {
    /// `(font size, leading, space before)` in points, and the structure
    /// type.
    fn style(self) -> (i64, i64, i64, &'static str) {
        match self {
            BlockKind::Heading1 => (18, 24, 12, "H1"),
            BlockKind::Heading2 => (14, 19, 10, "H2"),
            BlockKind::Paragraph => (11, 15, 6, "P"),
        }
    }
}

/// One block of text. Runs of spaces collapse and lines wrap at spaces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// The kind.
    pub kind: BlockKind,
    /// The text, without control characters.
    pub text: String,
}

/// One empty signature field, declared in revision 0 (ADR-016).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureField {
    /// The field name `/T`: 1 to 64 of `A-Z a-z 0-9 _ -`. The increment
    /// verifier finds a party's field by it.
    pub name: String,
    /// The visible label and alternate text, one line at 9 points.
    pub label: String,
}

/// A document to render.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Document {
    /// The title, written to `/Info` and shown by viewers.
    pub title: String,
    /// The natural language, such as `en` or `de-AT`.
    pub lang: String,
    /// The blocks in reading order.
    pub blocks: Vec<Block>,
    /// The signature fields, placed after the text.
    pub signature_fields: Vec<SignatureField>,
}

/// Why a document was not written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The embedded font failed its pin or parse.
    Font(FontError),
    /// The title is empty, too long or holds a control character.
    Title,
    /// The language tag is not 2 to 35 of `A-Z a-z 0-9 -`.
    Lang,
    /// More than [`MAX_BLOCKS`] blocks or [`MAX_FIELDS`] fields.
    TooMany,
    /// Block `index` is blank, too long or holds a control character.
    Text {
        /// The block index.
        index: usize,
    },
    /// The font has no glyph for this character.
    GlyphMissing(char),
    /// Field `index` has a malformed or duplicate name.
    FieldName {
        /// The field index.
        index: usize,
    },
    /// Field `index` has a label that is blank or does not fit one line.
    FieldLabel {
        /// The field index.
        index: usize,
    },
    /// A size or offset computation overflowed.
    Overflow,
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PDF not written: {self:?}")
    }
}

impl std::error::Error for WriteError {}

/// One laid-out line: baseline position, size and glyphs.
struct Line {
    x: i64,
    y: i64,
    size: i64,
    glyphs: Vec<u16>,
}

/// One marked-content sequence: the lines of one block on one page.
struct Run {
    block: usize,
    lines: Vec<Line>,
}

#[derive(Default)]
struct Page {
    runs: Vec<Run>,
    /// `(field index, lower-left y)`.
    widgets: Vec<(usize, i64)>,
}

struct Shaper<'a> {
    font: &'a TrueType,
    used: BTreeMap<u16, char>,
}

impl Shaper<'_> {
    fn glyphs(&mut self, text: &str) -> Result<Vec<u16>, WriteError> {
        text.chars()
            .map(|c| {
                let g = self.font.glyph(c).ok_or(WriteError::GlyphMissing(c))?;
                self.used.entry(g).or_insert(c);
                Ok(g)
            })
            .collect()
    }

    fn width(&self, glyphs: &[u16]) -> i64 {
        glyphs
            .iter()
            .map(|&g| i64::from(self.font.advance(g)))
            .fold(0i64, i64::saturating_add)
    }

    /// Whether `units` font units at `size` points fit `limit` points.
    fn fits(&self, units: i64, size: i64, limit: i64) -> bool {
        units.saturating_mul(size) <= limit.saturating_mul(i64::from(self.font.units_per_em))
    }

    fn wrap(&mut self, text: &str, size: i64) -> Result<Vec<Vec<u16>>, WriteError> {
        let space = self.glyphs(" ")?;
        let space_w = self.width(&space);
        let mut lines = Vec::new();
        let mut cur: Vec<u16> = Vec::new();
        let mut cur_w = 0i64;
        for word in text.split(' ').filter(|w| !w.is_empty()) {
            let glyphs = self.glyphs(word)?;
            let w = self.width(&glyphs);
            if !cur.is_empty() {
                let joined = cur_w.saturating_add(space_w).saturating_add(w);
                if self.fits(joined, size, TEXT_WIDTH) {
                    cur.extend_from_slice(&space);
                    cur.extend_from_slice(&glyphs);
                    cur_w = joined;
                    continue;
                }
                lines.push(std::mem::take(&mut cur));
                cur_w = 0;
            }
            if self.fits(w, size, TEXT_WIDTH) {
                cur = glyphs;
                cur_w = w;
                continue;
            }
            // A word wider than the line breaks between glyphs.
            for g in glyphs {
                let gw = i64::from(self.font.advance(g));
                if !cur.is_empty() && !self.fits(cur_w.saturating_add(gw), size, TEXT_WIDTH) {
                    lines.push(std::mem::take(&mut cur));
                    cur_w = 0;
                }
                cur.push(g);
                cur_w = cur_w.saturating_add(gw);
            }
        }
        if !cur.is_empty() {
            lines.push(cur);
        }
        Ok(lines)
    }
}

fn valid_text(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.chars().count() <= max && !s.chars().any(char::is_control)
}

fn utf16_hex(s: &str) -> Vec<u8> {
    let mut bytes = vec![0xfe, 0xff];
    for unit in s.encode_utf16() {
        bytes.extend_from_slice(&unit.to_be_bytes());
    }
    let mut out = Vec::new();
    write_hex_string(&mut out, &bytes);
    out
}

fn glyph_hex(glyphs: &[u16]) -> String {
    let mut s = String::with_capacity(glyphs.len().saturating_mul(4).saturating_add(2));
    s.push('<');
    for g in glyphs {
        s.push_str(&format!("{g:04X}"));
    }
    s.push('>');
    s
}

fn validate(doc: &Document) -> Result<(), WriteError> {
    if !valid_text(&doc.title, 512) {
        return Err(WriteError::Title);
    }
    let lang_ok = (2..=35).contains(&doc.lang.len())
        && doc
            .lang
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if !lang_ok {
        return Err(WriteError::Lang);
    }
    if doc.blocks.len() > MAX_BLOCKS || doc.signature_fields.len() > MAX_FIELDS {
        return Err(WriteError::TooMany);
    }
    for (index, b) in doc.blocks.iter().enumerate() {
        if !valid_text(&b.text, MAX_BLOCK_CHARS) {
            return Err(WriteError::Text { index });
        }
    }
    let mut names = BTreeSet::new();
    for (index, f) in doc.signature_fields.iter().enumerate() {
        let ok = (1..=64).contains(&f.name.len())
            && f.name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if !ok || !names.insert(f.name.as_str()) {
            return Err(WriteError::FieldName { index });
        }
        if !valid_text(&f.label, 128) {
            return Err(WriteError::FieldLabel { index });
        }
    }
    Ok(())
}

/// Renders `doc` as revision 0.
///
/// # Errors
///
/// A [`WriteError`] naming the first fault in `doc`.
pub fn write(doc: &Document) -> Result<Vec<u8>, WriteError> {
    validate(doc)?;
    let font = embedded_font().map_err(WriteError::Font)?;
    let mut shaper = Shaper {
        font: &font,
        used: BTreeMap::new(),
    };

    // Layout.
    let mut pages: Vec<Page> = vec![Page::default()];
    let mut y = TOP;
    for (bi, block) in doc.blocks.iter().enumerate() {
        let (size, leading, before, _) = block.kind.style();
        let lines = shaper.wrap(&block.text, size)?;
        if y != TOP {
            y = y.saturating_sub(before);
        }
        for glyphs in lines {
            if y.saturating_sub(leading) < MARGIN {
                pages.push(Page::default());
                y = TOP;
            }
            y = y.saturating_sub(leading);
            let page = pages.last_mut().ok_or(WriteError::Overflow)?;
            let line = Line {
                x: MARGIN,
                y,
                size,
                glyphs,
            };
            match page.runs.last_mut() {
                Some(run) if run.block == bi => run.lines.push(line),
                _ => page.runs.push(Run {
                    block: bi,
                    lines: vec![line],
                }),
            }
        }
    }
    let mut labels = Vec::with_capacity(doc.signature_fields.len());
    for (fi, field) in doc.signature_fields.iter().enumerate() {
        let glyphs = shaper.glyphs(&field.label)?;
        let inner = FIELD_WIDTH.saturating_sub(12);
        if !shaper.fits(shaper.width(&glyphs), FIELD_LABEL_SIZE, inner) {
            return Err(WriteError::FieldLabel { index: fi });
        }
        labels.push(glyphs);
        let need = FIELD_GAP.saturating_add(FIELD_HEIGHT);
        if y.saturating_sub(need) < MARGIN {
            pages.push(Page::default());
            y = TOP;
        }
        y = y.saturating_sub(need);
        pages
            .last_mut()
            .ok_or(WriteError::Overflow)?
            .widgets
            .push((fi, y));
    }

    // Object numbers.
    const CATALOG: u32 = 1;
    const PAGES: u32 = 2;
    const TYPE0: u32 = 3;
    const CIDFONT: u32 = 4;
    const DESCRIPTOR: u32 = 5;
    const FONTFILE: u32 = 6;
    const TOUNICODE: u32 = 7;
    const INFO: u32 = 8;
    const STRUCT_ROOT: u32 = 9;
    const DOC_ELEM: u32 = 10;
    let mut next: u32 = 11;
    let mut alloc = || {
        let n = next;
        next = next.saturating_add(1);
        n
    };
    let acroform = (!doc.signature_fields.is_empty()).then(&mut alloc);
    let page_nums: Vec<(u32, u32)> = pages.iter().map(|_| (alloc(), alloc())).collect();
    let block_elems: Vec<u32> = doc.blocks.iter().map(|_| alloc()).collect();
    let field_nums: Vec<(u32, u32, u32)> = doc
        .signature_fields
        .iter()
        .map(|_| (alloc(), alloc(), alloc()))
        .collect();
    let size = next;
    if size >= crate::file::MAX_OBJECT_NUMBER {
        return Err(WriteError::Overflow);
    }

    let mut objs: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let r = |n: u32| format!("{n} 0 R");
    let page_count = pages.len();

    // Where each field sits: page index and lower-left y.
    let mut field_at: BTreeMap<usize, (usize, i64)> = BTreeMap::new();
    for (pi, page) in pages.iter().enumerate() {
        for &(fi, fy) in &page.widgets {
            field_at.insert(fi, (pi, fy));
        }
    }

    // Pages and content.
    let mut parent_tree = String::new();
    let mut block_mcrs: BTreeMap<usize, Vec<(usize, usize)>> = BTreeMap::new();
    for (pi, page) in pages.iter().enumerate() {
        let (pnum, cnum) = *page_nums.get(pi).ok_or(WriteError::Overflow)?;
        let mut content = String::new();
        let mut mcid_elems = Vec::new();
        for (mcid, run) in page.runs.iter().enumerate() {
            let kind = doc.blocks.get(run.block).ok_or(WriteError::Overflow)?.kind;
            let (_, _, _, tag) = kind.style();
            content.push_str(&format!("/{tag} <</MCID {mcid}>> BDC\n"));
            for line in &run.lines {
                content.push_str(&format!(
                    "BT /F1 {} Tf {} {} Td {} Tj ET\n",
                    line.size,
                    line.x,
                    line.y,
                    glyph_hex(&line.glyphs)
                ));
            }
            content.push_str("EMC\n");
            let elem = *block_elems.get(run.block).ok_or(WriteError::Overflow)?;
            mcid_elems.push(r(elem));
            block_mcrs.entry(run.block).or_default().push((pi, mcid));
        }
        parent_tree.push_str(&format!("{pi} [{}] ", mcid_elems.join(" ")));
        let annots: Vec<String> = page
            .widgets
            .iter()
            .filter_map(|&(fi, _)| field_nums.get(fi).map(|f| r(f.0)))
            .collect();
        let annots = if annots.is_empty() {
            String::new()
        } else {
            format!(" /Annots [{}]", annots.join(" "))
        };
        objs.insert(
            pnum,
            format!(
                "<< /Type /Page /Parent {} /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] /Resources << /Font << /F1 {} >> >> /Contents {} /StructParents {pi} /Tabs /S{annots} >>",
                r(PAGES),
                r(TYPE0),
                r(cnum)
            )
            .into_bytes(),
        );
        objs.insert(
            cnum,
            stream(
                &format!("<< /Length {} >>", content.len()),
                content.as_bytes(),
            ),
        );
    }

    // Block structure elements.
    for (bi, block) in doc.blocks.iter().enumerate() {
        let (_, _, _, tag) = block.kind.style();
        let mcrs = block_mcrs.get(&bi).ok_or(WriteError::Overflow)?;
        let first_page = mcrs.first().map(|m| m.0).ok_or(WriteError::Overflow)?;
        let pg = |pi: usize| {
            page_nums
                .get(pi)
                .map(|p| r(p.0))
                .ok_or(WriteError::Overflow)
        };
        let kids: Result<Vec<String>, WriteError> = mcrs
            .iter()
            .map(|&(pi, mcid)| Ok(format!("<< /Type /MCR /Pg {} /MCID {mcid} >>", pg(pi)?)))
            .collect();
        objs.insert(
            *block_elems.get(bi).ok_or(WriteError::Overflow)?,
            format!(
                "<< /Type /StructElem /S /{tag} /P {} /Pg {} /K [{}] >>",
                r(DOC_ELEM),
                pg(first_page)?,
                kids?.join(" ")
            )
            .into_bytes(),
        );
    }

    // Signature fields, appearances and their structure elements.
    let mut form_elems = Vec::new();
    for (fi, field) in doc.signature_fields.iter().enumerate() {
        let (wnum, apnum, elem) = *field_nums.get(fi).ok_or(WriteError::Overflow)?;
        let (pi, fy) = *field_at.get(&fi).ok_or(WriteError::Overflow)?;
        let pref = r(page_nums.get(pi).ok_or(WriteError::Overflow)?.0);
        let key = page_count.saturating_add(fi);
        let label = labels.get(fi).ok_or(WriteError::Overflow)?;
        let ap = format!(
            "0 G 1 w 1 1 {} {} re S BT /F1 {FIELD_LABEL_SIZE} Tf 6 8 Td {} Tj ET\n",
            FIELD_WIDTH.saturating_sub(2),
            FIELD_HEIGHT.saturating_sub(2),
            glyph_hex(label)
        );
        objs.insert(
            apnum,
            stream(
                &format!(
                    "<< /Type /XObject /Subtype /Form /BBox [0 0 {FIELD_WIDTH} {FIELD_HEIGHT}] /Resources << /Font << /F1 {} >> >> /Length {} >>",
                    r(TYPE0),
                    ap.len()
                ),
                ap.as_bytes(),
            ),
        );
        let tu = String::from_utf8_lossy(&utf16_hex(&field.label)).into_owned();
        objs.insert(
            wnum,
            format!(
                "<< /Type /Annot /Subtype /Widget /FT /Sig /T ({}) /TU {tu} /Rect [{MARGIN} {fy} {} {}] /F 4 /P {pref} /AP << /N {} >> /StructParent {key} >>",
                field.name,
                MARGIN.saturating_add(FIELD_WIDTH),
                fy.saturating_add(FIELD_HEIGHT),
                r(apnum)
            )
            .into_bytes(),
        );
        objs.insert(
            elem,
            format!(
                "<< /Type /StructElem /S /Form /P {} /Pg {pref} /Alt {tu} /K << /Type /OBJR /Obj {} /Pg {pref} >> >>",
                r(DOC_ELEM),
                r(wnum)
            )
            .into_bytes(),
        );
        parent_tree.push_str(&format!("{key} {} ", r(elem)));
        form_elems.push(r(elem));
    }

    // Document-level objects.
    let mut doc_kids: Vec<String> = block_elems.iter().map(|&n| r(n)).collect();
    doc_kids.extend(form_elems);
    objs.insert(
        DOC_ELEM,
        format!(
            "<< /Type /StructElem /S /Document /P {} /K [{}] >>",
            r(STRUCT_ROOT),
            doc_kids.join(" ")
        )
        .into_bytes(),
    );
    objs.insert(
        STRUCT_ROOT,
        format!(
            "<< /Type /StructTreeRoot /K {} /ParentTree << /Nums [{}] >> /ParentTreeNextKey {} >>",
            r(DOC_ELEM),
            parent_tree.trim_end(),
            page_count.saturating_add(doc.signature_fields.len())
        )
        .into_bytes(),
    );
    let kids: Vec<String> = page_nums.iter().map(|p| r(p.0)).collect();
    objs.insert(
        PAGES,
        format!(
            "<< /Type /Pages /Kids [{}] /Count {page_count} >>",
            kids.join(" ")
        )
        .into_bytes(),
    );
    let acro = match acroform {
        Some(a) => {
            let fields: Vec<String> = field_nums.iter().map(|f| r(f.0)).collect();
            objs.insert(
                a,
                format!("<< /Fields [{}] /SigFlags 3 >>", fields.join(" ")).into_bytes(),
            );
            format!(" /AcroForm {}", r(a))
        }
        None => String::new(),
    };
    objs.insert(
        CATALOG,
        format!(
            "<< /Type /Catalog /Pages {} /StructTreeRoot {} /MarkInfo << /Marked true >> /Lang ({}) /ViewerPreferences << /DisplayDocTitle true >>{acro} >>",
            r(PAGES),
            r(STRUCT_ROOT),
            doc.lang
        )
        .into_bytes(),
    );
    let title = String::from_utf8_lossy(&utf16_hex(&doc.title)).into_owned();
    objs.insert(
        INFO,
        format!("<< /Title {title} /Producer (fstp-pdf) >>").into_bytes(),
    );

    // Fonts.
    objs.insert(
        TYPE0,
        format!(
            "<< /Type /Font /Subtype /Type0 /BaseFont /{EMBEDDED_FONT_NAME} /Encoding /Identity-H /DescendantFonts [{}] /ToUnicode {} >>",
            r(CIDFONT),
            r(TOUNICODE)
        )
        .into_bytes(),
    );
    let widths: Vec<String> = shaper
        .used
        .keys()
        .map(|&g| format!("{g} [{}]", font.to_pdf_units(i32::from(font.advance(g)))))
        .collect();
    objs.insert(
        CIDFONT,
        format!(
            "<< /Type /Font /Subtype /CIDFontType2 /BaseFont /{EMBEDDED_FONT_NAME} /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor {} /CIDToGIDMap /Identity /DW 1000 /W [{}] >>",
            r(DESCRIPTOR),
            widths.join(" ")
        )
        .into_bytes(),
    );
    let u = |v: i16| font.to_pdf_units(i32::from(v));
    objs.insert(
        DESCRIPTOR,
        format!(
            "<< /Type /FontDescriptor /FontName /{EMBEDDED_FONT_NAME} /Flags 32 /FontBBox [{} {} {} {}] /ItalicAngle {} /Ascent {} /Descent {} /CapHeight {} /StemV 80 /FontFile2 {} >>",
            u(font.bbox[0]),
            u(font.bbox[1]),
            u(font.bbox[2]),
            u(font.bbox[3]),
            font.italic_angle,
            u(font.ascent),
            u(font.descent),
            u(font.cap_height),
            r(FONTFILE)
        )
        .into_bytes(),
    );
    objs.insert(
        FONTFILE,
        stream(
            &format!("<< /Length {0} /Length1 {0} >>", EMBEDDED_FONT.len()),
            EMBEDDED_FONT,
        ),
    );
    let cmap = to_unicode(&shaper.used);
    objs.insert(
        TOUNICODE,
        stream(&format!("<< /Length {} >>", cmap.len()), cmap.as_bytes()),
    );

    assemble(&objs, size)
}

fn stream(dict: &str, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len().saturating_add(dict.len()).saturating_add(32));
    out.extend_from_slice(dict.as_bytes());
    out.extend_from_slice(b"\nstream\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\nendstream");
    out
}

fn to_unicode(used: &BTreeMap<u16, char>) -> String {
    let mut s = String::from(
        "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n/CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n",
    );
    let entries: Vec<(&u16, &char)> = used.iter().collect();
    for chunk in entries.chunks(100) {
        s.push_str(&format!("{} beginbfchar\n", chunk.len()));
        for (g, c) in chunk {
            let mut units = [0u16; 2];
            let hex: String = c
                .encode_utf16(&mut units)
                .iter()
                .map(|u| format!("{u:04X}"))
                .collect();
            s.push_str(&format!("<{g:04X}> <{hex}>\n"));
        }
        s.push_str("endbfchar\n");
    }
    s.push_str("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n");
    s
}

fn assemble(objs: &BTreeMap<u32, Vec<u8>>, size: u32) -> Result<Vec<u8>, WriteError> {
    let body_len: usize = objs.values().map(Vec::len).fold(0, usize::saturating_add);
    let mut out = Vec::with_capacity(body_len.saturating_add(4096));
    out.extend_from_slice(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n");
    let mut offsets = Vec::with_capacity(objs.len());
    for num in 1..size {
        let body = objs.get(&num).ok_or(WriteError::Overflow)?;
        offsets.push(out.len());
        out.extend_from_slice(format!("{num} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    let digest = fstp_crypto::sha256(&out);
    let mut id = Vec::new();
    write_hex_string(&mut id, digest.get(..16).ok_or(WriteError::Overflow)?);
    let id = String::from_utf8_lossy(&id).into_owned();
    out.extend_from_slice(format!("xref\n0 {size}\n0000000000 65535 f \n").as_bytes());
    for off in offsets {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {size} /Root 1 0 R /Info 8 0 R /ID [{id} {id}] >>\nstartxref\n{xref}\n%%EOF\n"
        )
        .as_bytes(),
    );
    Ok(out)
}
