//! Reading a stored PDF revision: header, `startxref`, the classic xref
//! tables along the `/Prev` chain, the trailer and objects by number.
//!
//! Xref streams, object streams and encrypted files are refused. The
//! platform writes none of them (M5 design section 3.1, step 1).

use std::collections::{BTreeMap, BTreeSet};

use crate::object::{Dict, Object, ParseError, ParseErrorKind, Parser, Ref};

/// Largest file the reader accepts, in bytes.
pub const MAX_FILE: usize = 64 * 1024 * 1024;
/// Longest `/Prev` chain the reader follows.
pub const MAX_XREF_CHAIN: usize = 256;
/// Largest object number the reader accepts.
pub const MAX_OBJECT_NUMBER: u32 = 8_000_000;
/// How far from the end the reader looks for `startxref`.
const TAIL_WINDOW: usize = 1024;

/// One in-use xref entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XrefEntry {
    /// The byte offset of `num gen obj`.
    pub offset: usize,
    /// The generation number.
    pub generation: u16,
    /// Whether the entry is in use (`n`) rather than free (`f`).
    pub in_use: bool,
}

/// One xref section and the trailer that follows it.
#[derive(Clone, Debug)]
pub struct XrefSection {
    /// The entries in input order, by object number.
    pub entries: Vec<(u32, XrefEntry)>,
    /// The trailer dictionary.
    pub trailer: Dict,
    /// The offset just after the trailer dictionary.
    pub end: usize,
}

/// A parsed PDF file with every revision's xref merged.
#[derive(Clone, Debug)]
pub struct PdfFile<'a> {
    bytes: &'a [u8],
    xref: BTreeMap<u32, XrefEntry>,
    trailer: Dict,
    startxref: usize,
}

fn err(offset: usize, kind: ParseErrorKind) -> ParseError {
    ParseError { offset, kind }
}

/// Reads the xref section at `offset` of `buf`: `xref`, its subsections
/// and the trailer dictionary.
///
/// # Errors
///
/// [`ParseErrorKind::XrefStream`] when `offset` does not hold `xref`, and
/// the other kinds for malformed entries or trailers.
pub fn read_xref_section(buf: &[u8], offset: usize) -> Result<XrefSection, ParseError> {
    let mut p = Parser::new(buf, offset);
    if !p.at_keyword(b"xref") {
        return Err(err(offset, ParseErrorKind::XrefStream));
    }
    p.keyword("xref")?;
    let mut entries = Vec::new();
    loop {
        p.skip_ws()?;
        if p.at_keyword(b"trailer") {
            break;
        }
        let first = p.uint()?;
        let count = p.uint()?;
        let first = u32::try_from(first).map_err(|_| p.err(ParseErrorKind::XrefEntry))?;
        let count = u32::try_from(count).map_err(|_| p.err(ParseErrorKind::XrefEntry))?;
        let last = first
            .checked_add(count)
            .filter(|&l| l <= MAX_OBJECT_NUMBER)
            .ok_or(p.err(ParseErrorKind::XrefEntry))?;
        p.skip_ws()?;
        let mut pos = p.pos();
        for num in first..last {
            let end = pos
                .checked_add(20)
                .ok_or(err(pos, ParseErrorKind::XrefEntry))?;
            let line = buf
                .get(pos..end)
                .ok_or(err(pos, ParseErrorKind::UnexpectedEnd))?;
            let entry = xref_line(line).ok_or(err(pos, ParseErrorKind::XrefEntry))?;
            entries.push((num, entry));
            pos = end;
        }
        p = Parser::new(buf, pos);
    }
    p.keyword("trailer")?;
    let trailer = match p.object()? {
        Object::Dict(d) => d,
        _ => return Err(p.err(ParseErrorKind::Trailer)),
    };
    if trailer.get(b"Encrypt").is_some() || trailer.get(b"XRefStm").is_some() {
        return Err(p.err(ParseErrorKind::Trailer));
    }
    Ok(XrefSection {
        entries,
        trailer,
        end: p.pos(),
    })
}

/// One 20-byte xref line: `nnnnnnnnnn ggggg n` and a two-byte end of line.
fn xref_line(line: &[u8]) -> Option<XrefEntry> {
    let (offset, rest) = line.split_at_checked(10)?;
    let (sp1, rest) = rest.split_first()?;
    let (generation, rest) = rest.split_at_checked(5)?;
    let (sp2, rest) = rest.split_first()?;
    let (kind, eol) = rest.split_first()?;
    if *sp1 != b' ' || *sp2 != b' ' || !matches!(eol, b" \n" | b" \r" | b"\r\n") {
        return None;
    }
    let in_use = match kind {
        b'n' => true,
        b'f' => false,
        _ => return None,
    };
    Some(XrefEntry {
        offset: usize::try_from(digits(offset)?).ok()?,
        generation: u16::try_from(digits(generation)?).ok()?,
        in_use,
    })
}

fn digits(d: &[u8]) -> Option<u64> {
    d.iter().try_fold(0u64, |v, &b| {
        let b = b.checked_sub(b'0').filter(|b| *b <= 9)?;
        v.checked_mul(10)?.checked_add(u64::from(b))
    })
}

/// Reads the `startxref` offset, `%%EOF` and one optional end of line
/// that end a file, starting at `pos`. Returns the offset.
///
/// # Errors
///
/// [`ParseErrorKind::Tail`] for anything else, including trailing bytes.
pub fn read_tail(buf: &[u8], pos: usize) -> Result<usize, ParseError> {
    let mut p = Parser::new(buf, pos);
    p.keyword("startxref")
        .map_err(|_| err(pos, ParseErrorKind::Tail))?;
    let offset = p.uint().map_err(|_| err(pos, ParseErrorKind::Tail))?;
    // `%%EOF` is a comment, so it is matched by hand.
    let mut at = p.pos();
    while buf
        .get(at)
        .is_some_and(|&b| matches!(b, b'\r' | b'\n' | b' '))
    {
        at = at.saturating_add(1);
    }
    let end = at.saturating_add(5);
    if buf.get(at..end) != Some(b"%%EOF".as_slice()) {
        return Err(err(at, ParseErrorKind::Tail));
    }
    let rest = buf.get(end..).unwrap_or_default();
    if !matches!(rest, b"" | b"\n" | b"\r\n" | b"\r") {
        return Err(err(end, ParseErrorKind::Tail));
    }
    usize::try_from(offset).map_err(|_| err(pos, ParseErrorKind::Tail))
}

/// The position of the last `startxref` keyword in the tail of `buf`.
fn find_startxref(buf: &[u8]) -> Option<usize> {
    let from = buf.len().saturating_sub(TAIL_WINDOW);
    let window = buf.get(from..)?;
    let at = window.windows(9).rposition(|w| w == b"startxref")?;
    from.checked_add(at)
}

impl<'a> PdfFile<'a> {
    /// Parses the header, the tail and every xref section of `bytes`.
    ///
    /// # Errors
    ///
    /// Any [`ParseErrorKind`]: a missing header or tail, an xref stream,
    /// a looping or overlong `/Prev` chain, or an encrypted file.
    pub fn open(bytes: &'a [u8]) -> Result<PdfFile<'a>, ParseError> {
        if bytes.len() > MAX_FILE {
            return Err(err(0, ParseErrorKind::TooLarge));
        }
        let header = bytes.get(..8).ok_or(err(0, ParseErrorKind::Header))?;
        if !header.starts_with(b"%PDF-1.") || !header.get(7).is_some_and(u8::is_ascii_digit) {
            return Err(err(0, ParseErrorKind::Header));
        }
        let tail = find_startxref(bytes).ok_or(err(bytes.len(), ParseErrorKind::Tail))?;
        let startxref = read_tail(bytes, tail)?;
        let mut xref = BTreeMap::new();
        let mut trailer: Option<Dict> = None;
        let mut seen = BTreeSet::new();
        let mut next = Some(startxref);
        while let Some(offset) = next {
            if !seen.insert(offset) || seen.len() > MAX_XREF_CHAIN || offset >= tail {
                return Err(err(offset, ParseErrorKind::XrefChain));
            }
            let section = read_xref_section(bytes, offset)?;
            for (num, entry) in section.entries {
                if entry.in_use && entry.offset >= bytes.len() {
                    return Err(err(offset, ParseErrorKind::XrefEntry));
                }
                xref.entry(num).or_insert(entry);
            }
            next = match section.trailer.get(b"Prev") {
                None => None,
                Some(Object::Int(p)) => {
                    Some(usize::try_from(*p).map_err(|_| err(offset, ParseErrorKind::Trailer))?)
                }
                Some(_) => return Err(err(offset, ParseErrorKind::Trailer)),
            };
            if trailer.is_none() {
                trailer = Some(section.trailer);
            }
        }
        let trailer = trailer.ok_or(err(startxref, ParseErrorKind::Trailer))?;
        let size = trailer
            .int(b"Size")
            .and_then(|s| u32::try_from(s).ok())
            .filter(|&s| s <= MAX_OBJECT_NUMBER)
            .ok_or(err(startxref, ParseErrorKind::Trailer))?;
        if trailer.reference(b"Root").is_none() || xref.keys().any(|&n| n >= size) {
            return Err(err(startxref, ParseErrorKind::Trailer));
        }
        Ok(PdfFile {
            bytes,
            xref,
            trailer,
            startxref,
        })
    }

    /// The file bytes.
    #[must_use]
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The newest trailer.
    #[must_use]
    pub fn trailer(&self) -> &Dict {
        &self.trailer
    }

    /// The offset the final `startxref` names.
    #[must_use]
    pub fn startxref(&self) -> usize {
        self.startxref
    }

    /// The newest trailer's `/Size`.
    #[must_use]
    pub fn size(&self) -> u32 {
        self.trailer
            .int(b"Size")
            .and_then(|s| u32::try_from(s).ok())
            .unwrap_or(0)
    }

    /// The catalog reference.
    #[must_use]
    pub fn root(&self) -> Option<Ref> {
        self.trailer.reference(b"Root")
    }

    /// The merged xref: object number to its newest entry.
    #[must_use]
    pub fn xref(&self) -> &BTreeMap<u32, XrefEntry> {
        &self.xref
    }

    /// Parses the object `r` names.
    ///
    /// # Errors
    ///
    /// [`ParseErrorKind::ObjectMissing`] when no in-use entry has that
    /// number and generation, or the object there carries another header.
    pub fn get(&self, r: Ref) -> Result<Object, ParseError> {
        let entry = self
            .xref
            .get(&r.num)
            .filter(|e| e.in_use && e.generation == r.generation)
            .ok_or(err(0, ParseErrorKind::ObjectMissing))?;
        let mut p = Parser::new(self.bytes, entry.offset);
        let (found, obj) = p.indirect()?;
        if found != r {
            return Err(err(entry.offset, ParseErrorKind::ObjectMissing));
        }
        Ok(obj)
    }

    /// The dictionary `r` names, or the dictionary of the stream it names.
    ///
    /// # Errors
    ///
    /// As [`PdfFile::get`], and [`ParseErrorKind::ObjectMissing`] when the
    /// object is neither.
    pub fn dict(&self, r: Ref) -> Result<Dict, ParseError> {
        match self.get(r)? {
            Object::Dict(d) => Ok(d),
            Object::Stream(s) => Ok(s.dict),
            _ => Err(err(0, ParseErrorKind::ObjectMissing)),
        }
    }

    /// Parses every in-use object. Tests and fuzz targets use it to check
    /// that a whole file reads back.
    ///
    /// # Errors
    ///
    /// The first object that fails to parse.
    pub fn parse_all(&self) -> Result<Vec<(Ref, Object)>, ParseError> {
        self.xref
            .iter()
            .filter(|(_, e)| e.in_use)
            .map(|(&num, e)| {
                let r = Ref {
                    num,
                    generation: e.generation,
                };
                self.get(r).map(|o| (r, o))
            })
            .collect()
    }
}
