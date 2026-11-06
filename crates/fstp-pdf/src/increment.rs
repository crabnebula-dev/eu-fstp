//! The strict signature increment verifier (ADR-016, M5 design section
//! 3.1 step 4; I-30).
//!
//! The browser sends only the bytes it appends to the stored revision.
//! The server concatenates them, so the prefix is exact by construction.
//! [`verify_increment`] then accepts exactly one shape:
//!
//! 1. the party's field object, unchanged except for a new `/V` that
//!    references the new signature dictionary;
//! 2. one new signature dictionary, numbered with the stored `/Size`,
//!    holding `/Type /Sig`, `/Filter /Adobe.PPKLite`, `/SubFilter
//!    /ETSI.CAdES.detached`, a `/ByteRange`, a zero-filled `/Contents`
//!    placeholder and optionally `/M`;
//! 3. one classic xref section with exactly those two entries;
//! 4. a trailer whose `/Size`, `/Root`, `/Prev` and first `/ID` match the
//!    stored revision, then `startxref` and `%%EOF`.
//!
//! The objects may come in either order, with any white space between
//! tokens. Comments, other objects, streams, a second update and trailing
//! bytes are refused, each with its own [`IncrementError`]. The
//! `/ByteRange` must cover every byte except the `/Contents` string. Its
//! digest is computed through `fstp-crypto` (aws-lc-rs).

use std::ops::Range;

use crate::file::{PdfFile, read_tail, read_xref_section};
use crate::object::{Dict, Object, ParseError, ParseErrorKind, Parser, Ref, write_hex_string};

/// Largest increment accepted, in bytes.
pub const MAX_INCREMENT: usize = 256 * 1024;
/// Smallest `/Contents` placeholder, in bytes of signature.
pub const CONTENTS_MIN: usize = 1024;
/// Largest `/Contents` placeholder, in bytes of signature.
pub const CONTENTS_MAX: usize = 65_536;
/// Most indirect objects read from an increment before refusing it.
const MAX_INCREMENT_OBJECTS: usize = 2;

/// Which of the two expected objects is missing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expected {
    /// The party's updated field object.
    Field,
    /// The new signature dictionary.
    Signature,
}

/// Why an increment was refused. Each attack class of ADR-016 has its
/// own variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncrementError {
    /// The increment or the stored revision is too large.
    TooLarge,
    /// The stored revision does not parse.
    Base(ParseError),
    /// The increment does not parse, or holds a comment.
    Parse(ParseError),
    /// The stored revision has no signature field with the party's name.
    FieldNotFound,
    /// The party's field already has a value.
    FieldAlreadySigned,
    /// An object number appears twice in the increment.
    DuplicateObject {
        /// The repeated number.
        number: u32,
    },
    /// The increment holds an object other than the party's field and the
    /// new signature dictionary: a shadow or other-field change.
    ObjectOutsideField {
        /// The object number.
        number: u32,
    },
    /// An object carries another generation than the stored one.
    GenerationMismatch {
        /// The object number.
        number: u32,
    },
    /// One of the two expected objects is missing.
    MissingObject(Expected),
    /// The increment holds a stream, such as an object or xref stream.
    StreamInIncrement,
    /// The field object changed beyond the new `/V`. It names the key.
    FieldChanged,
    /// The field's `/V` is not a reference to the new signature dictionary.
    FieldValue,
    /// The signature dictionary is malformed. It names the key.
    SignatureDictionary(&'static str),
    /// `/Contents` is not a zero-filled hexadecimal placeholder of
    /// [`CONTENTS_MIN`] to [`CONTENTS_MAX`] bytes.
    ContentsPlaceholder,
    /// `/ByteRange` is not four non-negative integers.
    ByteRangeMalformed,
    /// `/ByteRange` leaves out bytes other than `/Contents`.
    ByteRangeGap,
    /// `/ByteRange` covers part of `/Contents`, or its two ranges overlap.
    ByteRangeOverlap,
    /// `/ByteRange` reaches past the end of the file.
    ByteRangeBeyondEnd,
    /// No classic xref section follows the objects.
    XrefStream,
    /// The xref section does not list exactly the two objects at their
    /// offsets.
    XrefMismatch,
    /// The trailer's `/Size`, `/Root`, `/Prev`, `/ID` or `/Info` do not
    /// match, or it holds another key. It names the key.
    Trailer(&'static str),
    /// `startxref` does not name the increment's xref section.
    StartXref,
    /// Bytes follow `%%EOF`, such as a second update, or the tail is
    /// malformed.
    TrailingBytes,
    /// The signature value does not fit the placeholder.
    SignatureTooLarge,
    /// The placeholder to fill is not the verified, zero-filled one.
    PlaceholderMismatch,
}

impl std::fmt::Display for IncrementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "signature increment refused: {self:?}")
    }
}

impl std::error::Error for IncrementError {}

/// An increment that passed [`verify_increment`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedIncrement {
    /// The `/ByteRange` values.
    pub byte_range: [u64; 4],
    /// The SHA-256 of the bytes the `/ByteRange` covers.
    pub digest: [u8; 32],
    /// The byte range of the `/Contents` string, delimiters included, in
    /// the concatenated revision.
    pub contents: Range<usize>,
    /// The length of the concatenated revision.
    pub total_len: usize,
    /// The party's field object.
    pub field: Ref,
    /// The new signature dictionary.
    pub signature: Ref,
}

/// The party's signature field in `file`: its reference and dictionary.
fn party_field(file: &PdfFile<'_>, party: &str) -> Result<(Ref, Dict), IncrementError> {
    let root = file.root().ok_or(IncrementError::FieldNotFound)?;
    let catalog = file.dict(root).map_err(IncrementError::Base)?;
    let acro = match catalog.get(b"AcroForm") {
        Some(Object::Ref(r)) => file.dict(*r).map_err(IncrementError::Base)?,
        Some(Object::Dict(d)) => d.clone(),
        _ => return Err(IncrementError::FieldNotFound),
    };
    let Some(Object::Array(fields)) = acro.get(b"Fields") else {
        return Err(IncrementError::FieldNotFound);
    };
    let mut found = None;
    for f in fields {
        let Object::Ref(r) = f else { continue };
        let dict = file.dict(*r).map_err(IncrementError::Base)?;
        let named =
            matches!(dict.get(b"T"), Some(Object::String(s)) if s.bytes == party.as_bytes());
        if named && dict.name(b"FT") == Some(b"Sig".as_slice()) && dict.get(b"Kids").is_none() {
            if found.is_some() {
                return Err(IncrementError::FieldNotFound);
            }
            found = Some((*r, dict));
        }
    }
    found.ok_or(IncrementError::FieldNotFound)
}

fn check_field(old: &Dict, new: &Object, signature: Ref) -> Result<(), IncrementError> {
    let Object::Dict(new) = new else {
        return Err(IncrementError::FieldChanged);
    };
    if new.reference(b"V") != Some(signature) {
        return Err(IncrementError::FieldValue);
    }
    let same_keys = new.len() == old.len().saturating_add(1);
    let same_values = old.entries().iter().all(|(k, v)| new.get(k) == Some(v));
    if !same_keys || !same_values {
        return Err(IncrementError::FieldChanged);
    }
    Ok(())
}

/// The `/Contents` span and the `/ByteRange` of a signature dictionary.
fn check_signature(sig: &Object) -> Result<(Range<usize>, [u64; 4]), IncrementError> {
    let Object::Dict(d) = sig else {
        return Err(IncrementError::SignatureDictionary("Type"));
    };
    for (k, _) in d.entries() {
        if !matches!(
            k.as_slice(),
            b"Type" | b"Filter" | b"SubFilter" | b"ByteRange" | b"Contents" | b"M"
        ) {
            return Err(IncrementError::SignatureDictionary("unknown key"));
        }
    }
    if d.name(b"Type") != Some(b"Sig".as_slice()) {
        return Err(IncrementError::SignatureDictionary("Type"));
    }
    if d.name(b"Filter") != Some(b"Adobe.PPKLite".as_slice()) {
        return Err(IncrementError::SignatureDictionary("Filter"));
    }
    if d.name(b"SubFilter") != Some(b"ETSI.CAdES.detached".as_slice()) {
        return Err(IncrementError::SignatureDictionary("SubFilter"));
    }
    if let Some(m) = d.get(b"M")
        && !matches!(m, Object::String(s) if s.bytes.len() <= 64)
    {
        return Err(IncrementError::SignatureDictionary("M"));
    }
    let Some(Object::String(contents)) = d.get(b"Contents") else {
        return Err(IncrementError::ContentsPlaceholder);
    };
    let hex_len = contents.span.len().saturating_sub(2);
    let placeholder = contents.hex
        && contents.bytes.iter().all(|&b| b == 0)
        && hex_len == contents.bytes.len().saturating_mul(2)
        && (CONTENTS_MIN..=CONTENTS_MAX).contains(&contents.bytes.len());
    if !placeholder {
        return Err(IncrementError::ContentsPlaceholder);
    }
    let Some(Object::Array(br)) = d.get(b"ByteRange") else {
        return Err(IncrementError::ByteRangeMalformed);
    };
    let mut range = [0u64; 4];
    if br.len() != 4 {
        return Err(IncrementError::ByteRangeMalformed);
    }
    for (slot, v) in range.iter_mut().zip(br) {
        *slot = match v {
            Object::Int(i) => u64::try_from(*i).map_err(|_| IncrementError::ByteRangeMalformed)?,
            _ => return Err(IncrementError::ByteRangeMalformed),
        };
    }
    Ok((contents.span.clone(), range))
}

fn check_byte_range(
    br: [u64; 4],
    contents: &Range<usize>,
    total: usize,
) -> Result<(), IncrementError> {
    let [a, b, c, d] = br;
    let start = u64::try_from(contents.start).map_err(|_| IncrementError::ByteRangeMalformed)?;
    let end = u64::try_from(contents.end).map_err(|_| IncrementError::ByteRangeMalformed)?;
    let total = u64::try_from(total).map_err(|_| IncrementError::ByteRangeMalformed)?;
    let first_end = a.checked_add(b).ok_or(IncrementError::ByteRangeBeyondEnd)?;
    let second_end = c.checked_add(d).ok_or(IncrementError::ByteRangeBeyondEnd)?;
    if first_end > total || second_end > total {
        return Err(IncrementError::ByteRangeBeyondEnd);
    }
    if c < first_end || first_end > start || c < end {
        return Err(IncrementError::ByteRangeOverlap);
    }
    if a != 0 || first_end != start || c != end || second_end != total {
        return Err(IncrementError::ByteRangeGap);
    }
    Ok(())
}

/// Verifies `increment` against the stored revision `base` for the
/// signature field named `party`.
///
/// # Errors
///
/// An [`IncrementError`] naming the first fault. Nothing is accepted
/// beyond the shape in the module documentation.
pub fn verify_increment(
    base: &[u8],
    increment: &[u8],
    party: &str,
) -> Result<VerifiedIncrement, IncrementError> {
    if increment.len() > MAX_INCREMENT {
        return Err(IncrementError::TooLarge);
    }
    let file = PdfFile::open(base).map_err(IncrementError::Base)?;
    let (field_ref, field_dict) = party_field(&file, party)?;
    if field_dict.get(b"V").is_some() {
        return Err(IncrementError::FieldAlreadySigned);
    }
    let sig_ref = Ref {
        num: file.size(),
        generation: 0,
    };

    let mut full = Vec::with_capacity(base.len().saturating_add(increment.len()));
    full.extend_from_slice(base);
    full.extend_from_slice(increment);
    let total = full.len();
    let mut p = Parser::new(&full, base.len());

    let mut field_obj: Option<(usize, Object)> = None;
    let mut sig_obj: Option<(usize, Object)> = None;
    let mut seen: Vec<u32> = Vec::new();
    loop {
        p.skip_ws().map_err(IncrementError::Parse)?;
        if p.at_keyword(b"xref") {
            break;
        }
        if p.at_keyword(b"startxref") || p.at_end() {
            return Err(IncrementError::XrefStream);
        }
        let offset = p.pos();
        let (r, obj) = p.indirect().map_err(IncrementError::Parse)?;
        if seen.contains(&r.num) {
            return Err(IncrementError::DuplicateObject { number: r.num });
        }
        seen.push(r.num);
        if matches!(obj, Object::Stream(_)) {
            return Err(IncrementError::StreamInIncrement);
        }
        if r.num == field_ref.num {
            if r.generation != field_ref.generation {
                return Err(IncrementError::GenerationMismatch { number: r.num });
            }
            field_obj = Some((offset, obj));
        } else if r.num == sig_ref.num {
            if r.generation != 0 {
                return Err(IncrementError::GenerationMismatch { number: r.num });
            }
            sig_obj = Some((offset, obj));
        } else {
            return Err(IncrementError::ObjectOutsideField { number: r.num });
        }
        if seen.len() > MAX_INCREMENT_OBJECTS {
            return Err(IncrementError::ObjectOutsideField { number: r.num });
        }
    }
    let (field_off, field_new) = field_obj.ok_or(IncrementError::MissingObject(Expected::Field))?;
    let (sig_off, sig_new) = sig_obj.ok_or(IncrementError::MissingObject(Expected::Signature))?;
    check_field(&field_dict, &field_new, sig_ref)?;
    let (contents, byte_range) = check_signature(&sig_new)?;

    // The xref section.
    let xref_off = p.pos();
    let section = read_xref_section(&full, xref_off).map_err(|e| match e.kind {
        ParseErrorKind::Trailer => IncrementError::Trailer("dictionary"),
        _ => IncrementError::XrefMismatch,
    })?;
    let mut entries = section.entries.clone();
    entries.sort_by_key(|e| e.0);
    let mut expected = vec![
        (field_ref.num, field_off, field_ref.generation),
        (sig_ref.num, sig_off, 0),
    ];
    expected.sort_by_key(|e| e.0);
    let matches = entries.len() == 2
        && entries.iter().zip(&expected).all(|((n, e), (en, eo, eg))| {
            n == en && e.in_use && e.offset == *eo && e.generation == *eg
        });
    if !matches {
        return Err(IncrementError::XrefMismatch);
    }

    // The trailer.
    let t = &section.trailer;
    for (k, _) in t.entries() {
        if !matches!(k.as_slice(), b"Size" | b"Root" | b"Prev" | b"ID" | b"Info") {
            return Err(IncrementError::Trailer("unknown key"));
        }
    }
    let size_ok = t
        .int(b"Size")
        .is_some_and(|s| i64::from(sig_ref.num).checked_add(1) == Some(s));
    if !size_ok {
        return Err(IncrementError::Trailer("Size"));
    }
    if t.reference(b"Root") != file.root() {
        return Err(IncrementError::Trailer("Root"));
    }
    let prev_ok = t
        .int(b"Prev")
        .and_then(|v| usize::try_from(v).ok())
        .is_some_and(|v| v == file.startxref());
    if !prev_ok {
        return Err(IncrementError::Trailer("Prev"));
    }
    match (file.trailer().get(b"ID"), t.get(b"ID")) {
        (None, None) => {}
        (Some(Object::Array(old)), Some(Object::Array(new))) => {
            let ok = new.len() == 2
                && new.first() == old.first()
                && matches!(new.get(1), Some(Object::String(s)) if s.bytes.len() <= 64);
            if !ok {
                return Err(IncrementError::Trailer("ID"));
            }
        }
        _ => return Err(IncrementError::Trailer("ID")),
    }
    if let Some(info) = t.get(b"Info")
        && file.trailer().get(b"Info") != Some(info)
    {
        return Err(IncrementError::Trailer("Info"));
    }

    // The tail.
    let mut tail = Parser::new(&full, section.end);
    tail.skip_ws().map_err(|_| IncrementError::TrailingBytes)?;
    let named = read_tail(&full, tail.pos()).map_err(|e| {
        if e.offset > tail.pos() {
            IncrementError::TrailingBytes
        } else {
            IncrementError::StartXref
        }
    })?;
    if named != xref_off {
        return Err(IncrementError::StartXref);
    }

    check_byte_range(byte_range, &contents, total)?;
    let mut h = fstp_crypto::Sha256::new();
    h.update(full.get(..contents.start).unwrap_or_default());
    h.update(full.get(contents.end..).unwrap_or_default());
    Ok(VerifiedIncrement {
        byte_range,
        digest: h.finish(),
        contents,
        total_len: total,
        field: field_ref,
        signature: sig_ref,
    })
}

/// Writes the canonical increment for the field named `party`, with a
/// `/Contents` placeholder of `capacity` bytes. Seals use it in place of
/// the browser (M5 design section 3.1), and its output is the shape
/// [`verify_increment`] accepts.
///
/// # Errors
///
/// [`IncrementError::Base`], [`IncrementError::FieldNotFound`] or
/// [`IncrementError::FieldAlreadySigned`] for the stored revision, and
/// [`IncrementError::ContentsPlaceholder`] for a capacity out of range.
pub fn prepare_increment(
    base: &[u8],
    party: &str,
    capacity: usize,
) -> Result<Vec<u8>, IncrementError> {
    if !(CONTENTS_MIN..=CONTENTS_MAX).contains(&capacity) {
        return Err(IncrementError::ContentsPlaceholder);
    }
    let file = PdfFile::open(base).map_err(IncrementError::Base)?;
    let (field_ref, mut field) = party_field(&file, party)?;
    if field.get(b"V").is_some() {
        return Err(IncrementError::FieldAlreadySigned);
    }
    let sig_num = file.size();
    let root = file.root().ok_or(IncrementError::FieldNotFound)?;
    field.set(
        b"V",
        Object::Ref(Ref {
            num: sig_num,
            generation: 0,
        }),
    );
    let base_len = base.len();
    let mut inc: Vec<u8> = Vec::new();
    let at = |inc: &Vec<u8>| base_len.saturating_add(inc.len());

    let field_off = at(&inc);
    inc.extend_from_slice(format!("{} {} obj\n", field_ref.num, field_ref.generation).as_bytes());
    if !Object::Dict(field).write_to(&mut inc) {
        return Err(IncrementError::FieldChanged);
    }
    inc.extend_from_slice(b"\nendobj\n");

    let sig_off = at(&inc);
    inc.extend_from_slice(
        format!(
            "{sig_num} 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange ["
        )
        .as_bytes(),
    );
    let br_at = inc.len();
    inc.extend_from_slice(format!("{:<43}", "0").as_bytes());
    inc.extend_from_slice(b"] /Contents ");
    let contents_start = at(&inc);
    inc.push(b'<');
    inc.resize(inc.len().saturating_add(capacity.saturating_mul(2)), b'0');
    inc.push(b'>');
    let contents_end = at(&inc);
    inc.extend_from_slice(b" >>\nendobj\n");

    let xref_off = at(&inc);
    let mut lines = vec![
        (field_ref.num, field_off, field_ref.generation),
        (sig_num, sig_off, 0u16),
    ];
    lines.sort_by_key(|l| l.0);
    inc.extend_from_slice(b"xref\n");
    for (num, off, generation) in lines {
        inc.extend_from_slice(format!("{num} 1\n{off:010} {generation:05} n \n").as_bytes());
    }
    let mut trailer = format!(
        "trailer\n<< /Size {} /Root {} {} R /Prev {}",
        sig_num.saturating_add(1),
        root.num,
        root.generation,
        file.startxref()
    );
    if let Some(Object::Ref(info)) = file.trailer().get(b"Info") {
        trailer.push_str(&format!(" /Info {} {} R", info.num, info.generation));
    }
    if let Some(id) = file.trailer().get(b"ID") {
        let mut b = Vec::new();
        if !id.write_to(&mut b) {
            return Err(IncrementError::Trailer("ID"));
        }
        trailer.push_str(" /ID ");
        trailer.push_str(&String::from_utf8_lossy(&b));
    }
    trailer.push_str(&format!(" >>\nstartxref\n{xref_off}\n%%EOF\n"));
    inc.extend_from_slice(trailer.as_bytes());

    let total = at(&inc);
    let br = format!(
        "0 {} {} {}",
        contents_start,
        contents_end,
        total.saturating_sub(contents_end)
    );
    let slot = inc
        .get_mut(br_at..br_at.saturating_add(43))
        .ok_or(IncrementError::ByteRangeMalformed)?;
    let formatted = format!("{br:<43}");
    if formatted.len() != slot.len() {
        return Err(IncrementError::ByteRangeMalformed);
    }
    slot.copy_from_slice(formatted.as_bytes());
    Ok(inc)
}

/// Writes the DER `cms` into the verified placeholder and returns the
/// new revision: `base`, then `increment` with `/Contents` filled. The
/// covered bytes do not change, so the digest still holds.
///
/// # Errors
///
/// [`IncrementError::PlaceholderMismatch`] when the inputs are not the
/// ones `verified` describes, and [`IncrementError::SignatureTooLarge`]
/// when `cms` does not fit.
pub fn embed_signature(
    base: &[u8],
    increment: &[u8],
    verified: &VerifiedIncrement,
    cms: &[u8],
) -> Result<Vec<u8>, IncrementError> {
    let mut full = Vec::with_capacity(verified.total_len);
    full.extend_from_slice(base);
    full.extend_from_slice(increment);
    if full.len() != verified.total_len || verified.contents.start < base.len() {
        return Err(IncrementError::PlaceholderMismatch);
    }
    let inner = verified.contents.start.saturating_add(1)..verified.contents.end.saturating_sub(1);
    let slot = full
        .get_mut(inner)
        .ok_or(IncrementError::PlaceholderMismatch)?;
    if slot.iter().any(|&b| b != b'0') {
        return Err(IncrementError::PlaceholderMismatch);
    }
    let mut hex = Vec::new();
    write_hex_string(&mut hex, cms);
    let digits = hex.get(1..hex.len().saturating_sub(1)).unwrap_or_default();
    let dst = slot
        .get_mut(..digits.len())
        .ok_or(IncrementError::SignatureTooLarge)?;
    dst.copy_from_slice(digits);
    Ok(full)
}
