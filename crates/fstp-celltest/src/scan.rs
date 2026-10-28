//! Scanners over raw bytes and their encodings (design section 14.1). Lane
//! W1a.
//!
//! [`scan`] looks for each canary's text in every store, in each encoding
//! section 14.1 lists:
//!
//! - raw bytes;
//! - lowercase and uppercase hex;
//! - base64 and base64url, at each of the three byte alignments, padded or
//!   not, also across line breaks;
//! - percent-encoding of any subset of the bytes, in either hex case;
//! - JSON string escaping (`\u00XX` in either case, and the short escapes);
//! - UTF-16LE.
//!
//! The decodings compose. Each store is also read as percent-decoded,
//! JSON-unescaped, and percent-decoded then JSON-unescaped. Each of those
//! views is read again with its line breaks removed. Every matcher runs
//! over every view. So a base64 body wrapped at 76 characters inside a
//! JSON string (`\n` escapes) or a percent-encoded body (`%0A`) is found.
//!
//! [`scan`] also looks for the ASCII lowercase and uppercase forms of each
//! canary text, in every encoding, since a component may normalise a value
//! before it stores or logs it (an email login address, design section
//! 4.2). [`Canary::email_address`] gives the field-shaped email value.
//!
//! A hit names the store and the canary text. A near miss, such as a
//! canary whose nonce differs in one bit, is never reported. Base64 leaves
//! up to two bytes at each end of a text undetermined, so the base64
//! matchers skip at most two leading bytes and two trailing bytes of the
//! text. A canary's leading bytes are its fixed `CNRY-` prefix, so only
//! the last nonce byte can go unchecked there.
//!
//! [`scan_bytes`] runs the same matchers over arbitrary byte needles, such
//! as the root bytes the custody simulator holds. It matches the bytes
//! exactly, with no case folding.
//!
//! The scanner reads each store's bytes as given. It cannot see a value
//! that PostgreSQL compressed or split into TOAST chunks. The world's
//! store set therefore adds a logical dump of every database
//! ([`crate::world::World::stores`]).
//!
//! A store that starts like a plain `pg_dump` output is a dump store. Its
//! COPY data rows carry a second layer of escapes: COPY text format writes
//! each backslash of a value as two, and a `bytea` value as `\\x<hex>`.
//! So a dump store gets one more view: its data rows, each field
//! COPY-decoded once and each `bytea` field decoded to its bytes. The
//! composed views above are built over that view too. A base64 body
//! inside a JSON string in a `jsonb` column is then found, and so is a
//! base64 or UTF-16LE body inside a `bytea` value. Arrays and composites
//! of `bytea` are not decoded.
//!
//! [`CellDump::from_stores`] extracts the identifier candidates of a store
//! set for [`shared_identifiers`] (I-20).

use std::collections::{BTreeSet, HashMap};

use crate::NotImplemented;
use crate::canary::Canary;

/// Every store of a world: databases, object directories, logs and
/// metrics sinks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoreSet {
    /// Each store's name and bytes.
    pub stores: Vec<(String, Vec<u8>)>,
}

impl StoreSet {
    /// Adds one store.
    pub fn push(&mut self, name: impl Into<String>, bytes: Vec<u8>) {
        self.stores.push((name.into(), bytes));
    }
}

/// What a scan found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanReport {
    /// Each hit: store name and canary text (or needle label). Each pair
    /// appears at most once, in store order, then canary order.
    pub hits: Vec<(String, String)>,
}

impl ScanReport {
    /// Whether nothing was found.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.hits.is_empty()
    }
}

/// A dump of one cell's identifiers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CellDump {
    /// The identifiers.
    pub identifiers: BTreeSet<Vec<u8>>,
}

/// The shortest identifier [`CellDump::from_stores`] keeps, in decoded
/// bytes. Random ids, keys and lookup digests are at least this long.
pub const MIN_IDENTIFIER_LEN: usize = 16;

/// The fewest distinct byte values a kept identifier holds. It drops runs
/// such as zero padding, which every store shares and no random value is.
pub const MIN_IDENTIFIER_DISTINCT: usize = 8;

impl CellDump {
    /// The identifier candidates of every store in `stores` (I-20, design
    /// section 14.4). Each candidate is kept as its decoded bytes, so a key
    /// written as hex in one cell and as base64 in another is the same
    /// identifier:
    ///
    /// - each maximal run of hex digits of at least 32 characters, decoded
    ///   (an odd run at both alignments);
    /// - each UUID in its 8-4-4-4-12 hex form, decoded to 16 bytes;
    /// - each maximal run of the base64 or the base64url alphabet of at
    ///   least 22 characters that holds an uppercase letter, a lowercase
    ///   letter and a digit, decoded from its start.
    ///
    /// A candidate is kept when it has at least [`MIN_IDENTIFIER_LEN`]
    /// bytes and [`MIN_IDENTIFIER_DISTINCT`] distinct byte values.
    ///
    /// The mixed-class rule drops names and words, such as SQL settings,
    /// catalog function names, collation names and HTTP header names. Every
    /// cell holds those. A random 16-byte value in base64 lacks a digit
    /// with a chance of about 2.4 percent, and is then missed in that form.
    /// Its hex or UUID form is still extracted.
    ///
    /// In a dump store (see the module documentation) only the fields of
    /// the COPY data rows are read, each COPY-decoded once. The SQL
    /// preamble, comments, the `\restrict` lines and the COPY headers name
    /// settings, tables and columns that every cell of the platform shares.
    /// A `bytea` field is read as its hex text and as its decoded bytes.
    ///
    /// Raw binary values are not extracted. The world's logical dumps show
    /// a `bytea` or `uuid` column as text, so database values are covered.
    /// A binary file store must be added in a text form to be covered. The
    /// text runs of a raw binary store, such as a relation file, include
    /// catalog names that every cell shares, so a comparison over such
    /// stores takes [`PublicConstants::baseline`] as its allow list.
    #[must_use]
    pub fn from_stores(stores: &StoreSet) -> CellDump {
        let mut identifiers = BTreeSet::new();
        for (_, bytes) in &stores.stores {
            let Some(fields) = dump_fields(bytes) else {
                extract_identifiers(bytes, &mut identifiers);
                continue;
            };
            for field in fields {
                extract_identifiers(&field, &mut identifiers);
                if let Some(value) = bytea_value(&field) {
                    extract_identifiers(&value, &mut identifiers);
                }
            }
        }
        CellDump { identifiers }
    }
}

/// Constants that may appear in every cell.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PublicConstants {
    /// The constants.
    pub values: BTreeSet<Vec<u8>>,
}

impl PublicConstants {
    /// The identifiers that two cells of one build share before any
    /// account or person exists in either: `a` and `b` are the dumps of two
    /// fresh cells with every migration applied (I-20, design section
    /// 14.4).
    ///
    /// A logical dump store needs no baseline, since only its data fields
    /// are read. Raw binary stores do. A relation file or WAL segment holds
    /// the system catalogs and the schema, and a catalog name next to a
    /// length byte reads as a mixed-class run, such as
    /// `Abrin_minmax_multi_distance_int2`. Every cell of a build holds the
    /// same such runs. A random identifier of a later account is not in
    /// the baseline, so the baseline hides no link.
    #[must_use]
    pub fn baseline(a: &CellDump, b: &CellDump) -> PublicConstants {
        PublicConstants {
            values: a
                .identifiers
                .intersection(&b.identifiers)
                .cloned()
                .collect(),
        }
    }
}

/// A byte string to look for, with the label a hit reports.
#[derive(Clone, PartialEq, Eq)]
pub struct Needle {
    /// The label a hit reports. It never holds the bytes themselves.
    pub label: String,
    /// The bytes to look for. At least four bytes.
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for Needle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Needle")
            .field("label", &self.label)
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// The shortest needle the scanner accepts. Shorter needles would match
/// by chance.
pub const MIN_NEEDLE_LEN: usize = 4;

/// Searches every store for every canary in every encoding, and for the
/// ASCII lowercase and uppercase forms of its text.
///
/// # Errors
///
/// Never fails for canaries. The `Result` keeps the W0 signature.
pub fn scan(stores: &StoreSet, canaries: &[Canary]) -> Result<ScanReport, NotImplemented> {
    let needles: Vec<Needle> = canaries
        .iter()
        .map(|c| {
            let text = c.text();
            Needle {
                bytes: text.clone().into_bytes(),
                label: text,
            }
        })
        .collect();
    scan_needles(stores, &needles, case_variants)
}

/// Searches every store for every needle in every encoding of
/// [`scan`]. The bytes match exactly, with no case folding.
///
/// # Errors
///
/// Refuses a needle shorter than [`MIN_NEEDLE_LEN`].
pub fn scan_bytes(stores: &StoreSet, needles: &[Needle]) -> Result<ScanReport, NotImplemented> {
    scan_needles(stores, needles, |n| vec![n.to_vec()])
}

/// The needle as given, and its ASCII lowercase and uppercase forms.
fn case_variants(needle: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![
        needle.to_vec(),
        needle.to_ascii_lowercase(),
        needle.to_ascii_uppercase(),
    ];
    out.sort();
    out.dedup();
    out
}

/// Searches every store for every needle, in each spelling `variants`
/// gives and each encoding of each spelling.
fn scan_needles(
    stores: &StoreSet,
    needles: &[Needle],
    variants: fn(&[u8]) -> Vec<Vec<u8>>,
) -> Result<ScanReport, NotImplemented> {
    if needles.iter().any(|n| n.bytes.len() < MIN_NEEDLE_LEN) {
        return Err(NotImplemented::new(
            "fstp_celltest::scan: a needle shorter than four bytes",
        ));
    }
    let matcher = Matcher::new(needles, |n| {
        let mut forms = Vec::new();
        for v in variants(n) {
            forms.extend(encoded_forms(&v));
            forms.push(v);
        }
        forms
    });
    let mut report = ScanReport::default();
    for (name, bytes) in &stores.stores {
        let mut found = vec![false; needles.len()];
        for_each_view(bytes, |view| matcher.mark(view, &mut found));
        if let Some(rows) = dump_view(bytes) {
            for_each_view(&rows, |view| matcher.mark(view, &mut found));
        }
        for (needle, hit) in needles.iter().zip(found) {
            if hit {
                report.hits.push((name.clone(), needle.label.clone()));
            }
        }
    }
    Ok(report)
}

/// The identifiers two cells share, beyond the public constants (I-20).
///
/// # Errors
///
/// Never fails. The `Result` keeps the W0 signature.
pub fn shared_identifiers(
    a: &CellDump,
    b: &CellDump,
    allow: &PublicConstants,
) -> Result<BTreeSet<Vec<u8>>, NotImplemented> {
    Ok(a.identifiers
        .intersection(&b.identifiers)
        .filter(|id| !allow.values.contains(*id))
        .cloned()
        .collect())
}

// ---------------------------------------------------------------------------
// Identifier candidates.

/// Adds the identifier candidates of `bytes` to `out`, as
/// [`CellDump::from_stores`] describes.
fn extract_identifiers(bytes: &[u8], out: &mut BTreeSet<Vec<u8>>) {
    let mut keep = |id: Vec<u8>| {
        if id.len() >= MIN_IDENTIFIER_LEN && distinct_bytes(&id) >= MIN_IDENTIFIER_DISTINCT {
            out.insert(id);
        }
    };
    let hex_len = MIN_IDENTIFIER_LEN.saturating_mul(2);
    for run in runs(bytes, |b| b.is_ascii_hexdigit() || b == b'-') {
        let groups: Vec<&[u8]> = run.split(|b| *b == b'-').collect();
        let lens: Vec<usize> = groups.iter().map(|g| g.len()).collect();
        if lens == [8, 4, 4, 4, 12] {
            keep(hex_decode(&groups.concat()));
        }
        for group in groups {
            if group.len() >= hex_len {
                keep(hex_decode(group));
                if group.len() % 2 == 1 {
                    keep(hex_decode(group.get(1..).unwrap_or_default()));
                }
            }
        }
    }
    let b64_len = 22;
    for alphabet in [B64, B64URL] {
        let table = base64_table(alphabet);
        let member = |b: u8| table.get(usize::from(b)).is_some_and(|v| *v != NOT_BASE64);
        for run in runs(bytes, member) {
            if run.len() >= b64_len && mixes_classes(run) {
                keep(base64_decode(run, &table));
            }
        }
    }
}

/// Whether `run` holds an uppercase letter, a lowercase letter and a
/// digit, as almost every random base64 value of 16 bytes or more does.
fn mixes_classes(run: &[u8]) -> bool {
    run.iter().any(u8::is_ascii_uppercase)
        && run.iter().any(u8::is_ascii_lowercase)
        && run.iter().any(u8::is_ascii_digit)
}

// ---------------------------------------------------------------------------
// Plain `pg_dump` output.

/// The start of every plain-format `pg_dump` output.
const DUMP_HEADER: &[u8] = b"--\n-- PostgreSQL database dump\n";

/// The fields of every COPY data row of a dump store, each COPY-decoded
/// once, in order. `None` when `bytes` is not a dump store.
///
/// A data block starts at a line `COPY <table> ... FROM stdin;` and ends
/// at the line `\.`. Each line between is a row of tab-separated fields.
fn dump_fields(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let rows = dump_rows(bytes)?;
    Some(
        rows.into_iter()
            .flat_map(|row| {
                row.split(|b| *b == b'\t')
                    .map(copy_unescape)
                    .collect::<Vec<_>>()
            })
            .collect(),
    )
}

/// The raw data row lines of a dump store, or `None` when `bytes` is not
/// one.
fn dump_rows(bytes: &[u8]) -> Option<Vec<&[u8]>> {
    if !bytes.starts_with(DUMP_HEADER) {
        return None;
    }
    let mut rows = Vec::new();
    let mut in_data = false;
    for line in bytes.split(|b| *b == b'\n') {
        if in_data {
            if line == b"\\." {
                in_data = false;
            } else {
                rows.push(line);
            }
        } else if line.starts_with(b"COPY ") && line.ends_with(b" FROM stdin;") {
            in_data = true;
        }
    }
    Some(rows)
}

/// The data rows of a dump store as one byte string: each field
/// COPY-decoded once, a `bytea` field decoded to its bytes, fields joined
/// by a tab and rows ended by a line feed. `None` when `bytes` is not a
/// dump store or holds no data row.
fn dump_view(bytes: &[u8]) -> Option<Vec<u8>> {
    let rows = dump_rows(bytes)?;
    if rows.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len());
    for row in rows {
        for (i, field) in row.split(|b| *b == b'\t').enumerate() {
            if i > 0 {
                out.push(b'\t');
            }
            let field = copy_unescape(field);
            match bytea_value(&field) {
                Some(value) => out.extend_from_slice(&value),
                None => out.extend_from_slice(&field),
            }
        }
        out.push(b'\n');
    }
    Some(out)
}

/// One COPY text-format field with its escapes undone (the PostgreSQL
/// `COPY` reference, "Text Format"): `\b`, `\f`, `\n`, `\r`, `\t`, `\v`,
/// one to three octal digits, `\x` with one or two hex digits, and a
/// backslash before any other byte, which stands for that byte. The NULL
/// marker `\N` becomes empty.
fn copy_unescape(field: &[u8]) -> Vec<u8> {
    if field == b"\\N" {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(field.len());
    let mut i = 0usize;
    while let Some(&b) = field.get(i) {
        if b != b'\\' {
            out.push(b);
            i = i.saturating_add(1);
            continue;
        }
        let Some(&c) = field.get(i.saturating_add(1)) else {
            out.push(b);
            break;
        };
        let rest = field.get(i.saturating_add(2)..).unwrap_or_default();
        let (byte, used) = match c {
            b'0'..=b'7' => {
                let mut value = c.wrapping_sub(b'0');
                let mut used = 2usize;
                for d in rest.iter().take(2) {
                    if !matches!(d, b'0'..=b'7') {
                        break;
                    }
                    value = value.wrapping_shl(3) | d.wrapping_sub(b'0');
                    used = used.saturating_add(1);
                }
                (value, used)
            }
            b'x' => {
                let digits: Vec<u8> = rest.iter().take(2).map_while(|d| hex_value(*d)).collect();
                match digits.as_slice() {
                    [] => (b'x', 2),
                    [d] => (*d, 3),
                    [hi, lo, ..] => (hi.wrapping_shl(4) | lo, 4),
                }
            }
            b'b' => (0x08, 2),
            b'f' => (0x0c, 2),
            b'n' => (b'\n', 2),
            b'r' => (b'\r', 2),
            b't' => (b'\t', 2),
            b'v' => (0x0b, 2),
            other => (other, 2),
        };
        out.push(byte);
        i = i.saturating_add(used);
    }
    out
}

/// The bytes of a COPY-decoded `bytea` field in hex output format
/// (`\x` and an even number of hex digits), or `None` for any other field.
fn bytea_value(field: &[u8]) -> Option<Vec<u8>> {
    let digits = field.strip_prefix(b"\\x")?;
    if digits.len() % 2 != 0 || !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    Some(hex_decode(digits))
}

/// The value of a byte outside the alphabet in a [`base64_table`].
const NOT_BASE64: u8 = 0xff;

/// Each byte's value in `alphabet`, or [`NOT_BASE64`].
fn base64_table(alphabet: &[u8; 64]) -> [u8; 256] {
    let mut table = [NOT_BASE64; 256];
    for (value, ch) in (0u8..).zip(alphabet.iter()) {
        if let Some(slot) = table.get_mut(usize::from(*ch)) {
            *slot = value;
        }
    }
    table
}

/// The maximal runs of bytes in `bytes` for which `member` holds.
fn runs(bytes: &[u8], member: impl Fn(u8) -> bool) -> impl Iterator<Item = &[u8]> {
    bytes.split(move |b| !member(*b)).filter(|r| !r.is_empty())
}

fn distinct_bytes(bytes: &[u8]) -> usize {
    let mut seen = [false; 256];
    let mut n = 0usize;
    for b in bytes {
        if let Some(slot) = seen.get_mut(usize::from(*b))
            && !*slot
        {
            *slot = true;
            n = n.saturating_add(1);
        }
    }
    n
}

/// Decodes hex digits in pairs from the start. A last odd digit is
/// dropped.
fn hex_decode(digits: &[u8]) -> Vec<u8> {
    digits
        .chunks_exact(2)
        .filter_map(|pair| {
            let hi = hex_value(*pair.first()?)?;
            let lo = hex_value(*pair.get(1)?)?;
            Some(hi.wrapping_shl(4) | lo)
        })
        .collect()
}

/// Decodes base64 characters with the values in `table` from the start,
/// without padding. A last lone character is dropped.
fn base64_decode(chars: &[u8], table: &[u8; 256]) -> Vec<u8> {
    let value = |c: &u8| {
        table
            .get(usize::from(*c))
            .filter(|v| **v != NOT_BASE64)
            .map(|v| u32::from(*v))
    };
    let mut out = Vec::with_capacity(chars.len());
    for group in chars.chunks(4) {
        let values: Vec<u32> = group.iter().filter_map(value).collect();
        if values.len() < 2 {
            break;
        }
        let mut n = 0u32;
        for (k, v) in values.iter().enumerate() {
            let shift = 18u32.saturating_sub(6u32.saturating_mul(u32::try_from(k).unwrap_or(0)));
            n |= v.wrapping_shl(shift);
        }
        let bytes = n.to_be_bytes();
        let take = values.len().saturating_sub(1);
        out.extend_from_slice(bytes.get(1..take.saturating_add(1)).unwrap_or_default());
    }
    out
}

// ---------------------------------------------------------------------------
// Encoded forms of a needle.

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The forms of `text` that appear verbatim in a store: both hex cases,
/// base64 and base64url at each alignment, and UTF-16LE.
fn encoded_forms(text: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![hex(text, false), hex(text, true), utf16le(text)];
    for skip in 0..3 {
        let Some(rest) = text.get(skip..) else {
            continue;
        };
        let whole = rest.len().saturating_sub(rest.len() % 3);
        let Some(groups) = rest.get(..whole) else {
            continue;
        };
        if groups.is_empty() {
            continue;
        }
        out.push(base64_groups(groups, B64));
        out.push(base64_groups(groups, B64URL));
    }
    out.retain(|f| f.len() >= MIN_NEEDLE_LEN);
    out.sort();
    out.dedup();
    out
}

fn hex(bytes: &[u8], upper: bool) -> Vec<u8> {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b.wrapping_shr(4), b & 0x0f] {
            if let Some(d) = digits.get(usize::from(nibble)) {
                out.push(*d);
            }
        }
    }
    out
}

fn utf16le(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().flat_map(|b| [*b, 0]).collect()
}

/// Base64 of whole 3-byte groups, so no padding arises.
fn base64_groups(bytes: &[u8], alphabet: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(2));
    for chunk in bytes.chunks_exact(3) {
        let [a, b, c] = chunk else {
            continue;
        };
        let n = u32::from(*a).wrapping_shl(16) | u32::from(*b).wrapping_shl(8) | u32::from(*c);
        for shift in [18u32, 12, 6, 0] {
            let index = usize::try_from(n.wrapping_shr(shift) & 0x3f).unwrap_or(0);
            if let Some(ch) = alphabet.get(index) {
                out.push(*ch);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Decoded views of a store.

/// Calls `f` on every view of `bytes`: the bytes as they are,
/// percent-decoded, JSON-unescaped, and percent-decoded then
/// JSON-unescaped, each also with its line breaks removed. A view equal to
/// the one it was built from is skipped.
fn for_each_view(bytes: &[u8], mut f: impl FnMut(&[u8])) {
    let mut with_joined = |view: &[u8]| {
        f(view);
        if let Some(joined) = join_lines(view) {
            f(&joined);
        }
    };
    with_joined(bytes);
    if let Some(json) = json_unescape(bytes) {
        with_joined(&json);
    }
    if let Some(percent) = percent_decode(bytes) {
        with_joined(&percent);
        if let Some(both) = json_unescape(&percent) {
            with_joined(&both);
        }
    }
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(b.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// The size of the chunks a view is built from. A chunk without a marker
/// byte is copied whole.
const CHUNK: usize = 4096;

/// Rewrites `bytes` with `step`, which sees the bytes from a marker byte on
/// and returns what to write and how many bytes it used, or `None` to keep
/// the marker. Finding markers and copying chunks run at memory speed, so
/// a large binary store costs little. Returns `None` when nothing changed,
/// so the caller can skip a pass over an identical view.
fn rewrite(
    bytes: &[u8],
    markers: &[u8],
    step: impl Fn(&[u8]) -> Option<(Vec<u8>, usize)>,
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut changed = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let end = i.saturating_add(CHUNK).min(bytes.len());
        let chunk = bytes.get(i..end).unwrap_or_default();
        if !markers.iter().any(|m| chunk.contains(m)) {
            out.extend_from_slice(chunk);
            i = end;
            continue;
        }
        while i < end {
            let rest = bytes.get(i..).unwrap_or_default();
            let Some(&b) = rest.first() else {
                break;
            };
            if markers.contains(&b)
                && let Some((emit, used)) = step(rest)
            {
                out.extend_from_slice(&emit);
                i = i.saturating_add(used.max(1));
                changed = true;
                continue;
            }
            out.push(b);
            i = i.saturating_add(1);
        }
    }
    changed.then_some(out)
}

/// Decodes every `%XX` escape. Other bytes stay. `None` when the store
/// holds no escape.
fn percent_decode(bytes: &[u8]) -> Option<Vec<u8>> {
    rewrite(bytes, b"%", |s| {
        let hi = hex_value(*s.get(1)?)?;
        let lo = hex_value(*s.get(2)?)?;
        Some((vec![hi.wrapping_shl(4) | lo], 3))
    })
}

/// Decodes JSON string escapes: `\uXXXX` (written as UTF-8) and the short
/// escapes. Other bytes stay. `None` when the store holds no escape.
fn json_unescape(bytes: &[u8]) -> Option<Vec<u8>> {
    rewrite(bytes, b"\\", json_escape_at)
}

/// The store without line breaks. `None` when it has none.
fn join_lines(bytes: &[u8]) -> Option<Vec<u8>> {
    rewrite(bytes, b"\r\n", |_| Some((Vec::new(), 1)))
}

/// The escape at the start of `s`, which begins with a backslash.
fn json_escape_at(s: &[u8]) -> Option<(Vec<u8>, usize)> {
    let short = match s.get(1)? {
        b'"' => Some(b'"'),
        b'\\' => Some(b'\\'),
        b'/' => Some(b'/'),
        b'b' => Some(0x08),
        b'f' => Some(0x0c),
        b'n' => Some(b'\n'),
        b'r' => Some(b'\r'),
        b't' => Some(b'\t'),
        _ => None,
    };
    if let Some(byte) = short {
        return Some((vec![byte], 2));
    }
    if *s.get(1)? != b'u' {
        return None;
    }
    let mut value = 0u32;
    for k in 2..6 {
        let d = hex_value(*s.get(k)?)?;
        value = value.wrapping_shl(4) | u32::from(d);
    }
    let ch = char::from_u32(value)?;
    let mut buf = [0u8; 4];
    Some((ch.encode_utf8(&mut buf).as_bytes().to_vec(), 6))
}

// ---------------------------------------------------------------------------
// Multi-needle search (Wu-Manber, two-byte blocks).
//
// Let `m` be the length of the shortest form. The scan looks at the two
// bytes that end a window of `m` bytes. A block that ends no form's
// first `m` bytes moves the window by up to `m - 1` bytes at once. Store
// contents are mostly bytes that occur in no form, such as zero pages, so
// a scan reads only about one block in `m - 1`.

/// Every form of every needle, with the shift and candidate tables.
struct Matcher {
    /// Each form and the needle it belongs to.
    forms: Vec<(usize, Vec<u8>)>,
    /// The length of the shortest form.
    min_len: usize,
    /// For each two-byte block, how far the window may move.
    shift: Vec<usize>,
    /// For each block that ends a window of some form, those forms.
    ends: HashMap<u16, Vec<usize>>,
}

fn block(a: u8, b: u8) -> u16 {
    u16::from(a).wrapping_shl(8) | u16::from(b)
}

impl Matcher {
    fn new(needles: &[Needle], forms_of: impl Fn(&[u8]) -> Vec<Vec<u8>>) -> Matcher {
        let mut forms = Vec::new();
        for (owner, needle) in needles.iter().enumerate() {
            for form in forms_of(&needle.bytes) {
                if form.len() >= MIN_NEEDLE_LEN {
                    forms.push((owner, form));
                }
            }
        }
        let min_len = forms
            .iter()
            .map(|(_, f)| f.len())
            .min()
            .unwrap_or(MIN_NEEDLE_LEN);
        // The window's last block starts at `min_len - 2`.
        let last = min_len.saturating_sub(2);
        let mut shift = vec![last.saturating_add(1); 65_536];
        let mut ends: HashMap<u16, Vec<usize>> = HashMap::new();
        for (k, (_, form)) in forms.iter().enumerate() {
            for j in 0..=last {
                let (Some(a), Some(b)) = (form.get(j), form.get(j.saturating_add(1))) else {
                    continue;
                };
                let key = block(*a, *b);
                let distance = last.saturating_sub(j);
                if let Some(slot) = shift.get_mut(usize::from(key))
                    && distance < *slot
                {
                    *slot = distance;
                }
                if distance == 0 {
                    ends.entry(key).or_default().push(k);
                }
            }
        }
        Matcher {
            forms,
            min_len,
            shift,
            ends,
        }
    }

    /// Marks in `found` each needle that one of its forms occurs in `hay`.
    fn mark(&self, hay: &[u8], found: &mut [bool]) {
        if self.forms.is_empty() || hay.len() < self.min_len {
            return;
        }
        let last = self.min_len.saturating_sub(2);
        // `i` is where the window's last block starts.
        let mut i = last;
        while let (Some(a), Some(b)) = (hay.get(i), hay.get(i.saturating_add(1))) {
            let key = block(*a, *b);
            let step = self.shift.get(usize::from(key)).copied().unwrap_or(1);
            if step > 0 {
                i = i.saturating_add(step);
                continue;
            }
            let start = i.saturating_sub(last);
            if let (Some(candidates), Some(window)) = (self.ends.get(&key), hay.get(start..)) {
                for &k in candidates {
                    if let Some((owner, form)) = self.forms.get(k)
                        && window.starts_with(form)
                        && let Some(slot) = found.get_mut(*owner)
                    {
                        *slot = true;
                    }
                }
            }
            i = i.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_keeps_bad_escapes() {
        assert_eq!(percent_decode(b"%41%4a%zz%"), Some(b"AJ%zz%".to_vec()));
        assert_eq!(percent_decode(b"%zz"), None);
    }

    #[test]
    fn json_unescape_decodes_unicode_and_short_escapes() {
        assert_eq!(
            json_unescape(b"\\u0041\\u002D\\n\\q"),
            Some(b"A-\n\\q".to_vec())
        );
    }

    #[test]
    fn base64_groups_matches_a_known_value() {
        assert_eq!(base64_groups(b"Man", B64), b"TWFu".to_vec());
    }

    #[test]
    fn base64_decode_inverts_base64_groups() {
        let text = b"identifier-bytes-0123456789";
        let encoded = base64_groups(text, B64);
        assert_eq!(base64_decode(&encoded, &base64_table(B64)), text.to_vec());
        assert_eq!(base64_decode(b"TWE", &base64_table(B64)), b"Ma".to_vec());
    }

    #[test]
    fn hex_decode_reads_pairs() {
        assert_eq!(hex_decode(b"0aFf1"), vec![0x0a, 0xff]);
    }

    #[test]
    fn identifiers_skip_low_entropy_runs() {
        let mut out = BTreeSet::new();
        extract_identifiers(&[b'0'; 64], &mut out);
        extract_identifiers(&[b'A'; 64], &mut out);
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn copy_unescape_undoes_one_layer() {
        assert_eq!(
            copy_unescape(b"a\\\\nb\\tc\\101\\x41\\x4\\q\\"),
            b"a\\nb\tcAA\x04q\\".to_vec()
        );
        assert_eq!(copy_unescape(b"\\N"), Vec::<u8>::new());
    }

    #[test]
    fn bytea_fields_decode_to_bytes() {
        assert_eq!(bytea_value(b"\\x4142"), Some(b"AB".to_vec()));
        assert_eq!(bytea_value(b"\\x414"), None);
        assert_eq!(bytea_value(b"x4142"), None);
    }

    #[test]
    fn dump_view_reads_only_data_rows() {
        let dump = b"--\n-- PostgreSQL database dump\n--\nSET a = 0;\n\
                     COPY public.t (b, j) FROM stdin;\n\\\\x4142\t{\"k\": \"x\\\\ny\"}\n\\.\n";
        assert_eq!(dump_view(dump), Some(b"AB\t{\"k\": \"x\\ny\"}\n".to_vec()));
        assert_eq!(dump_view(b"COPY t FROM stdin;\nx\n\\.\n"), None);
    }

    #[test]
    fn identifiers_skip_names_and_words() {
        let mut out = BTreeSet::new();
        extract_identifiers(
            b"idle_in_transaction_session_timeout Strict-Transport-Security \
              euc_jis_2004_to_shift_jis_2004 en-US-u-va-posix-x-icu",
            &mut out,
        );
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn short_needles_are_refused() {
        let needle = Needle {
            label: "x".to_owned(),
            bytes: b"abc".to_vec(),
        };
        assert!(scan_bytes(&StoreSet::default(), &[needle]).is_err());
    }
}
