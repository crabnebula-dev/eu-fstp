//! Process memory reading for the I-80 root canary tests (design section
//! 14.4). Lane W1a. The `/proc/<pid>/maps` reader is a test-only parser
//! with its own fuzz target (`proc_maps_decode`).
//!
//! A maps line is `start-end perms offset dev inode [path]`, with single
//! spaces between the six fields. Addresses and offset are lowercase hex
//! of 1 to 16 digits. Perms are `[r-][w-][x-][ps]`. Dev is `hex:hex`, and
//! inode is decimal. The path, if any, follows padding spaces and runs to
//! the end of the line. The kernel writes the path bytes as the file
//! system holds them, so a path that is not UTF-8 is decoded lossily. Only
//! the pseudo paths such as `[vvar]` matter to the reader. A malformed
//! line refuses the whole text, so a scan never runs over a partial
//! region list.
//!
//! [`read_memory`] reads every region of a process through
//! `/proc/<pid>/mem`, including regions without read permission, such as
//! pages a guarded allocator set to `PROT_NONE`. The kernel's forced
//! access reads them where the mapping allows it. Each region records
//! whether all of it was read. It works on Linux only, and needs the right
//! to trace the process (the same user, or root, under the default Yama
//! setting for a child process).

use std::fmt;
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};

use crate::NotImplemented;

/// One mapped region.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapRegion {
    /// The start address.
    pub start: u64,
    /// The end address.
    pub end: u64,
    /// Whether the region is readable.
    pub readable: bool,
    /// The mapped path, if any.
    pub path: Option<String>,
}

/// Why a maps text was refused, or memory could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcMemError {
    /// Line `line` (counted from 1) is malformed. `field` names the part.
    Malformed {
        /// The line number, from 1.
        line: usize,
        /// The field that failed.
        field: &'static str,
    },
    /// Reading `/proc` failed. The message names the file, never memory
    /// contents.
    Io(String),
    /// The platform has no `/proc/<pid>/mem`.
    Unsupported,
}

impl fmt::Display for ProcMemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcMemError::Malformed { line, field } => {
                write!(f, "malformed maps line {line}: bad {field}")
            }
            ProcMemError::Io(msg) => write!(f, "cannot read process memory: {msg}"),
            ProcMemError::Unsupported => write!(f, "/proc/<pid>/mem is Linux only"),
        }
    }
}

impl std::error::Error for ProcMemError {}

/// Decodes the text of `/proc/<pid>/maps`. Fuzzed (`proc_maps_decode`).
///
/// An empty text has no regions. One final newline is allowed.
///
/// # Errors
///
/// Refuses a text with any malformed line. The error names the first one.
/// The `NotImplemented` type is the W0 signature, and its operation names
/// the line and field; [`decode_maps`] gives the typed error.
pub fn decode_proc_maps(bytes: &[u8]) -> Result<Vec<MapRegion>, NotImplemented> {
    decode_maps(bytes).map_err(|e| match e {
        ProcMemError::Malformed { field, .. } => NotImplemented::new(malformed_label(field)),
        ProcMemError::Io(_) | ProcMemError::Unsupported => {
            NotImplemented::new("fstp_celltest::procmem: unreadable maps text")
        }
    })
}

/// A static label for a refusal through the W0 error type.
fn malformed_label(field: &'static str) -> &'static str {
    match field {
        "range" => "fstp_celltest::procmem: malformed maps line (range)",
        "perms" => "fstp_celltest::procmem: malformed maps line (perms)",
        "offset" => "fstp_celltest::procmem: malformed maps line (offset)",
        "dev" => "fstp_celltest::procmem: malformed maps line (dev)",
        "inode" => "fstp_celltest::procmem: malformed maps line (inode)",
        "path" => "fstp_celltest::procmem: malformed maps line (path)",
        _ => "fstp_celltest::procmem: malformed maps line",
    }
}

/// Decodes the text of `/proc/<pid>/maps` with a typed error.
///
/// # Errors
///
/// [`ProcMemError::Malformed`] for the first malformed line.
pub fn decode_maps(bytes: &[u8]) -> Result<Vec<MapRegion>, ProcMemError> {
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if body.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for (index, line) in body.split(|b| *b == b'\n').enumerate() {
        let number = index.saturating_add(1);
        let region = decode_line(line).map_err(|field| ProcMemError::Malformed {
            line: number,
            field,
        })?;
        out.push(region);
    }
    Ok(out)
}

/// Decodes one line. The error names the field.
fn decode_line(line: &[u8]) -> Result<MapRegion, &'static str> {
    let mut rest = line;
    let range = take_field(&mut rest).ok_or("range")?;
    let perms = take_field(&mut rest).ok_or("perms")?;
    let offset = take_field(&mut rest).ok_or("offset")?;
    let dev = take_field(&mut rest).ok_or("dev")?;
    let inode = take_last_field(&mut rest).ok_or("inode")?;

    let dash = range.iter().position(|b| *b == b'-').ok_or("range")?;
    let (start, end) = (
        range.get(..dash).ok_or("range")?,
        range.get(dash.saturating_add(1)..).ok_or("range")?,
    );
    let start = lower_hex_u64(start).ok_or("range")?;
    let end = lower_hex_u64(end).ok_or("range")?;
    if start >= end {
        return Err("range");
    }
    let readable = decode_perms(perms).ok_or("perms")?;
    lower_hex_u64(offset).ok_or("offset")?;
    let colon = dev.iter().position(|b| *b == b':').ok_or("dev")?;
    let (major, minor) = (
        dev.get(..colon).ok_or("dev")?,
        dev.get(colon.saturating_add(1)..).ok_or("dev")?,
    );
    if !is_hex_field(major, 8) || !is_hex_field(minor, 8) {
        return Err("dev");
    }
    decimal_u64(inode).ok_or("inode")?;

    // What remains is empty, or padding spaces and then the path.
    let path_bytes = trim_leading_spaces(rest);
    let path = if path_bytes.is_empty() {
        None
    } else {
        if rest.first() != Some(&b' ') {
            return Err("inode");
        }
        let text = String::from_utf8_lossy(path_bytes);
        Some(text.into_owned())
    };
    Ok(MapRegion {
        start,
        end,
        readable,
        path,
    })
}

/// Takes the bytes up to the next single space and the space itself.
fn take_field<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let at = rest.iter().position(|b| *b == b' ')?;
    let field = rest.get(..at)?;
    *rest = rest.get(at.saturating_add(1)..)?;
    (!field.is_empty()).then_some(field)
}

/// Takes the inode: the bytes up to the next space or the end.
fn take_last_field<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let at = rest.iter().position(|b| *b == b' ').unwrap_or(rest.len());
    let field = rest.get(..at)?;
    *rest = rest.get(at..)?;
    (!field.is_empty()).then_some(field)
}

fn trim_leading_spaces(bytes: &[u8]) -> &[u8] {
    let skip = bytes.iter().take_while(|b| **b == b' ').count();
    bytes.get(skip..).unwrap_or_default()
}

/// `[r-][w-][x-][ps]`. Returns whether the region is readable.
fn decode_perms(perms: &[u8]) -> Option<bool> {
    let [r, w, x, s] = perms else {
        return None;
    };
    let ok = matches!(r, b'r' | b'-')
        && matches!(w, b'w' | b'-')
        && matches!(x, b'x' | b'-')
        && matches!(s, b'p' | b's');
    ok.then_some(*r == b'r')
}

fn is_hex_field(bytes: &[u8], max: usize) -> bool {
    !bytes.is_empty()
        && bytes.len() <= max
        && bytes.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Lowercase hex of 1 to 16 digits.
fn lower_hex_u64(bytes: &[u8]) -> Option<u64> {
    if !is_hex_field(bytes, 16) {
        return None;
    }
    let mut value = 0u64;
    for b in bytes {
        let d = match b {
            b'0'..=b'9' => b.wrapping_sub(b'0'),
            _ => b.wrapping_sub(b'a').wrapping_add(10),
        };
        value = value.wrapping_shl(4) | u64::from(d);
    }
    Some(value)
}

/// Decimal digits only, within `u64`.
fn decimal_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 20 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut value = 0u64;
    for b in bytes {
        value = value
            .checked_mul(10)?
            .checked_add(u64::from(b.wrapping_sub(b'0')))?;
    }
    Some(value)
}

/// One region and its bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct RegionBytes {
    /// The region.
    pub region: MapRegion,
    /// The bytes read from it, from its start. Shorter than the region
    /// when part of it could not be read, such as a guard page, or when
    /// the region is larger than [`MAX_REGION_BYTES`].
    pub bytes: Vec<u8>,
    /// Whether `bytes` holds the whole region. An I-80 scan that needs
    /// every byte checks it.
    pub complete: bool,
}

impl fmt::Debug for RegionBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegionBytes")
            .field("region", &self.region)
            .field("len", &self.bytes.len())
            .field("complete", &self.complete)
            .finish_non_exhaustive()
    }
}

/// The largest region [`read_memory`] reads, so a huge reservation does
/// not exhaust the test host. Larger regions are read up to this size,
/// and [`RegionBytes::complete`] is false for them.
pub const MAX_REGION_BYTES: u64 = 1_073_741_824;

/// Reads every region of process `pid` through `/proc/<pid>/maps` and
/// `/proc/<pid>/mem` (I-80 instrument, design section 14.4). Regions
/// without read permission are read too, where the kernel allows it. The
/// `[vvar]` and `[vsyscall]` regions are skipped, since the kernel refuses
/// reads of them.
///
/// # Errors
///
/// [`ProcMemError::Unsupported`] off Linux, [`ProcMemError::Io`] when a
/// file cannot be opened, and [`ProcMemError::Malformed`] for a bad maps
/// text.
pub fn read_memory(pid: u32) -> Result<Vec<RegionBytes>, ProcMemError> {
    if !cfg!(target_os = "linux") {
        return Err(ProcMemError::Unsupported);
    }
    let maps_path = format!("/proc/{pid}/maps");
    let maps =
        std::fs::read(&maps_path).map_err(|e| ProcMemError::Io(format!("{maps_path}: {e}")))?;
    let regions = decode_maps(&maps)?;
    let mem_path = format!("/proc/{pid}/mem");
    let mut mem =
        File::open(&mem_path).map_err(|e| ProcMemError::Io(format!("{mem_path}: {e}")))?;
    let mut out = Vec::new();
    for region in regions {
        if matches!(
            region.path.as_deref(),
            Some("[vvar]" | "[vsyscall]" | "[vvar_vclock]")
        ) {
            continue;
        }
        let full = region.end.wrapping_sub(region.start);
        let bytes = read_region(&mut mem, region.start, full.min(MAX_REGION_BYTES));
        let complete = u64::try_from(bytes.len()).is_ok_and(|n| n == full);
        out.push(RegionBytes {
            region,
            bytes,
            complete,
        });
    }
    Ok(out)
}

/// Reads up to `len` bytes at `start`. A read error ends the region early,
/// since parts of a mapping can be unreadable.
fn read_region(mem: &mut File, start: u64, len: u64) -> Vec<u8> {
    let mut out = Vec::new();
    if mem.seek(SeekFrom::Start(start)).is_err() {
        return out;
    }
    let mut limited = mem.take(len);
    let mut chunk = vec![0u8; 65_536];
    loop {
        match limited.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(chunk.get(..n).unwrap_or_default()),
        }
    }
    out
}
