//! The table generator of `fstp-unorm` (ADR-029). It reads the vendored
//! Unicode Character Database files under `third_party/unicode/<version>/`
//! and renders `crates/fstp-unorm/src/tables.rs`. It is a build tool and
//! never ships. The binary `unorm-gen` writes or checks the file, and the
//! tests of `fstp-unorm` call [`generate`] to prove the committed tables
//! fresh.
//!
//! The tables are sorted arrays of packed `u64` values, so the normaliser
//! finds an entry by binary search. A code point takes 21 bits.
//!
//! | Table | Packing |
//! | --- | --- |
//! | `CCC` | `lo << 29 \| hi << 8 \| class`: a range of code points with one non-zero class |
//! | `DECOMP` | `cp << 42 \| a << 21 \| b`: the one-level canonical decomposition `a b`, with `b = 0` for a singleton |
//! | `COMP` | `a << 42 \| b << 21 \| c`: the primary composite `c` of the pair `a b` |
//! | `FOLD` | `cp << 21 \| f`: a full case folding to one code point |
//! | `FOLD_MULTI` | `(cp, [f1, f2, f3])`: a full case folding to two or three code points, padded with 0 |
//! | `COMPAT` | `cp << 21 \| start << 5 \| len`: the one-level compatibility decomposition `COMPAT_POOL[start..start + len]` |
//! | `COMPAT_POOL` | the code points of the compatibility decompositions, as `u32` |
//! | `IGNORABLE` | `lo << 21 \| hi`: a range of code points that `NFKC_CF` removes (its mapping is empty) |

pub mod ucd;

use std::collections::BTreeSet;
use std::fmt::{self, Write as _};
use std::path::{Path, PathBuf};

use ucd::{CaseFolding, NfkcCf, ParseError, UnicodeData};

/// The Unicode version of the vendored files (ADR-029).
pub const UCD_VERSION: &str = "18.0.0";
/// The vendored files, relative to the repository root.
pub const UCD_DIR: &str = "third_party/unicode/18.0.0";
/// The generated file, relative to the repository root.
pub const TABLES_RS: &str = "crates/fstp-unorm/src/tables.rs";

/// Why a generation failed.
#[derive(Debug)]
pub enum GenError {
    /// A file could not be read.
    Io(PathBuf, std::io::ErrorKind),
    /// A file was refused by its parser.
    Parse(ParseError),
    /// A file names another Unicode version in its first line.
    Version(&'static str),
    /// The data breaks an assumption of the table layout.
    Build(&'static str),
}

impl fmt::Display for GenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(p, k) => write!(f, "{}: {k}", p.display()),
            Self::Parse(e) => e.fmt(f),
            Self::Version(file) => write!(f, "{file} is not version {UCD_VERSION}"),
            Self::Build(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for GenError {}

impl From<ParseError> for GenError {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}

/// The tables, before rendering.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tables {
    /// Combining class ranges, packed as the crate documentation says.
    pub ccc: Vec<u64>,
    /// One-level canonical decompositions.
    pub decomp: Vec<u64>,
    /// Primary composites.
    pub comp: Vec<u64>,
    /// Case foldings to one code point.
    pub fold: Vec<u64>,
    /// Case foldings to two or three code points.
    pub fold_multi: Vec<(u32, [u32; 3])>,
    /// One-level compatibility decompositions, as index entries.
    pub compat: Vec<u64>,
    /// The code points of the compatibility decompositions.
    pub compat_pool: Vec<u32>,
    /// Ranges of code points that `NFKC_CF` removes.
    pub ignorable: Vec<u64>,
}

/// Builds the tables from the parsed files. The full composition
/// exclusion is derived here (UAX #15): the listed exclusions, every
/// singleton decomposition, and every decomposition of a non-starter or
/// one that starts with a non-starter. The removed code points are those
/// whose `NFKC_CF` mapping is empty.
pub fn build(
    ud: &UnicodeData,
    exclusions: &BTreeSet<u32>,
    folding: &CaseFolding,
    nfkc_cf: &NfkcCf,
) -> Result<Tables, GenError> {
    let mut t = Tables::default();
    let class = |cp: u32| ud.ccc.get(&cp).copied().unwrap_or(0);

    let mut run: Option<(u32, u32, u8)> = None;
    for (&cp, &c) in &ud.ccc {
        run = match run {
            Some((lo, hi, rc)) if rc == c && hi.checked_add(1) == Some(cp) => Some((lo, cp, rc)),
            Some((lo, hi, rc)) => {
                t.ccc
                    .push((u64::from(lo) << 29) | (u64::from(hi) << 8) | u64::from(rc));
                Some((cp, cp, c))
            }
            None => Some((cp, cp, c)),
        };
    }
    if let Some((lo, hi, rc)) = run {
        t.ccc
            .push((u64::from(lo) << 29) | (u64::from(hi) << 8) | u64::from(rc));
    }

    let mut pairs = BTreeSet::new();
    for (&cp, d) in &ud.canonical {
        let (a, b) = match d.as_slice() {
            [a] => (*a, 0),
            [a, b] => (*a, *b),
            _ => return Err(GenError::Build("a canonical decomposition longer than two")),
        };
        if a == 0 {
            return Err(GenError::Build("a decomposition to U+0000"));
        }
        t.decomp
            .push((u64::from(cp) << 42) | (u64::from(a) << 21) | u64::from(b));
        let excluded = b == 0 || exclusions.contains(&cp) || class(cp) != 0 || class(a) != 0;
        if !excluded {
            if !pairs.insert((a, b)) {
                return Err(GenError::Build("two primary composites of one pair"));
            }
            t.comp
                .push((u64::from(a) << 42) | (u64::from(b) << 21) | u64::from(cp));
        }
    }
    t.comp.sort_unstable();

    for (&cp, f) in folding {
        match f.as_slice() {
            [one] => t.fold.push((u64::from(cp) << 21) | u64::from(*one)),
            [a, b] => t.fold_multi.push((cp, [*a, *b, 0])),
            [a, b, c] => t.fold_multi.push((cp, [*a, *b, *c])),
            _ => return Err(GenError::Build("a case folding of no or many code points")),
        }
    }
    for (&cp, d) in &ud.compat {
        let start = u64::try_from(t.compat_pool.len()).unwrap_or(u64::MAX);
        let len = u64::try_from(d.len()).unwrap_or(u64::MAX);
        if start >= 1 << 16 || len == 0 || len >= 1 << 5 {
            return Err(GenError::Build(
                "the compatibility pool outgrows its packing",
            ));
        }
        t.compat.push((u64::from(cp) << 21) | (start << 5) | len);
        t.compat_pool.extend_from_slice(d);
    }

    let mut run: Option<(u32, u32)> = None;
    for (&cp, _) in nfkc_cf.iter().filter(|(_, m)| m.is_empty()) {
        run = match run {
            Some((lo, hi)) if hi.checked_add(1) == Some(cp) => Some((lo, cp)),
            Some((lo, hi)) => {
                t.ignorable.push((u64::from(lo) << 21) | u64::from(hi));
                Some((cp, cp))
            }
            None => Some((cp, cp)),
        };
    }
    if let Some((lo, hi)) = run {
        t.ignorable.push((u64::from(lo) << 21) | u64::from(hi));
    }

    let packed_ok = t.decomp.iter().chain(&t.comp).all(|&e| e >> 63 == 0);
    if !packed_ok || t.fold.iter().any(|&e| e >> 42 != 0) {
        return Err(GenError::Build("a code point beyond 21 bits"));
    }
    Ok(t)
}

/// Writes one packed `u64` array.
fn render_u64(out: &mut String, name: &str, doc: &str, values: &[u64]) {
    let _ = writeln!(out, "/// {doc}");
    let _ = writeln!(out, "#[rustfmt::skip]");
    let _ = writeln!(out, "pub(crate) static {name}: [u64; {}] = [", values.len());
    for row in values.chunks(4) {
        out.push_str("   ");
        for v in row {
            let _ = write!(out, " {v:#018x},");
        }
        out.push('\n');
    }
    out.push_str("];\n\n");
}

/// Renders the tables as the Rust source of `tables.rs`.
pub fn render(version: (u8, u8, u8), t: &Tables) -> String {
    let (major, minor, update) = version;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "//! Tables of the Unicode Character Database {major}.{minor}.{update} (ADR-029).\n\
         //!\n\
         //! Generated by `tools/unorm-gen` from `{UCD_DIR}`. Do not edit: run\n\
         //! `cargo run -p unorm-gen` instead. The packing of each table is described\n\
         //! in the documentation of `unorm-gen`.\n"
    );
    let _ = writeln!(out, "/// The Unicode version of these tables.");
    let _ = writeln!(
        out,
        "pub(crate) const VERSION: (u8, u8, u8) = ({major}, {minor}, {update});\n"
    );
    render_u64(
        &mut out,
        "CCC",
        "Ranges of code points with one non-zero canonical combining class.",
        &t.ccc,
    );
    render_u64(
        &mut out,
        "DECOMP",
        "One-level canonical decompositions.",
        &t.decomp,
    );
    render_u64(&mut out, "COMP", "Primary composites by pair.", &t.comp);
    render_u64(
        &mut out,
        "FOLD",
        "Full case foldings (status C and F) to one code point.",
        &t.fold,
    );
    let _ = writeln!(
        out,
        "/// Full case foldings (status F) to two or three code points."
    );
    let _ = writeln!(out, "#[rustfmt::skip]");
    let _ = writeln!(
        out,
        "pub(crate) static FOLD_MULTI: [(u32, [u32; 3]); {}] = [",
        t.fold_multi.len()
    );
    for (cp, [a, b, c]) in &t.fold_multi {
        let _ = writeln!(out, "    ({cp:#07x}, [{a:#07x}, {b:#07x}, {c:#07x}]),");
    }
    out.push_str("];\n\n");
    render_u64(
        &mut out,
        "COMPAT",
        "One-level compatibility decompositions, as index entries into `COMPAT_POOL`.",
        &t.compat,
    );
    let _ = writeln!(
        out,
        "/// The code points of the compatibility decompositions."
    );
    let _ = writeln!(out, "#[rustfmt::skip]");
    let _ = writeln!(
        out,
        "pub(crate) static COMPAT_POOL: [u32; {}] = [",
        t.compat_pool.len()
    );
    for row in t.compat_pool.chunks(8) {
        out.push_str("   ");
        for v in row {
            let _ = write!(out, " {v:#07x},");
        }
        out.push('\n');
    }
    out.push_str("];\n\n");
    let ignorable_doc = "Ranges of code points that `NFKC_CF` removes.";
    let _ = writeln!(out, "/// {ignorable_doc}");
    let _ = writeln!(out, "#[rustfmt::skip]");
    let _ = writeln!(
        out,
        "pub(crate) static IGNORABLE: [u64; {}] = [",
        t.ignorable.len()
    );
    for row in t.ignorable.chunks(4) {
        out.push_str("   ");
        for v in row {
            let _ = write!(out, " {v:#018x},");
        }
        out.push('\n');
    }
    out.push_str("];\n");
    out
}

/// Parses `"18.0.0"` into its three numbers.
fn version_numbers(v: &str) -> Option<(u8, u8, u8)> {
    let mut it = v.split('.').map(|p| p.parse::<u8>().ok());
    let r = (it.next()??, it.next()??, it.next()??);
    it.next().is_none().then_some(r)
}

/// Reads one vendored file.
fn read(dir: &Path, name: &str) -> Result<String, GenError> {
    let p = dir.join(name);
    std::fs::read_to_string(&p).map_err(|e| GenError::Io(p, e.kind()))
}

/// The parsed vendored files that the tables come from.
#[derive(Debug, Clone)]
pub struct Ucd {
    /// `UnicodeData.txt`.
    pub unicode_data: UnicodeData,
    /// `CompositionExclusions.txt`.
    pub exclusions: BTreeSet<u32>,
    /// `CaseFolding.txt`, status C and F.
    pub folding: CaseFolding,
    /// The `NFKC_CF` mappings of `DerivedNormalizationProps.txt`.
    pub nfkc_cf: NfkcCf,
}

/// Reads and parses the vendored files from `ucd_dir`. Each file with a
/// version header must name [`UCD_VERSION`].
pub fn load(ucd_dir: &Path) -> Result<Ucd, GenError> {
    let unicode_data = read(ucd_dir, "UnicodeData.txt")?;
    let exclusions = read(ucd_dir, "CompositionExclusions.txt")?;
    let folding = read(ucd_dir, "CaseFolding.txt")?;
    let derived = read(ucd_dir, "DerivedNormalizationProps.txt")?;
    for (text, stem, file) in [
        (
            &exclusions,
            "CompositionExclusions",
            "CompositionExclusions.txt",
        ),
        (&folding, "CaseFolding", "CaseFolding.txt"),
        (
            &derived,
            "DerivedNormalizationProps",
            "DerivedNormalizationProps.txt",
        ),
    ] {
        if ucd::header_version(text, stem) != Some(UCD_VERSION) {
            return Err(GenError::Version(file));
        }
    }
    Ok(Ucd {
        unicode_data: ucd::parse_unicode_data(&unicode_data)?,
        exclusions: ucd::parse_composition_exclusions(&exclusions)?,
        folding: ucd::parse_case_folding(&folding)?,
        nfkc_cf: ucd::parse_nfkc_cf(&derived)?,
    })
}

/// Reads the vendored files from `ucd_dir` and returns the Rust source of
/// `tables.rs`.
pub fn generate(ucd_dir: &Path) -> Result<String, GenError> {
    let u = load(ucd_dir)?;
    let version =
        version_numbers(UCD_VERSION).ok_or(GenError::Build("UCD_VERSION is not a version"))?;
    let tables = build(&u.unicode_data, &u.exclusions, &u.folding, &u.nfkc_cf)?;
    Ok(render(version, &tables))
}

/// Reads and parses the vendored `NormalizationTest.txt` under `ucd_dir`,
/// for the conformance test of `fstp-unorm`.
pub fn normalization_test(ucd_dir: &Path) -> Result<Vec<ucd::NormCase>, GenError> {
    let text = read(ucd_dir, "NormalizationTest.txt")?;
    if ucd::header_version(&text, "NormalizationTest") != Some(UCD_VERSION) {
        return Err(GenError::Version("NormalizationTest.txt"));
    }
    Ok(ucd::parse_normalization_test(&text)?)
}
