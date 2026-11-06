//! The calibration fixture reader.
//!
//! A fixture is UTF-8 text, one record per line, fields separated by one
//! tab. Blank lines and lines starting with `#` are skipped. The first
//! line is `fstp-calib<TAB>1` and the first record is `corpus`:
//!
//! ```text
//! corpus    synthetic|consented
//! proposal  <id> clean|seeded
//! seed      <proposal> <seed> omission|claim
//! runs      <proposal> <count 1..=100>
//! finding   <proposal> <run> <finding> <type> info|minor|major <seed>|-
//! mark      <proposal> <finding> <reviewer> agreed|disputed
//! variant   <proposal> <base> injected|fluency
//! rating    <type> <unit> <rater> <integer>
//! ```
//!
//! A record may only name what an earlier record declared. The reader is
//! strict and bounded (TH-26): it never panics, refuses floats, and
//! returns the first error with its line number.

use std::collections::{BTreeMap, BTreeSet};

use crate::metrics::{
    Corpus, Dataset, Finding, Kind, Mark, Proposal, ProposalClass, SeedKind, Severity, VariantKind,
};

/// The largest accepted input, in bytes.
pub const MAX_INPUT: usize = 4 << 20;
/// The largest number of records.
pub const MAX_RECORDS: usize = 200_000;
/// The longest id, in bytes.
pub const MAX_ID: usize = 64;
/// The largest number of runs per proposal.
pub const MAX_RUNS: u32 = 100;
/// The largest absolute rating value.
pub const MAX_VALUE: i64 = 1_000_000;

/// Why a fixture was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureErrorKind {
    /// The input exceeds [`MAX_INPUT`].
    TooLarge,
    /// The input is not UTF-8.
    NotUtf8,
    /// The first line is not `fstp-calib<TAB>1`.
    BadHeader,
    /// The first record is not `corpus`.
    MissingCorpus,
    /// A second `corpus` record.
    DuplicateCorpus,
    /// An unknown record name.
    UnknownRecord,
    /// A known record with the wrong number of fields.
    FieldCount,
    /// An id outside `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`.
    BadId,
    /// A value outside its closed set or range.
    BadValue,
    /// A record repeats an earlier one.
    Duplicate,
    /// The proposal was not declared earlier.
    UnknownProposal,
    /// The seed was not declared earlier on that proposal.
    UnknownSeed,
    /// The finding was not declared earlier on that proposal.
    UnknownFinding,
    /// A seed on a clean proposal.
    SeedOnClean,
    /// A finding's run exceeds the proposal's run count.
    RunOutOfRange,
    /// A variant of itself, of a variant, or of which another is a variant.
    BadVariant,
    /// More than [`MAX_RECORDS`] records.
    TooManyRecords,
}

/// A refused fixture: the 1-based line and the reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixtureError {
    /// The 1-based line, or 0 for the whole input.
    pub line: usize,
    /// The reason.
    pub kind: FixtureErrorKind,
}

/// Reads a calibration fixture into a [`Dataset`].
pub fn parse(input: &[u8]) -> Result<Dataset, FixtureError> {
    use FixtureErrorKind as K;
    if input.len() > MAX_INPUT {
        return Err(FixtureError {
            line: 0,
            kind: K::TooLarge,
        });
    }
    let text = std::str::from_utf8(input).map_err(|e| FixtureError {
        line: input
            .get(..e.valid_up_to())
            .map_or(0, |ok| ok.iter().filter(|&&b| b == b'\n').count())
            .saturating_add(1),
        kind: K::NotUtf8,
    })?;
    let mut lines = text.split('\n').zip(1_usize..);
    match lines.next() {
        Some(("fstp-calib\t1", _)) => {}
        _ => {
            return Err(FixtureError {
                line: 1,
                kind: K::BadHeader,
            });
        }
    }
    let mut records = lines.filter(|(l, _)| !l.is_empty() && !l.starts_with('#'));
    let corpus = match records.next() {
        None => {
            return Err(FixtureError {
                line: 1,
                kind: K::MissingCorpus,
            });
        }
        Some((line, n)) => {
            let at = |kind| FixtureError { line: n, kind };
            match line.split('\t').collect::<Vec<_>>().as_slice() {
                ["corpus", c] => corpus_from(c).ok_or(at(K::BadValue))?,
                _ => return Err(at(K::MissingCorpus)),
            }
        }
    };
    let mut r = Reader {
        d: Dataset {
            corpus,
            proposals: BTreeMap::new(),
            ratings: BTreeMap::new(),
        },
        runs_set: BTreeSet::new(),
        bases: BTreeSet::new(),
    };
    for (count, (line, n)) in records.enumerate() {
        if count >= MAX_RECORDS {
            return Err(FixtureError {
                line: n,
                kind: K::TooManyRecords,
            });
        }
        r.record(line)
            .map_err(|kind| FixtureError { line: n, kind })?;
    }
    Ok(r.d)
}

struct Reader {
    d: Dataset,
    /// Proposals whose `runs` record was read.
    runs_set: BTreeSet<String>,
    /// Proposals that are the base of a variant.
    bases: BTreeSet<String>,
}

impl Reader {
    fn record(&mut self, line: &str) -> Result<(), FixtureErrorKind> {
        use FixtureErrorKind as K;
        let fields: Vec<&str> = line.split('\t').collect();
        match fields.as_slice() {
            ["corpus", _] => Err(K::DuplicateCorpus),
            ["proposal", id, class] => {
                let id = ident(id)?;
                let class = match *class {
                    "clean" => ProposalClass::Clean,
                    "seeded" => ProposalClass::Seeded,
                    _ => return Err(K::BadValue),
                };
                if self.d.proposals.contains_key(id) {
                    return Err(K::Duplicate);
                }
                self.d.proposals.insert(
                    id.to_owned(),
                    Proposal {
                        class,
                        runs: 1,
                        variant: None,
                        seeds: BTreeMap::new(),
                        findings: BTreeMap::new(),
                        marks: BTreeMap::new(),
                    },
                );
                Ok(())
            }
            ["seed", p, s, kind] => {
                let p = self.proposal(p)?;
                let s = ident(s)?;
                let kind = match *kind {
                    "omission" => SeedKind::Omission,
                    "claim" => SeedKind::Claim,
                    _ => return Err(K::BadValue),
                };
                if p.class == ProposalClass::Clean {
                    return Err(K::SeedOnClean);
                }
                if p.seeds.insert(s.to_owned(), kind).is_some() {
                    return Err(K::Duplicate);
                }
                Ok(())
            }
            ["runs", p, count] => {
                let id = ident(p)?;
                let count = uint(count, MAX_RUNS.into())
                    .and_then(|v| u32::try_from(v).ok())
                    .filter(|&v| v >= 1)
                    .ok_or(K::BadValue)?;
                let p = self.proposal(id)?;
                p.runs = count;
                if !self.runs_set.insert(id.to_owned()) {
                    return Err(K::Duplicate);
                }
                Ok(())
            }
            ["finding", p, run, f, kind, severity, seed] => {
                let p = self.proposal(p)?;
                let run = uint(run, MAX_RUNS.into())
                    .and_then(|v| u32::try_from(v).ok())
                    .filter(|&v| v >= 1)
                    .ok_or(K::BadValue)?;
                let f = ident(f)?;
                let kind = kind_from(kind).ok_or(K::BadValue)?;
                let severity = match *severity {
                    "info" => Severity::Info,
                    "minor" => Severity::Minor,
                    "major" => Severity::Major,
                    _ => return Err(K::BadValue),
                };
                let seed = match *seed {
                    "-" => None,
                    s => {
                        let s = ident(s)?;
                        if !p.seeds.contains_key(s) {
                            return Err(K::UnknownSeed);
                        }
                        Some(s.to_owned())
                    }
                };
                if run > p.runs {
                    return Err(K::RunOutOfRange);
                }
                if p.findings.contains_key(f) {
                    return Err(K::Duplicate);
                }
                p.findings.insert(
                    f.to_owned(),
                    Finding {
                        run,
                        kind,
                        severity,
                        seed,
                    },
                );
                Ok(())
            }
            ["mark", p, f, reviewer, mark] => {
                let p = self.proposal(p)?;
                let f = ident(f)?;
                let reviewer = ident(reviewer)?;
                let mark = match *mark {
                    "agreed" => Mark::Agreed,
                    "disputed" => Mark::Disputed,
                    _ => return Err(K::BadValue),
                };
                if !p.findings.contains_key(f) {
                    return Err(K::UnknownFinding);
                }
                let key = (f.to_owned(), reviewer.to_owned());
                if p.marks.insert(key, mark).is_some() {
                    return Err(K::Duplicate);
                }
                Ok(())
            }
            ["variant", v, base, kind] => {
                let v = ident(v)?;
                let base = ident(base)?;
                let kind = match *kind {
                    "injected" => VariantKind::Injected,
                    "fluency" => VariantKind::Fluency,
                    _ => return Err(K::BadValue),
                };
                let base_is_variant = self.proposal(base)?.variant.is_some();
                let v_is_base = self.bases.contains(v);
                let vp = self.proposal(v)?;
                if vp.variant.is_some() {
                    return Err(K::Duplicate);
                }
                if v == base || base_is_variant || v_is_base {
                    return Err(K::BadVariant);
                }
                vp.variant = Some((base.to_owned(), kind));
                self.bases.insert(base.to_owned());
                Ok(())
            }
            ["rating", kind, unit, rater, value] => {
                let kind = kind_from(kind).ok_or(K::BadValue)?;
                let unit = ident(unit)?;
                let rater = ident(rater)?;
                let value = int(value).ok_or(K::BadValue)?;
                let key = (kind, unit.to_owned(), rater.to_owned());
                if self.d.ratings.insert(key, value).is_some() {
                    return Err(K::Duplicate);
                }
                Ok(())
            }
            [
                "corpus" | "proposal" | "seed" | "runs" | "finding" | "mark" | "variant" | "rating",
                ..,
            ] => Err(K::FieldCount),
            _ => Err(K::UnknownRecord),
        }
    }

    fn proposal(&mut self, id: &str) -> Result<&mut Proposal, FixtureErrorKind> {
        let id = ident(id)?;
        self.d
            .proposals
            .get_mut(id)
            .ok_or(FixtureErrorKind::UnknownProposal)
    }
}

fn corpus_from(s: &str) -> Option<Corpus> {
    match s {
        "synthetic" => Some(Corpus::Synthetic),
        "consented" => Some(Corpus::Consented),
        _ => None,
    }
}

fn kind_from(s: &str) -> Option<Kind> {
    Kind::ALL.into_iter().find(|k| k.name() == s)
}

fn ident(s: &str) -> Result<&str, FixtureErrorKind> {
    let ok = !s.is_empty()
        && s.len() <= MAX_ID
        && s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(s)
    } else {
        Err(FixtureErrorKind::BadId)
    }
}

/// A decimal of 1 to 7 ASCII digits, at most `max`.
fn uint(s: &str, max: u64) -> Option<u64> {
    if s.is_empty() || s.len() > 7 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok().filter(|&v| v <= max)
}

/// An optional `-` and a decimal of at most [`MAX_VALUE`].
fn int(s: &str) -> Option<i64> {
    let max = MAX_VALUE.unsigned_abs();
    match s.strip_prefix('-') {
        Some(rest) => uint(rest, max).and_then(|v| i64::try_from(v).ok()?.checked_neg()),
        None => uint(s, max).and_then(|v| i64::try_from(v).ok()),
    }
}
