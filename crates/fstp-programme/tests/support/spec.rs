//! In-house markdown readers for the spec tables `fstp-programme` follows.
//!
//! The tests read `SPEC/` at test time, so a spec edit that the crate does
//! not follow fails a test. The table helpers follow
//! `crates/fstp-domain/tests/support/mod.rs`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use fstp_domain::rules::ParamId;

/// The repository's `SPEC/` directory.
pub(crate) fn spec_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../SPEC")
}

/// The text of `SPEC/<rel>`.
pub(crate) fn read_spec(rel: &str) -> Result<String, String> {
    let path = spec_dir().join(rel);
    std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// The lines after the heading line `heading` up to the next heading of the
/// same or a higher level.
pub(crate) fn section<'a>(doc: &'a str, heading: &str) -> Result<Vec<&'a str>, String> {
    let level = heading.chars().take_while(|c| *c == '#').count();
    let mut lines = doc.lines();
    if !lines.by_ref().any(|l| l.trim_end() == heading) {
        return Err(format!("heading {heading:?} not found"));
    }
    let mut out = Vec::new();
    for line in lines {
        let hashes = line.chars().take_while(|c| *c == '#').count();
        if hashes > 0 && hashes <= level && line.chars().nth(hashes) == Some(' ') {
            break;
        }
        out.push(line);
    }
    Ok(out)
}

/// The cells of one table line, trimmed, without the outer pipes.
pub(crate) fn cells(line: &str) -> Vec<String> {
    let inner = line.trim();
    let inner = inner.strip_prefix('|').unwrap_or(inner);
    let inner = inner.strip_suffix('|').unwrap_or(inner);
    inner.split('|').map(|c| c.trim().to_owned()).collect()
}

/// The body rows of the first table in `lines` whose header cells equal
/// `header`. Fails when no such table exists or a row has another number
/// of cells.
pub(crate) fn table(lines: &[&str], header: &[&str]) -> Result<Vec<Vec<String>>, String> {
    let mut iter = lines.iter().skip_while(|l| {
        let c = cells(l);
        !(l.trim_start().starts_with('|')
            && c.iter().map(String::as_str).eq(header.iter().copied()))
    });
    if iter.next().is_none() {
        return Err(format!("table with header {header:?} not found"));
    }
    match iter.next() {
        Some(sep)
            if cells(sep)
                .iter()
                .all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':')) => {}
        _ => return Err(format!("table {header:?} has no separator line")),
    }
    let mut rows = Vec::new();
    for line in iter {
        if !line.trim_start().starts_with('|') {
            break;
        }
        let row = cells(line);
        if row.len() != header.len() {
            return Err(format!(
                "row {line:?} has {} cells, expected {}",
                row.len(),
                header.len()
            ));
        }
        rows.push(row);
    }
    if rows.is_empty() {
        return Err(format!("table {header:?} has no rows"));
    }
    Ok(rows)
}

/// The parameter spelled `text` exactly, such as `"P-05"`.
pub(crate) fn param(text: &str) -> Result<ParamId, String> {
    ParamId::ALL
        .iter()
        .copied()
        .find(|p| p.spec_id() == text)
        .ok_or_else(|| format!("{text:?} is not a parameter of the catalogue"))
}

/// Every parameter from `from` to `to`, inclusive, in catalogue order.
fn param_range(from: ParamId, to: ParamId) -> Result<Vec<ParamId>, String> {
    let all = ParamId::ALL;
    let start = all.iter().position(|p| *p == from);
    let end = all.iter().position(|p| *p == to);
    match (start, end) {
        (Some(s), Some(e)) if s <= e => Ok(all.get(s..=e).unwrap_or(&[]).to_vec()),
        _ => Err(format!("bad parameter range {from:?} to {to:?}")),
    }
}

/// What one "Bounded by" cell of the creator table names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Bounds {
    /// The parameters, with ranges such as "P-61 to P-64" expanded.
    pub(crate) params: BTreeSet<ParamId>,
    /// Every other item of the cell, verbatim, such as "I-49".
    pub(crate) others: Vec<String>,
}

/// Reads a "Bounded by" cell: comma-separated items, each a parameter, a
/// parameter range or another reference. An item that mentions `P-` and is
/// not a parameter or a range fails, so no parameter is silently skipped.
pub(crate) fn bounds(cell: &str) -> Result<Bounds, String> {
    let mut out = Bounds::default();
    for item in cell.split(',').map(str::trim).filter(|i| !i.is_empty()) {
        if let Some((from, to)) = item.split_once(" to ") {
            if from.starts_with("P-") || to.starts_with("P-") {
                out.params
                    .extend(param_range(param(from.trim())?, param(to.trim())?)?);
                continue;
            }
        } else if item.starts_with("P-") {
            out.params.insert(param(item)?);
            continue;
        }
        if item.contains("P-") {
            return Err(format!("cannot read the bounded-by item {item:?}"));
        }
        out.others.push(item.to_owned());
    }
    Ok(out)
}

/// Every parameter token such as "P-45" in free text. A parameter range in
/// the text fails, because this reader does not expand ranges.
pub(crate) fn params_in_text(text: &str) -> Result<BTreeSet<ParamId>, String> {
    let mut out = BTreeSet::new();
    for (at, _) in text.match_indices("P-") {
        let digits: String = text
            .get(at.saturating_add(2)..)
            .unwrap_or("")
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if digits.len() != 2 {
            return Err(format!(
                "unreadable parameter token at byte {at} of {text:?}"
            ));
        }
        let token = format!("P-{digits}");
        let rest = text
            .get(at.saturating_add(token.len())..)
            .unwrap_or("")
            .trim_start();
        if rest.starts_with("to P-") {
            return Err(format!("parameter range in free text {text:?}"));
        }
        out.insert(param(&token)?);
    }
    Ok(out)
}

/// One row of the programme creator table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CreatorStep {
    /// The step number, 1 to 11.
    pub(crate) number: u8,
    /// The step name, such as "Funder and instrument".
    pub(crate) name: String,
    /// What the "Bounded by" cell names.
    pub(crate) bounds: Bounds,
}

/// The creator table of `SPEC/02-domain/programme-creator.md`, in order.
pub(crate) fn creator_steps() -> Result<Vec<CreatorStep>, String> {
    let doc = read_spec("02-domain/programme-creator.md")?;
    let lines = section(&doc, "## Programme creator")?;
    let rows = table(&lines, &["Step", "Captures", "Bounded by"])?;
    let mut out = Vec::new();
    for row in rows {
        let step = row.first().ok_or("empty creator row")?;
        let (number, name) = step
            .split_once(". ")
            .ok_or_else(|| format!("step cell {step:?} has no number"))?;
        let number: u8 = number
            .parse()
            .map_err(|_| format!("step cell {step:?} has no number"))?;
        let cell = row.get(2).ok_or("creator row has no Bounded by cell")?;
        out.push(CreatorStep {
            number,
            name: name.to_owned(),
            bounds: bounds(cell).map_err(|e| format!("step {number}: {e}"))?,
        });
    }
    Ok(out)
}

/// Every parameter the onboarding table of `programme-creator.md` names in
/// its Captures column, with the step that names it.
pub(crate) fn onboarding_params() -> Result<Vec<(String, ParamId)>, String> {
    let doc = read_spec("02-domain/programme-creator.md")?;
    let lines = section(&doc, "## Tenant onboarding")?;
    let rows = table(&lines, &["Step", "Captures"])?;
    let mut out = Vec::new();
    for row in rows {
        let step = row.first().ok_or("empty onboarding row")?.clone();
        let captures = row.get(1).ok_or("onboarding row has no Captures cell")?;
        for p in params_in_text(captures)? {
            out.push((step.clone(), p));
        }
    }
    Ok(out)
}

const PARAM_HEADER: &[&str] = &["ID", "Parameter", "SuperSAFE default", "Frozen"];

/// One row of either parameter table of `policy-parameters.md`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ParamRow {
    /// The parameter.
    pub(crate) id: ParamId,
    /// The "SuperSAFE default" cell, verbatim.
    pub(crate) supersafe: String,
}

/// Every row of both parameter tables, in spec order. Fails when a line
/// that starts with `| P-` is not a parsed row.
pub(crate) fn param_rows() -> Result<Vec<ParamRow>, String> {
    let doc = read_spec("02-domain/policy-parameters.md")?;
    let all: Vec<&str> = doc.lines().collect();
    let main_end = all
        .iter()
        .position(|l| l.trim_end() == "## Added parameters")
        .ok_or("no Added parameters heading")?;
    let main = table(all.get(..main_end).ok_or("bad split")?, PARAM_HEADER)?;
    let added = section(&doc, "## Added parameters")?;
    let more = table(&added, PARAM_HEADER)?;
    let rows: Vec<Vec<String>> = main.into_iter().chain(more).collect();
    let id_lines = all.iter().filter(|l| l.starts_with("| P-")).count();
    if id_lines != rows.len() {
        return Err(format!(
            "{id_lines} parameter lines, but {} parsed rows",
            rows.len()
        ));
    }
    let mut out = Vec::new();
    for row in rows {
        let id = param(row.first().ok_or("empty parameter row")?)?;
        let supersafe = row.get(2).ok_or("parameter row has no default")?.clone();
        out.push(ParamRow { id, supersafe });
    }
    Ok(out)
}
