//! The page forms of the applicant operations (design section 2.2 J4,
//! `web/src/applicant`), rewritten into the command codec's members
//! before the strict check (design section 3.7 step 1).
//!
//! The applicant pages send the forms people fill in, and the command
//! codec spells the domain's values. Two operations differ:
//!
//! - `proposal.submit` sends `{ethics: "none" | "declared",
//!   ethics_details?, notice_version}`. It becomes `{ethics:
//!   {issues_declared, text}, notice}`. A declaration of no issue carries
//!   the fixed text [`NO_ETHICS_ISSUE`], and a declared issue needs its
//!   details (R-SB-05). The submitted plan is the server's: dispatch
//!   names the proposal's latest recorded plan in the request before the
//!   action digest is made (`forms::name_plans`), so the digest, a
//!   pending action and its confirmation carry that plan (I-85).
//! - `proposal.record_plan` sends `{description, tasks: [{milestones:
//!   [{amount, start, due}]}]}`, with each day as `YYYY-MM-DD`. Each day
//!   becomes the instant of its start in UTC. The server draws the
//!   milestone ids and supplies the origin, the currency and the content
//!   digest of the description (`Derive::PlanForm`). The superseded plan
//!   is named before the digest, as for a submission.
//!
//! A body already in the codec's form, as an MCP tool sends it, passes
//! unchanged. Interim, pending Daniel: days are read in UTC, since the
//! cell holds no time zone database for the call's zone.

use fstp_access::OpSpec;
use fstp_json::{Array, Number, Object, Value};

use crate::ApiError;
use crate::forms::REQUEST_RULE;

/// The ethics text of a submission that declares no issue (R-SB-05).
pub(crate) const NO_ETHICS_ISSUE: &str = "No ethics issue is declared.";

fn bad() -> ApiError {
    ApiError::bad_request(REQUEST_RULE)
}

/// Rewrites the page form of `spec` in `request`, if it is one.
pub(crate) fn rewrite(spec: &OpSpec, request: &mut Object) -> Result<(), ApiError> {
    match spec.name {
        "proposal.submit" => submission(request),
        // R-EV-05 (lane mapp): the stage 2 revision page sends the plan
        // page form, which the revision records and submits in one entry.
        "proposal.record_plan" | "stage2.revise" => plan(request),
        _ => Ok(()),
    }
}

fn submission(request: &mut Object) -> Result<(), ApiError> {
    let Some(choice) = request
        .get("ethics")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return Ok(());
    };
    let details = request.remove("ethics_details");
    let (issues, text) = match (choice.as_str(), details) {
        ("none", None) => (false, NO_ETHICS_ISSUE.to_owned()),
        ("declared", Some(Value::String(d))) if !d.trim().is_empty() => (true, d),
        _ => return Err(bad()),
    };
    let mut ethics = Object::new();
    let _ = ethics.insert("issues_declared", Value::Bool(issues));
    let _ = ethics.insert("text", Value::String(text));
    let _ = request.insert("ethics", Value::Object(ethics));
    let version = request
        .remove("notice_version")
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or_else(bad)?;
    let canonical = !version.is_empty()
        && version.len() <= 9
        && version.bytes().all(|b| b.is_ascii_digit())
        && !version.starts_with('0');
    if !canonical {
        return Err(bad());
    }
    let n = Number::from_lexeme(&version).map_err(|_| bad())?;
    let _ = request.insert("notice", Value::Number(n));
    Ok(())
}

fn plan(request: &mut Object) -> Result<(), ApiError> {
    if !request.contains_key("description") {
        return Ok(());
    }
    let tasks = request
        .get("tasks")
        .and_then(Value::as_array)
        .ok_or_else(bad)?;
    let mut out = Array::new();
    for t in tasks.iter() {
        let milestones = t
            .as_object()
            .filter(|o| o.len() == 1)
            .and_then(|o| o.get("milestones"))
            .and_then(Value::as_array)
            .ok_or_else(bad)?;
        let mut ms = Array::new();
        for m in milestones.iter() {
            let m = m.as_object().filter(|o| o.len() == 3).ok_or_else(bad)?;
            let amount = m
                .get("amount")
                .filter(|v| v.as_str().is_some())
                .ok_or_else(bad)?;
            let mut row = Object::new();
            let _ = row.insert("amount", amount.clone());
            for k in ["start", "due"] {
                let day = m.get(k).and_then(Value::as_str).ok_or_else(bad)?;
                let micros = day_micros(day).ok_or_else(bad)?;
                let _ = row.insert(k, Value::String(micros.to_string()));
            }
            ms.push(Value::Object(row));
        }
        let mut task = Object::new();
        let _ = task.insert("milestones", Value::Array(ms));
        out.push(Value::Object(task));
    }
    let _ = request.insert("tasks", Value::Array(out));
    Ok(())
}

/// The microseconds since the Unix epoch of 00:00 UTC on `YYYY-MM-DD`,
/// for a real calendar day from 1970 to 9999, or `None`.
pub(crate) fn day_micros(day: &str) -> Option<i64> {
    let b = day.as_bytes();
    if b.len() != 10 || b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') {
        return None;
    }
    let num = |r: core::ops::Range<usize>| -> Option<i64> {
        let s = day.get(r)?;
        if !s.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        s.parse().ok()
    };
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    if y < 1970 || !(1..=12).contains(&m) || d < 1 {
        return None;
    }
    let leap = (y.rem_euclid(4) == 0 && y.rem_euclid(100) != 0) || y.rem_euclid(400) == 0;
    let days_in = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let month_len = *days_in.get(usize::try_from(m.checked_sub(1)?).ok()?)?;
    if d > month_len {
        return None;
    }
    // Days from 1970-01-01, on integers only (civil-to-days).
    let (yy, mm) = if m <= 2 {
        (y.checked_sub(1)?, m.checked_add(9)?)
    } else {
        (y, m.checked_sub(3)?)
    };
    let era = yy.div_euclid(400);
    let yoe = yy.checked_sub(era.checked_mul(400)?)?;
    let doy = mm
        .checked_mul(153)?
        .checked_add(2)?
        .div_euclid(5)
        .checked_add(d.checked_sub(1)?)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe.div_euclid(4))?
        .checked_sub(yoe.div_euclid(100))?
        .checked_add(doy)?;
    let days = era
        .checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)?;
    days.checked_mul(86_400_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-006, J4: the plan days are read as real calendar days in UTC.
    #[test]
    fn adr006_plan_days_are_calendar_days() {
        assert_eq!(day_micros("1970-01-01"), Some(0));
        assert_eq!(day_micros("2026-10-29"), Some(1_793_232_000_000_000));
        assert_eq!(day_micros("2024-02-29"), Some(1_709_164_800_000_000));
        assert_eq!(day_micros("2026-02-29"), None);
        assert_eq!(day_micros("2026-13-01"), None);
        assert_eq!(day_micros("2026-1-01"), None);
        assert_eq!(day_micros("1969-12-31"), None);
    }

    fn submit(members: Vec<(&str, Value)>) -> Result<Object, ApiError> {
        let mut o = Object::new();
        for (k, v) in members {
            let _ = o.insert(k, v);
        }
        submission(&mut o).map(|()| o)
    }

    /// R-SB-05, R-NG-06: a declaration of no issue carries the fixed text,
    /// a declared issue needs its details, and the notice version is a
    /// canonical decimal.
    #[test]
    fn r_sb_05_page_submission_form() {
        let ok = submit(vec![
            ("ethics", Value::from("none")),
            ("notice_version", Value::from("1")),
        ]);
        assert!(ok.is_ok());
        assert!(
            submit(vec![
                ("ethics", Value::from("declared")),
                ("notice_version", Value::from("1")),
            ])
            .is_err()
        );
        assert!(
            submit(vec![
                ("ethics", Value::from("none")),
                ("notice_version", Value::from("01")),
            ])
            .is_err()
        );
    }
}
