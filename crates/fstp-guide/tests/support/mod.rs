//! The one place the W2c Guide tests name the `fstp-guide` API, plus the
//! test references they compare against (M4 design section 3.10).
//!
//! # The adapter
//!
//! Every test reaches the crate only through the functions of this
//! module, which call the production API. The tests were written red
//! against the W0 stubs, and [`Fail::Missing`] stays so that their
//! matches keep reading as they did. The production API never yields it.
//!
//! Design section 3.10 names `parse_template`, `parse_markdown` and
//! `render`, one resolver per placeholder, and I-51 for locked text. The
//! crate builds the rest under these names:
//!
//! - `Template::placeholders(&self)`: the placeholder keys in document
//!   order, one per occurrence;
//! - `fstp_guide::RESOLVERS`: one row per known key, with its source and,
//!   for a `P-NN` key, its parameter;
//! - `fstp_guide::GuideInputs` and `fstp_guide::bind(&Template, &inputs)`:
//!   the bound template, or a refusal that names the first key that does
//!   not resolve;
//! - `RenderedGuide::html()`, `RenderedGuide::canonical()` (the bytes the
//!   publication digest is taken over) and `RenderedGuide::bound()`: one
//!   entry per placeholder occurrence, with its key, its parameter, its
//!   text and whether it is editable;
//! - `fstp_guide::missing_sections(&Template)`: the names of the required
//!   sections of `SPEC/02-domain/guide-for-applicants.md` the template
//!   lacks (I-52), as `fstp_guide::preview` reports them to the creator.
//!
//! Errors reach the tests only as text, so the error types stay free. A
//! refusal must name what it refuses: an unknown placeholder by its key,
//! an unresolved binding by its key.
//!
//! # The references
//!
//! The tests read the specification at test time: the Horizon Europe
//! template, its placeholders and the table of required sections. The
//! synthetic policy is the SuperSAFE fixture of `fstp-programme`, compiled
//! as a draft. Each fixture mutation edits the canonical spec text at one
//! unique place and compiles again.

#![allow(dead_code, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use fstp_domain::CATALOGUE;
use fstp_domain::id::{PolicyVersionId, ProgrammeId};
use fstp_domain::rules::ParamId;
use fstp_domain::time::{Timestamp, ZoneName};
use fstp_guide::GuideError;
use fstp_programme::{
    CompileIds, Compiled, FunderProfile, ProgrammeSpec, compile, decode_spec, encode_spec,
    supersafe_fixture,
};

/// The specification's Horizon Europe Guide template.
pub(crate) const SPEC_TEMPLATE: &str =
    include_str!("../../../../SPEC/profiles/horizon-europe/guide-for-applicants.md");

/// The specification's Guide rules, with the table of required sections.
pub(crate) const SPEC_GUIDE_RULES: &str =
    include_str!("../../../../SPEC/02-domain/guide-for-applicants.md");

/// Why an adapter call did not give a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Fail {
    /// The crate refused, with this text.
    Refused(String),
    /// The API is not implemented yet: a W0 stub refused, or the designed
    /// function does not exist. A test that meets this is red.
    Missing(String),
}

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fail::Refused(m) => write!(f, "refused: {m}"),
            Fail::Missing(m) => write!(f, "not implemented yet: {m}"),
        }
    }
}

/// Maps a crate error to its text and its debug form.
fn fail(e: &GuideError) -> Fail {
    Fail::Refused(format!("{e} ({e:?})"))
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// `fstp_guide::parse_markdown`, keeping only whether it accepted.
pub(crate) fn parse_markdown(bytes: &[u8]) -> Result<(), Fail> {
    fstp_guide::parse_markdown(bytes)
        .map(|_| ())
        .map_err(|e| fail(&e))
}

/// Whether two parses of `bytes` give equal documents. Refuses as a parse
/// does.
pub(crate) fn parse_markdown_is_stable(bytes: &[u8]) -> Result<bool, Fail> {
    let a = fstp_guide::parse_markdown(bytes).map_err(|e| fail(&e))?;
    let b = fstp_guide::parse_markdown(bytes).map_err(|e| fail(&e))?;
    Ok(a == b)
}

/// `fstp_guide::parse_template`, keeping only whether it accepted.
pub(crate) fn parse_template(bytes: &[u8]) -> Result<(), Fail> {
    fstp_guide::parse_template(bytes)
        .map(|_| ())
        .map_err(|e| fail(&e))
}

/// Whether two parses of `bytes` give equal templates.
pub(crate) fn parse_template_is_stable(bytes: &[u8]) -> Result<bool, Fail> {
    let a = fstp_guide::parse_template(bytes).map_err(|e| fail(&e))?;
    let b = fstp_guide::parse_template(bytes).map_err(|e| fail(&e))?;
    Ok(a == b)
}

/// The placeholder keys of the template `bytes`, one per occurrence, in
/// document order. Designed: `Template::placeholders`.
pub(crate) fn placeholders(bytes: &[u8]) -> Result<Vec<String>, Fail> {
    let t = fstp_guide::parse_template(bytes).map_err(|e| fail(&e))?;
    Ok(t.placeholders().into_iter().map(str::to_owned).collect())
}

// ---------------------------------------------------------------------------
// Resolvers
// ---------------------------------------------------------------------------

/// Where a resolver reads its value (M4 design section 3.10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Source {
    /// The draft or frozen policy.
    Policy,
    /// The call record.
    CallRecord,
    /// The programme artefacts.
    Artefacts,
    /// Anything else the crate binds, such as the Guide version or the
    /// platform address. The design names no source for these.
    Other,
}

/// One row of the resolver table. Designed: `fstp_guide::RESOLVERS`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolverRow {
    /// The placeholder key, such as `P-04.min`.
    pub(crate) key: String,
    /// Where it reads its value.
    pub(crate) source: Source,
    /// The parameter it reads, for a parameter-bound key.
    pub(crate) param: Option<ParamId>,
}

/// Every resolver the crate holds, in its own order.
pub(crate) fn resolvers() -> Result<Vec<ResolverRow>, Fail> {
    Ok(fstp_guide::RESOLVERS
        .iter()
        .map(|r| ResolverRow {
            key: r.key.to_owned(),
            source: match r.source {
                fstp_guide::Source::Policy => Source::Policy,
                fstp_guide::Source::CallRecord => Source::CallRecord,
                fstp_guide::Source::Artefacts => Source::Artefacts,
                fstp_guide::Source::Other => Source::Other,
            },
            param: r.param,
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Binding and rendering
// ---------------------------------------------------------------------------

/// The synthetic call record the tests bind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CallRecord {
    /// The call's public identifier.
    pub(crate) identifier: String,
    /// When it opens, in microseconds since the epoch.
    pub(crate) opens_micros: i64,
    /// Its deadline, in microseconds since the epoch.
    pub(crate) deadline_micros: i64,
    /// The IANA zone of the deadline.
    pub(crate) zone: String,
    /// The call budget, as an ADR-006 string in the programme currency.
    pub(crate) budget: String,
}

/// Everything one Guide is bound from: a compiled draft and a call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Inputs {
    /// The compiled draft: its policy, its artefacts and its gaps.
    pub(crate) compiled: Compiled,
    /// The call record.
    pub(crate) call: CallRecord,
    /// The Guide version, 1 at publication in M4.
    pub(crate) guide_version: u32,
    /// The platform address applicants create an account on.
    pub(crate) platform_url: String,
    /// Whether the cell has a pre-check provider (Q38). The Guide then
    /// describes the available pre-check in place of the Q38 C note.
    pub(crate) precheck_available: bool,
}

/// One bound placeholder occurrence of a rendered Guide.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Bound {
    /// The placeholder key.
    pub(crate) key: String,
    /// The parameter it shows, for a parameter-bound key.
    pub(crate) param: Option<ParamId>,
    /// The text it shows, without markup.
    pub(crate) text: String,
    /// Whether a person may edit it by hand. Never true for
    /// parameter-bound text (I-51).
    pub(crate) editable: bool,
}

/// A rendered Guide as the tests read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Rendered {
    /// The HTML document.
    pub(crate) html: String,
    /// The canonical document the publication digest is taken over.
    pub(crate) canonical: Vec<u8>,
    /// Every bound placeholder occurrence, in document order.
    pub(crate) bound: Vec<Bound>,
}

impl Rendered {
    /// The bound occurrences of `key`.
    pub(crate) fn of<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a Bound> + 'a {
        self.bound.iter().filter(move |b| b.key == key)
    }

    /// The text of the single occurrence of `key`.
    pub(crate) fn text<'a>(&'a self, key: &str) -> Result<&'a str, String> {
        let all: Vec<&'a Bound> = self.bound.iter().filter(|b| b.key == key).collect();
        match all.as_slice() {
            [one] => Ok(&one.text),
            other => Err(format!(
                "{key}: expected one bound occurrence, got {}",
                other.len()
            )),
        }
    }
}

/// Parses `template`, binds it to `inputs` and renders it.
/// Designed: `parse_template`, then `bind`, then `render`.
pub(crate) fn guide_from(template: &[u8], inputs: &Inputs) -> Result<Rendered, Fail> {
    let t = fstp_guide::parse_template(template).map_err(|e| fail(&e))?;
    let call = guide_call(&inputs.call)?;
    let bound = fstp_guide::bind(&t, &guide_inputs(inputs, &call)).map_err(|e| fail(&e))?;
    let r = fstp_guide::render(&bound).map_err(|e| fail(&e))?;
    Ok(Rendered {
        html: r.html().as_str().to_owned(),
        canonical: r.canonical().to_vec(),
        bound: r
            .bound()
            .iter()
            .map(|b| Bound {
                key: b.key.to_owned(),
                param: b.param,
                text: b.text.clone(),
                editable: b.editable,
            })
            .collect(),
    })
}

/// The synthetic data protection summary the tests bind. It is not the
/// programme's notice and not legal text.
pub(crate) const SYNTHETIC_DATA_PROTECTION: &str =
    "Synthetic data protection summary for tests. It is not a privacy notice.";

/// The synthetic privacy statement address the tests bind.
pub(crate) const SYNTHETIC_PRIVACY_URL: &str = "https://privacy.fstp.example/statement";

/// The crate's call record of `call`.
pub(crate) fn guide_call(call: &CallRecord) -> Result<fstp_guide::GuideCall, Fail> {
    Ok(fstp_guide::GuideCall {
        identifier: call.identifier.clone(),
        opens: Timestamp::from_micros(call.opens_micros),
        deadline: Timestamp::from_micros(call.deadline_micros),
        deadline_zone: ZoneName::new(&call.zone)
            .ok_or_else(|| Fail::Refused(format!("not a zone: {:?}", call.zone)))?,
        budget: call.budget.clone(),
    })
}

/// The crate's inputs of `inputs`, over `call`.
pub(crate) fn guide_inputs<'a>(
    inputs: &'a Inputs,
    call: &'a fstp_guide::GuideCall,
) -> fstp_guide::GuideInputs<'a> {
    fstp_guide::GuideInputs {
        compiled: &inputs.compiled,
        publication: None,
        call,
        guide_version: inputs.guide_version,
        platform_url: &inputs.platform_url,
        data_protection_summary: Some(SYNTHETIC_DATA_PROTECTION),
        privacy_statement_url: Some(SYNTHETIC_PRIVACY_URL),
        texts: &fstp_guide::NoStoredTexts,
        precheck_available: inputs.precheck_available,
    }
}

/// The shipped Horizon Europe Guide bound to `inputs`.
pub(crate) fn guide(inputs: &Inputs) -> Result<Rendered, Fail> {
    guide_from(SPEC_TEMPLATE.as_bytes(), inputs)
}

/// The required sections the template `bytes` lacks, by the names of the
/// specification's table (I-52). Designed: `fstp_guide::missing_sections`.
pub(crate) fn missing_sections(bytes: &[u8]) -> Result<BTreeSet<String>, Fail> {
    let t = fstp_guide::parse_template(bytes).map_err(|e| fail(&e))?;
    Ok(fstp_guide::missing_sections(&t)
        .into_iter()
        .map(str::to_owned)
        .collect())
}

// ---------------------------------------------------------------------------
// References read from the specification
// ---------------------------------------------------------------------------

/// The placeholder keys of `text`, one per occurrence, in order: the text
/// between each `{{` and the next `}}`.
pub(crate) fn reference_placeholders(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        match after.find("}}") {
            Some(end) => {
                out.push(after[..end].to_owned());
                rest = &after[end + 2..];
            }
            None => break,
        }
    }
    out
}

/// The section names of the table under "## Required sections" in
/// `SPEC/02-domain/guide-for-applicants.md`, in order.
pub(crate) fn required_sections() -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in SPEC_GUIDE_RULES.lines() {
        if line.starts_with("## ") {
            inside = line == "## Required sections";
            continue;
        }
        if !inside || !line.starts_with('|') {
            continue;
        }
        let first = line
            .trim_matches('|')
            .split('|')
            .next()
            .unwrap_or("")
            .trim();
        if first.is_empty() || first == "Section" || first.starts_with("---") {
            continue;
        }
        out.push(first.to_owned());
    }
    out
}

/// The numbered `## N. ...` section headings of the template, in order.
pub(crate) fn template_sections(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| {
            l.strip_prefix("## ")
                .and_then(|r| r.split_once(". "))
                .is_some_and(|(n, _)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        })
        .map(str::to_owned)
        .collect()
}

/// `text` without the section whose heading is `heading`: from that line
/// up to the next `## ` heading or the end.
pub(crate) fn without_section(text: &str, heading: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut skipping = false;
    let mut found = false;
    for line in text.split_inclusive('\n') {
        let bare = line.trim_end_matches('\n');
        if bare == heading {
            skipping = true;
            found = true;
            continue;
        }
        if skipping && bare.starts_with("## ") {
            skipping = false;
        }
        if !skipping {
            out.push_str(line);
        }
    }
    if found {
        Ok(out)
    } else {
        Err(format!("no heading {heading:?}"))
    }
}

/// The parameter whose specification id is `spec_id`, such as `"P-04"`.
pub(crate) fn param(spec_id: &str) -> Option<ParamId> {
    CATALOGUE
        .iter()
        .map(|r| r.id)
        .find(|p| p.spec_id() == spec_id)
}

/// The parameter a placeholder key names: the `P-NN` before the first
/// dot, if the key starts with one.
pub(crate) fn key_param(key: &str) -> Option<ParamId> {
    let head = key.split('.').next().unwrap_or(key);
    if head.starts_with("P-") {
        param(head)
    } else {
        None
    }
}

/// The maximal runs of ASCII digits and inner dots in `text`, such as
/// `["75.00"]` for "above 75.00 %".
pub(crate) fn numbers(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in text.chars() {
        if c.is_ascii_digit() || (c == '.' && !cur.is_empty()) {
            cur.push(c);
        } else if !cur.is_empty() {
            out.push(cur.trim_end_matches('.').to_owned());
            cur.clear();
        }
    }
    if !cur.is_empty() {
        out.push(cur.trim_end_matches('.').to_owned());
    }
    out
}

// ---------------------------------------------------------------------------
// The synthetic policy
// ---------------------------------------------------------------------------

/// The programme id every test compiles for.
pub(crate) const PROGRAMME: ProgrammeId = ProgrammeId::from_raw(0x5afe_0000_0001);
/// The policy version id every test compiles to.
pub(crate) const VERSION: PolicyVersionId = PolicyVersionId::from_raw(0x5afe_0000_0002);

/// The SuperSAFE fixture spec.
pub(crate) fn supersafe_spec() -> Result<ProgrammeSpec, String> {
    supersafe_fixture()
        .map(|f| f.spec)
        .map_err(|e| format!("fixture: {e:?}"))
}

/// Compiles `spec` as a first draft version under Horizon Europe.
pub(crate) fn compile_draft(spec: &ProgrammeSpec) -> Result<Compiled, String> {
    compile(
        spec,
        &FunderProfile::horizon_europe(),
        CompileIds::new(PROGRAMME, VERSION, None),
    )
    .map_err(|e| format!("compile: {e:?}"))
}

/// The SuperSAFE spec with `from` replaced by `to` in its canonical text.
/// `from` must occur exactly once, so each mutation is at one place.
pub(crate) fn mutated_spec(from: &str, to: &str) -> Result<ProgrammeSpec, String> {
    let text = encode_spec(&supersafe_spec()?);
    let n = text.matches(from).count();
    if n != 1 {
        return Err(format!("{from:?} occurs {n} times in the canonical spec"));
    }
    decode_spec(text.replacen(from, to, 1).as_bytes()).map_err(|e| format!("decode: {e:?}"))
}

/// The synthetic call: opens 2026-11-02 09:00 UTC, closes 2027-01-29
/// 16:00 UTC (Europe/Brussels), budget 250000.00.
pub(crate) fn synthetic_call() -> CallRecord {
    CallRecord {
        identifier: "SUPERSAFE-OC1".to_owned(),
        opens_micros: 1_793_610_000_000_000,
        deadline_micros: 1_801_238_400_000_000,
        zone: "Europe/Brussels".to_owned(),
        budget: "250000.00".to_owned(),
    }
}

/// The inputs of a Guide over `compiled` and the synthetic call.
pub(crate) fn inputs_over(compiled: Compiled) -> Inputs {
    Inputs {
        compiled,
        call: synthetic_call(),
        guide_version: 1,
        platform_url: "https://a.fstp.example/".to_owned(),
        precheck_available: false,
    }
}

/// The inputs of the SuperSAFE Guide.
pub(crate) fn supersafe_inputs() -> Result<Inputs, String> {
    Ok(inputs_over(compile_draft(&supersafe_spec()?)?))
}

/// One edit of the SuperSAFE fixture that changes one bound parameter.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Mutation {
    /// The placeholder key whose text must change.
    pub(crate) key: &'static str,
    /// The unique canonical spec text to replace.
    pub(crate) from: &'static str,
    /// Its replacement.
    pub(crate) to: &'static str,
}

/// One mutation per parameter-bound placeholder key of the shipped
/// template. A test checks that the list covers every such key.
pub(crate) const MUTATIONS: &[Mutation] = &[
    Mutation {
        key: "P-01.table",
        from: r#""name":"Relevance and impact","weight":40"#,
        to: r#""name":"Relevance and impact","weight":45"#,
    },
    Mutation {
        key: "P-02",
        from: r#""p02_threshold":"75.00""#,
        to: r#""p02_threshold":"80.00""#,
    },
    Mutation {
        key: "P-03",
        from: r#""p03_reviewers":2"#,
        to: r#""p03_reviewers":3"#,
    },
    Mutation {
        key: "P-04.min",
        from: r#""min":"5000.00""#,
        to: r#""min":"6000.00""#,
    },
    Mutation {
        key: "P-04.max",
        from: r#""max":"100000.00""#,
        to: r#""max":"90000.00""#,
    },
    Mutation {
        key: "P-05",
        from: r#""p05_recipient_cap":"400000.00""#,
        to: r#""p05_recipient_cap":"300000.00""#,
    },
    Mutation {
        key: "P-07",
        from: r#""p07_stage2_window":{"days":28}"#,
        to: r#""p07_stage2_window":{"days":21}"#,
    },
    Mutation {
        key: "P-08",
        from: r#""p08_notification_deadline":{"working_days":5}"#,
        to: r#""p08_notification_deadline":{"working_days":6}"#,
    },
    Mutation {
        key: "P-09.list",
        from: r#""text":"English""#,
        to: r#""text":"English only""#,
    },
    Mutation {
        key: "P-11.description",
        from: r#""p11_anonymity":"anonymous""#,
        to: r#""p11_anonymity":"named""#,
    },
    Mutation {
        key: "P-13.list",
        from: r#""description":"IRC members, employers, co-workers, relatives""#,
        to: r#""description":"IRC members and their employers""#,
    },
    Mutation {
        key: "P-23.per_day",
        from: r#""per_day_per_proposal":1"#,
        to: r#""per_day_per_proposal":2"#,
    },
    Mutation {
        key: "P-23.per_call",
        from: r#""per_call_per_proposal":5"#,
        to: r#""per_call_per_proposal":4"#,
    },
    Mutation {
        key: "P-25",
        from: r#""p25_language":"en""#,
        to: r#""p25_language":"de""#,
    },
    Mutation {
        key: "P-26.list",
        from: r#""GPL-3.0-or-later","MIT"]"#,
        to: r#""GPL-3.0-or-later"]"#,
    },
    Mutation {
        key: "P-29",
        from: r#""instrument":"mou""#,
        to: r#""instrument":"grant""#,
    },
    Mutation {
        key: "P-30.description",
        from: r#""qtsp_remote_qes","approved_advanced"]"#,
        to: r#""qtsp_remote_qes"]"#,
    },
    Mutation {
        key: "P-34.list",
        from: r#""spdx_licence","report"]"#,
        to: r#""spdx_licence"]"#,
    },
    Mutation {
        key: "P-36",
        from: r#""p36_bank_change_hold":{"days":7}"#,
        to: r#""p36_bank_change_hold":{"days":8}"#,
    },
    Mutation {
        key: "P-41",
        from: r#""p41_funder_retention":{"years":1}"#,
        to: r#""p41_funder_retention":{"years":2}"#,
    },
    Mutation {
        key: "P-55.list",
        from: r#""name":"Placeholder activity type B, pending the closed list (O-23)""#,
        to: r#""name":"Synthetic activity type B""#,
    },
    Mutation {
        key: "P-57.end",
        from: r#""end":"2028-12-31""#,
        to: r#""end":"2028-06-30""#,
    },
    Mutation {
        key: "P-59",
        from: r#""p59_payment_target":{"days":15}"#,
        to: r#""p59_payment_target":{"days":20}"#,
    },
    Mutation {
        key: "P-61",
        from: r#""p61_complaint_window":{"working_days":10}"#,
        to: r#""p61_complaint_window":{"working_days":11}"#,
    },
    Mutation {
        key: "P-62",
        from: r#""p62_coordinator_response":{"working_days":15}"#,
        to: r#""p62_coordinator_response":{"working_days":16}"#,
    },
    Mutation {
        key: "P-63",
        from: r#""p63_escalation_window":{"working_days":10}"#,
        to: r#""p63_escalation_window":{"working_days":12}"#,
    },
    Mutation {
        key: "P-64",
        from: r#""p64_irc_response":{"working_days":20}"#,
        to: r#""p64_irc_response":{"working_days":21}"#,
    },
    Mutation {
        key: "P-65.description",
        from: r#""p65_partial_claim_evidence":"public_deliverables""#,
        to: r#""p65_partial_claim_evidence":"progress_report_with_final_deliverables""#,
    },
    Mutation {
        key: "P-67.description",
        from: r#""p67_unclaimed_balances":"return_to_fstp_budget""#,
        to: r#""p67_unclaimed_balances":"lapse_and_report_unspent""#,
    },
    Mutation {
        key: "P-75.description",
        from: r#""p75_agent_content_reads":false"#,
        to: r#""p75_agent_content_reads":true"#,
    },
    Mutation {
        key: "P-77.description",
        from: r#""p77_mcp_binding_actions":"draft_only""#,
        to: r#""p77_mcp_binding_actions":"allowed""#,
    },
];

/// Whether the canonical spelling of the parse of `bytes` parses to an
/// equal document, and is itself canonical.
pub(crate) fn markdown_round_trips(bytes: &[u8]) -> Result<bool, Fail> {
    let doc = fstp_guide::parse_markdown(bytes).map_err(|e| fail(&e))?;
    let text = doc.to_markdown();
    let again = fstp_guide::parse_markdown(text.as_bytes()).map_err(|e| fail(&e))?;
    Ok(again == doc && again.to_markdown() == text)
}
