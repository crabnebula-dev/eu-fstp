//! The Guide checks of the report: `GuideSectionMissing` (I-52) and
//! `GuideBindingUnresolved` (I-51) (M4 design sections 3.2 and 3.10).
//!
//! [`guide_facts`] runs the Guide API over the draft:
//!
//! 1. `fstp_guide::parse_template` parses the template of the draft's
//!    Guide profile. A template that does not parse fails both checks
//!    closed.
//! 2. The draft spec is compiled as the Guide reads it ([`draft_compiled`]):
//!    the head policy, with the value of each set artefact field the
//!    creator holds, and a gap for each field with no value. A policy
//!    field reads from the head, which the ledger last recorded. A held or
//!    template value of a policy field adds only the free texts the policy
//!    does not hold, such as the P-01 criterion names and the P-13 and
//!    P-55 descriptions, and only while it agrees with the head. A value
//!    that a later policy version replaced, such as by a core
//!    `EditPolicy`, is ignored, so the head stands and its empty free
//!    texts fail closed.
//! 3. `fstp_guide::preview` names every required section the template
//!    lacks (`fstp_guide::missing_sections`, I-52) and every placeholder
//!    that does not resolve through the one resolver of its key (I-51).
//!
//! Only placeholders bound to the draft count: those whose resolver reads
//! the policy or the programme artefacts. A placeholder of the call
//! record, the Guide version, the platform address or the data
//! protection texts resolves when the Guide is generated, from facts no
//! draft holds. So the preview supplies none of them, and their refusals
//! are not draft failures.
//!
//! Interim readings, each pending Daniel:
//!
//! - A saved value the creator does not hold reads as follows. An
//!   artefact field is a gap, so its placeholder is unresolved and fails
//!   closed. A policy field reads back from the head policy, whose free
//!   texts are empty (`fstp_programme::policy_spec`). So a P-01, P-13 or
//!   P-55 text that is not held fails closed too.
//! - A stored text (ADR-007), such as P-09 wording, lives in the shell's
//!   text store, which the creator never reads. The draft policy names it
//!   by `TextRef`, so the preview reads each stored text as one fixed
//!   non-empty text, and its item counts as resolved from the policy. The
//!   resolver still checks every inline item beside it, so an empty one
//!   fails.
//!   The Guide generated at publication reads the text store, and refuses
//!   by key a text it does not hold.
//!
//! [`guide_scan`] is a text scan kept beside the Guide API. It reads two
//! things of a template text. A heading is a line that starts with `#`.
//! A placeholder is the text between `{{` and the next `}}`; an opening
//! without a closing on its line is a placeholder that never resolves. It
//! is total and fuzzed (`guide_scan`).

use std::collections::BTreeSet;

use fstp_domain::id::{ProgrammeId, TextRef};
use fstp_domain::policy::PolicyVersion;
use fstp_domain::rules::CATALOGUE;
use fstp_domain::time::{Timestamp, ZoneName};
use fstp_guide::{
    FunderProfile as GuideProfile, GuideCall, GuideError, GuideInputs, RESOLVERS, Source,
    StoredTexts,
};
use fstp_programme::{
    CompileIds, Compiled, FIELDS, FieldId, FieldKind, FieldValue, FunderProfile, ProgrammeSpec,
    compile,
};

use crate::state::{CreatorState, Draft};

/// Both Guide checks fail closed while the template does not parse.
pub(crate) const GUIDE_SEAM: &str =
    "the Guide preview: fstp_guide::parse_template refuses the profile's Guide template";

/// Both Guide checks fail closed without a profile.
pub(crate) const NO_GUIDE_PROFILE: &str =
    "no funder profile was passed, so fstp_guide has no Guide template to preview";

/// Both Guide checks fail closed when the draft spec does not compile.
const NOT_COMPILED: &str =
    "the Guide preview: fstp_programme::compile refuses the draft spec under its funder profile";

/// Both Guide checks fail closed without the zone the preview names.
const NO_ZONE: &str = "the Guide preview: the zone name UTC of fstp_domain::time::ZoneName";

/// How a placeholder resolves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Binding {
    /// From a field of the draft.
    Field(FieldId),
    /// When the Guide is generated, from the call record, the platform or
    /// the profile, never from the draft.
    Publication,
    /// From nothing the creator knows, so it never resolves.
    Unknown,
}

/// The placeholders that bind an artefact field of the draft. The field
/// docs of `fstp_programme::FIELDS` name them. Interim, pending Daniel.
const ARTEFACT_BINDINGS: [(&str, FieldId); 10] = [
    ("programme.name", FieldId::ProgrammeName),
    ("programme.narrative", FieldId::ProgrammeNarrative),
    ("programme.scope", FieldId::ProgrammeScope),
    ("programme.faq", FieldId::Faq),
    ("programme.contact", FieldId::ProgrammeContact),
    ("action.number", FieldId::ActionNumber),
    ("action.acronym", FieldId::ActionAcronym),
    ("coordinator.name", FieldId::CoordinatorName),
    ("eligibility.persons", FieldId::PersonsSupported),
    ("annexe.amount_criteria", FieldId::AmountCriteria),
];

/// The placeholders that resolve when the Guide is generated, not from the
/// draft (design 3.10: the call record, the timeline and the platform).
/// Interim, pending Daniel.
const PUBLICATION_BINDINGS: [&str; 5] = [
    "timeline.table",
    "guide.version",
    "platform.url",
    "funder.privacy_statement_url",
    "gdpr.notice_summary",
];

/// How the placeholder `name` resolves.
fn binding(name: &str) -> Binding {
    if name.starts_with("P-") {
        let param = name.split('.').next().unwrap_or(name);
        return CATALOGUE
            .iter()
            .find(|p| p.id.spec_id() == param)
            .and_then(|p| FieldId::for_param(p.id))
            .map_or(Binding::Unknown, Binding::Field);
    }
    if name.starts_with("call.") || PUBLICATION_BINDINGS.contains(&name) {
        return Binding::Publication;
    }
    ARTEFACT_BINDINGS
        .iter()
        .find(|(n, _)| *n == name)
        .map_or(Binding::Unknown, |(_, f)| Binding::Field(*f))
}

/// The headings of a template text: each line that starts with `#`,
/// without trailing white space.
fn headings(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter(|l| l.starts_with('#'))
        .map(|l| l.trim_end().to_owned())
        .collect()
}

/// The placeholders of a template text. An opening `{{` without a closing
/// `}}` on its line gives the rest of the line, opening included.
fn placeholders(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let mut rest = line;
        while let Some(open) = rest.find("{{") {
            let after = rest.get(open.saturating_add(2)..).unwrap_or("");
            match after.find("}}") {
                Some(close) => {
                    out.insert(after.get(..close).unwrap_or("").to_owned());
                    rest = after.get(close.saturating_add(2)..).unwrap_or("");
                }
                None => {
                    out.insert(rest.get(open..).unwrap_or("").to_owned());
                    break;
                }
            }
        }
    }
    out
}

/// What the Guide checks find in a template.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GuideScan {
    /// The required sections the template lacks (I-52). The Guide API
    /// names each by its name in the table of `guide-for-applicants.md`;
    /// [`guide_scan`] names each by its heading line.
    pub sections_missing: BTreeSet<String>,
    /// The placeholders that do not resolve from the draft (I-51): those
    /// that bind a field in `unset`, and those that bind nothing known.
    pub unresolved: BTreeSet<String>,
}

/// Compares `template` with the `required` template and with the draft's
/// gaps, as text. Total: it never panics on any text.
pub fn guide_scan(template: &str, required: &str, unset: &BTreeSet<FieldId>) -> GuideScan {
    let have = headings(template);
    let sections_missing = headings(required)
        .into_iter()
        .filter(|h| !have.contains(h))
        .collect();
    let unresolved = placeholders(template)
        .into_iter()
        .filter(|p| match binding(p) {
            Binding::Field(f) => unset.contains(&f),
            Binding::Publication => false,
            Binding::Unknown => true,
        })
        .collect();
    GuideScan {
        sections_missing,
        unresolved,
    }
}

/// Whether the placeholder `key` is bound to the draft: its resolver
/// reads the policy or the programme artefacts. An unknown key counts as
/// bound, so it fails closed.
fn draft_bound(key: &str) -> bool {
    RESOLVERS
        .iter()
        .find(|r| r.key == key)
        .is_none_or(|r| matches!(r.source, Source::Policy | Source::Artefacts))
}

/// The text [`AnyStoredText`] gives for every stored text.
const STORED_TEXT: &str = "A stored text, read from the text store at publication.";

/// The text store of the draft preview. The creator never reads the
/// shell's text store, so it answers every stored text (ADR-007) with
/// [`STORED_TEXT`] (module documentation). Each stored item then
/// resolves on its own, and the resolver still checks every inline item
/// beside it. The text never leaves the preview.
struct AnyStoredText;

impl StoredTexts for AnyStoredText {
    fn text(&self, _text: TextRef) -> Option<&str> {
        Some(STORED_TEXT)
    }
}

/// Whether the held or template value `value` of a policy field agrees
/// with the head policy: compiled into the head, it reads back as the
/// head's value of its field. Only the free texts the policy does not
/// hold may differ (`fstp_programme::policy_spec`). A value that does not
/// agree was replaced by a later policy version, such as a core
/// `EditPolicy`, and the head stands (module documentation).
fn agrees_with_head(
    head_spec: &ProgrammeSpec,
    profile: &FunderProfile,
    ids: CompileIds,
    value: &FieldValue,
) -> bool {
    let field = value.field();
    let head_value = head_spec.get(field);
    if head_value.as_set() == Some(value) {
        return true;
    }
    let mut spec = head_spec.clone();
    spec.set(value.clone());
    compile(&spec, profile, ids)
        .is_ok_and(|c| fstp_programme::policy_spec(&c.policy).get(field) == head_value)
}

/// The draft spec of `programme` as the Guide reads it, compiled under
/// the draft's funder profile with the head's ids (module documentation).
/// `set` names the fields that hold a value.
pub(crate) fn draft_compiled(
    creator: &CreatorState,
    programme: ProgrammeId,
    draft: &Draft,
    head: &PolicyVersion,
    set: &BTreeSet<FieldId>,
) -> Result<Compiled, &'static str> {
    let profile = crate::draft::profile_of(draft).map_err(|_| NOT_COMPILED)?;
    let ids = CompileIds::new(programme, head.id, head.parent);
    let spec = draft_spec(creator, programme, draft, head, set, Some(&profile));
    compile(&spec, &profile, ids).map_err(|_| NOT_COMPILED)
}

/// The draft spec of `programme` as the Guide and the draft read see it,
/// under `profile` with the head's ids (module documentation): the head
/// policy, with the value of each set artefact field the creator holds,
/// and a gap for each field outside `set`. Without a profile, a policy
/// field reads from the head alone.
pub(crate) fn draft_spec(
    creator: &CreatorState,
    programme: ProgrammeId,
    draft: &Draft,
    head: &PolicyVersion,
    set: &BTreeSet<FieldId>,
    profile: Option<&FunderProfile>,
) -> ProgrammeSpec {
    let ids = CompileIds::new(programme, head.id, head.parent);
    let head_spec = fstp_programme::policy_spec(head);
    let mut spec = head_spec.clone();
    for f in FIELDS {
        if !set.contains(&f.id) {
            spec.unset(f.id);
            continue;
        }
        match (
            f.kind,
            crate::draft::field_value(creator, programme, draft, f.id),
        ) {
            (FieldKind::Artefact, Some(v)) => spec.set(v),
            (FieldKind::Artefact, None) => spec.unset(f.id),
            // A policy field reads from the head. A held or template
            // value adds only the free texts the head does not hold.
            (FieldKind::Policy, Some(v))
                if profile.is_some_and(|p| agrees_with_head(&head_spec, p, ids, &v)) =>
            {
                spec.set(v)
            }
            (FieldKind::Policy, _) => {}
        }
    }
    spec
}

/// The Guide facts of the draft of `programme` (module documentation), or
/// why the Guide checks cannot run. `set` names the fields that hold a
/// value, and `head` is the draft's head policy.
pub(crate) fn guide_facts(
    creator: &CreatorState,
    programme: ProgrammeId,
    draft: &Draft,
    head: &PolicyVersion,
    profile: Option<&GuideProfile>,
    set: &BTreeSet<FieldId>,
) -> Result<GuideScan, &'static str> {
    let profile = profile.ok_or(NO_GUIDE_PROFILE)?;
    let template =
        fstp_guide::parse_template(profile.guide_template().as_bytes()).map_err(|_| GUIDE_SEAM)?;
    let compiled = draft_compiled(creator, programme, draft, head, set)?;
    // No call exists for a draft. The call record's placeholders are left
    // to publication, so this record names no call: an empty identifier
    // and budget, and Guide version 0, which the resolvers refuse.
    let call = GuideCall {
        identifier: String::new(),
        opens: Timestamp::from_micros(0),
        deadline: Timestamp::from_micros(0),
        deadline_zone: ZoneName::new("UTC").ok_or(NO_ZONE)?,
        budget: String::new(),
    };
    let inputs = GuideInputs {
        compiled: &compiled,
        publication: None,
        call: &call,
        guide_version: 0,
        platform_url: "",
        data_protection_summary: None,
        privacy_statement_url: None,
        texts: &AnyStoredText,
        // The scan reads sections and bindings only, never the note.
        precheck_available: false,
    };
    let preview = fstp_guide::preview(&template, &inputs);
    let sections_missing = preview
        .missing_sections
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    let unresolved = preview
        .unresolved
        .iter()
        .filter_map(|e| match e {
            GuideError::Unresolved { key, .. } if draft_bound(key.as_str()) => {
                Some(key.as_str().to_owned())
            }
            _ => None,
        })
        .collect();
    Ok(GuideScan {
        sections_missing,
        unresolved,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fstp_guide::{ProfileSource, ShippedProfiles};

    /// I-51, I-52: the scan names a missing heading, a placeholder of an
    /// unset field and an unknown placeholder. It skips a placeholder that
    /// resolves at publication and one of a set field.
    #[test]
    fn i51_i52_guide_scan_names_missing_sections_and_unresolved_bindings() {
        let required = "# Guide\n## 1. About {{programme.name}}\n## 2. Call\n";
        let template = "# Guide\n## 1. About {{programme.name}}\n{{P-05}} {{call.deadline}} {{nope}} {{P-04.min}}\nend {{open";
        let unset: BTreeSet<FieldId> = [FieldId::P04, FieldId::Faq].into_iter().collect();
        let scan = guide_scan(template, required, &unset);
        assert_eq!(
            scan.sections_missing,
            ["## 2. Call".to_owned()].into_iter().collect()
        );
        let want: BTreeSet<String> = ["P-04.min", "nope", "{{open"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert_eq!(scan.unresolved, want);
    }

    /// I-51: every placeholder of the shipped Horizon Europe Guide binds a
    /// draft field or resolves at publication, so a draft with no gap
    /// leaves none unresolved.
    #[test]
    fn i51_every_shipped_placeholder_has_a_binding() {
        let files = ShippedProfiles
            .files(fstp_guide::HORIZON_EUROPE)
            .unwrap_or_else(|e| panic!("{e:?}"));
        let text = std::str::from_utf8(files.guide).unwrap_or_else(|e| panic!("{e}"));
        let scan = guide_scan(text, text, &BTreeSet::new());
        assert_eq!(scan, GuideScan::default());
    }

    /// I-51: the scan's bindings agree with the Guide's resolvers. Every
    /// resolver of the policy or the artefacts binds a draft field here,
    /// and every other resolver resolves at publication.
    #[test]
    fn i51_scan_bindings_agree_with_the_guide_resolvers() {
        for r in RESOLVERS {
            let b = binding(r.key);
            match r.source {
                Source::Policy | Source::Artefacts => {
                    assert!(matches!(b, Binding::Field(_)), "{}: {b:?}", r.key);
                    assert!(draft_bound(r.key), "{}", r.key);
                }
                Source::CallRecord | Source::Other => {
                    assert_eq!(b, Binding::Publication, "{}", r.key);
                    assert!(!draft_bound(r.key), "{}", r.key);
                }
            }
        }
        assert!(draft_bound("no.such.key"));
    }
}
