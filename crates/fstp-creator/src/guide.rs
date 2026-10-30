//! The Guide checks of the report: `GuideSectionMissing` (I-52) and
//! `GuideBindingUnresolved` (I-51) (M4 design sections 3.2 and 3.10).
//!
//! The creator reaches the Guide only through `fstp_guide::parse_template`
//! and `fstp_guide::render`. While either refuses, as both do until lane
//! m4guide lands, both checks fail closed with a reason that names
//! `fstp_guide`. Once the template parses and renders, [`guide_scan`]
//! compares the draft profile's template with the shipped one and with the
//! draft's gaps.
//!
//! [`guide_scan`] reads two things of a template text. A heading is a
//! line that starts with `#`. A placeholder is the text between `{{` and
//! the next `}}`; an opening without a closing on its line is a
//! placeholder that never resolves. It is fuzzed (`guide_scan`).

use std::collections::BTreeSet;

use fstp_domain::rules::CATALOGUE;
use fstp_guide::{FunderProfile as GuideProfile, ProfileSource, ShippedProfiles};
use fstp_programme::FieldId;

/// Both Guide checks fail closed while the Guide API refuses.
pub(crate) const GUIDE_SEAM: &str = "the Guide preview: fstp_guide::parse_template and fstp_guide::render refuse until lane m4guide lands (design 3.10)";

/// Both Guide checks fail closed without a profile.
pub(crate) const NO_GUIDE_PROFILE: &str =
    "no funder profile was passed, so fstp_guide has no Guide template to preview";

/// The required sections come from the shipped profile of the same name.
const NO_SHIPPED: &str =
    "fstp_guide::ShippedProfiles holds no Guide of the profile to take the required sections from";

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

/// What [`guide_scan`] finds in a template.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GuideScan {
    /// The required headings the template lacks (I-52).
    pub sections_missing: BTreeSet<String>,
    /// The placeholders that do not resolve from the draft (I-51): those
    /// that bind a field in `unset`, and those that bind nothing known.
    pub unresolved: BTreeSet<String>,
}

/// Compares `template` with the `required` template and with the draft's
/// gaps. Total: it never panics on any text.
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

/// The Guide facts of a draft with the gaps `unset` under `profile`, or why
/// the Guide checks cannot run.
pub(crate) fn guide_facts(
    profile: Option<&GuideProfile>,
    unset: &BTreeSet<FieldId>,
) -> Result<GuideScan, &'static str> {
    let profile = profile.ok_or(NO_GUIDE_PROFILE)?;
    let text = profile.guide_template();
    let template = fstp_guide::parse_template(text.as_bytes()).map_err(|_| GUIDE_SEAM)?;
    fstp_guide::render(&template).map_err(|_| GUIDE_SEAM)?;
    let shipped = ShippedProfiles
        .files(profile.name())
        .map_err(|_| NO_SHIPPED)?;
    let required = std::str::from_utf8(shipped.guide).map_err(|_| NO_SHIPPED)?;
    Ok(guide_scan(text, required, unset))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
