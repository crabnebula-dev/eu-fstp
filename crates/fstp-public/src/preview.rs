//! The creator's previews of a draft (R-PG-01, I-51; M4 design sections
//! 2.2 J1 and 3.2): the Guide and the public programme page, as text
//! blocks the review page shows, never as markup.
//!
//! - [`draft_guide_preview`] compiles the draft spec as the creator holds
//!   it, under its funder profile with the head policy's ids, and walks
//!   the Guide template with `fstp_guide::preview_text`. A draft has no
//!   call, so the call record's placeholders show as markers that say
//!   they are set at publication. No value is made up.
//! - [`draft_public_preview`] shows the programme page a draft would get:
//!   its name, narrative and public address. A draft publishes no call
//!   and holds no grant, so the page lists none.
//!
//! The draft spec is its `fstp.programme/1` JSON form, with `null` for a
//! gap, as `fstp_creator::draft_view` gives it.

use fstp_domain::State;
use fstp_domain::id::ProgrammeId;
use fstp_domain::policy::FunderProfileRef;
use fstp_guide::{GuideCall, GuideInputs, PreviewBlock, PreviewKind, StoredTexts, Template};
use fstp_json::Value;
use fstp_programme::{CompileIds, FunderProfile, compile, decode_spec};

use crate::PublicError;
use crate::view::ProgrammeIdentity;

/// The string at `path` of `spec`, if it is a non-empty string.
fn member<'a>(spec: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut v = spec;
    for k in path {
        v = v.get(k)?;
    }
    v.as_str().filter(|s| !s.is_empty())
}

impl ProgrammeIdentity {
    /// The public identity of a draft spec in its `fstp.programme/1` JSON
    /// form: `identity.public_slug`, `identity.name` and
    /// `identity.narrative`. `None` without a slug or a name. A narrative
    /// that is a gap, or a stored text, reads as empty.
    pub fn from_spec_json(spec: &Value) -> Option<ProgrammeIdentity> {
        let spec = spec.get("spec").unwrap_or(spec);
        Some(ProgrammeIdentity {
            slug: member(spec, &["identity", "public_slug"])?.to_owned(),
            name: member(spec, &["identity", "name"])?.to_owned(),
            narrative: member(spec, &["identity", "narrative"])
                .unwrap_or_default()
                .to_owned(),
        })
    }
}

fn block(kind: PreviewKind, text: impl Into<String>) -> PreviewBlock {
    PreviewBlock {
        kind,
        text: text.into(),
    }
}

/// The Guide preview of the draft of `programme` (module documentation).
/// `spec` is the draft spec, `profile` the draft's funder profile and
/// `template` the parsed Guide template of that profile. `texts` gives
/// the stored texts the caller could read, such as the P-09 wording.
///
/// It refuses [`PublicError::NotFound`] for a programme with no head
/// policy, and [`PublicError::Html`] for a spec that does not compile.
pub fn draft_guide_preview(
    core: &State,
    programme: ProgrammeId,
    spec: &Value,
    profile: &FunderProfileRef,
    template: &Template,
    texts: &dyn StoredTexts,
) -> Result<Vec<PreviewBlock>, PublicError> {
    const NOT_COMPILED: PublicError =
        PublicError::Html("the draft spec does not compile under its funder profile");
    let head = fstp_domain::policy::head(core, programme).ok_or(PublicError::NotFound)?;
    let profile = FunderProfile::for_policy_ref(profile).ok_or(NOT_COMPILED)?;
    let spec = decode_spec(spec.to_compact().as_bytes()).map_err(|_| NOT_COMPILED)?;
    let compiled = compile(
        &spec,
        &profile,
        CompileIds::new(programme, head.id, head.parent),
    )
    .map_err(|_| NOT_COMPILED)?;
    // A draft has no call. This record names none: an empty identifier
    // and budget, which the resolvers refuse, so they show as markers.
    let zone = fstp_domain::time::ZoneName::new("UTC").ok_or(NOT_COMPILED)?;
    let call = GuideCall {
        identifier: String::new(),
        opens: fstp_domain::time::Timestamp::from_micros(0),
        deadline: fstp_domain::time::Timestamp::from_micros(0),
        deadline_zone: zone,
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
        texts,
    };
    let mut out = vec![block(PreviewKind::Heading, fstp_guide::GUIDE_TITLE)];
    out.extend(fstp_guide::preview_text(template, &inputs));
    Ok(out)
}

/// The public programme page preview of a draft spec (module
/// documentation). A spec with no name or no slug yet shows markers in
/// their place.
pub fn draft_public_preview(spec: &Value) -> Vec<PreviewBlock> {
    let inner = spec.get("spec").unwrap_or(spec);
    let name =
        member(inner, &["identity", "name"]).unwrap_or("[identity.name: not set in the draft]");
    let slug = member(inner, &["identity", "public_slug"]);
    let mut out = vec![block(PreviewKind::Heading, name)];
    if let Some(n) = member(inner, &["identity", "narrative"]) {
        out.push(block(PreviewKind::Paragraph, n));
    }
    out.push(block(
        PreviewKind::Paragraph,
        match slug {
            Some(s) => format!("Public address: /p/{s}/"),
            None => "Public address: [identity.public_slug: not set in the draft]".to_owned(),
        },
    ));
    out.push(block(PreviewKind::Heading, "Open calls"));
    out.push(block(
        PreviewKind::Paragraph,
        "There are no open calls right now. A draft programme publishes no call.",
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(identity: &str) -> Value {
        fstp_json::parse(format!("{{\"identity\":{identity}}}").as_bytes()).unwrap_or(Value::Null)
    }

    /// R-PB-01, R-PG-01: the identity of a spec needs a slug and a name.
    #[test]
    fn r_pb_01_identity_reads_slug_name_and_narrative() {
        let s = spec(r#"{"name":"Synthetic","narrative":"N","public_slug":"syn"}"#);
        let id = ProgrammeIdentity::from_spec_json(&s);
        assert_eq!(
            id,
            Some(ProgrammeIdentity {
                slug: "syn".to_owned(),
                name: "Synthetic".to_owned(),
                narrative: "N".to_owned(),
            })
        );
        let gap = spec(r#"{"name":"Synthetic","narrative":null,"public_slug":null}"#);
        assert_eq!(ProgrammeIdentity::from_spec_json(&gap), None);
    }

    /// R-PG-01: the public preview of a draft names it and lists no call.
    #[test]
    fn r_pg_01_public_preview_names_the_draft() {
        let s = spec(r#"{"name":"Synthetic","narrative":null,"public_slug":"syn"}"#);
        let blocks = draft_public_preview(&s);
        assert_eq!(blocks.first().map(|b| b.text.as_str()), Some("Synthetic"));
        assert!(blocks.iter().any(|b| b.text.contains("/p/syn/")));
    }
}
