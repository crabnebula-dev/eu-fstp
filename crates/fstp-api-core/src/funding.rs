//! The funding cards of the tenant's active programmes (ADR-034; I-69).
//!
//! A card reads the programme's creator draft: its name, the grant
//! agreement number (`funder.action_number`) and the coordinator's name
//! and contact. A missing coordinator value falls back to the tenant's
//! defaults (`FundingDefaultsSet`). The card ends with the approved
//! funding acknowledgement when every value it names is set (L-08,
//! ADR-036). Pages, PDFs and emails show the card as text only
//! (I-68).

use fstp_brand::funding::{FundingCard, FundingDefaults};
use fstp_domain::id::ProgrammeId;
use fstp_domain::programme::{ProgrammeStatus, programme_status};
use fstp_engine::EngineState;
use fstp_json::{Object, Value};

/// The string at `path` in a draft spec's JSON form, if it is a
/// non-empty string. A gap or a stored text that the shell has not held
/// reads as `None`.
fn member(spec: &Value, path: &[&str]) -> Option<String> {
    let mut v = spec;
    for k in path {
        v = v.get(k)?;
    }
    v.as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// The card of `programme` from its draft spec `spec` (the
/// `fstp.programme/1` JSON form), with no tenant default applied.
pub fn card_of_spec(programme: ProgrammeId, spec: &Value) -> FundingCard {
    let spec = spec.get("spec").unwrap_or(spec);
    let name = member(spec, &["identity", "name"]);
    let grant_number = member(spec, &["funder", "action_number"]);
    let acronym = member(spec, &["funder", "action_acronym"]);
    let (acknowledgement, acknowledgement_missing) = acknowledgement(
        spec,
        name.as_deref(),
        grant_number.as_deref(),
        acronym.as_deref(),
    );
    FundingCard {
        programme: programme.raw(),
        name: name.unwrap_or_else(|| format!("Programme {}", programme.raw())),
        grant_number,
        coordinator_name: member(spec, &["funder", "coordinator_name"]),
        coordinator_contact: member(spec, &["funder", "coordinator_contact"]),
        acknowledgement,
        acknowledgement_missing,
    }
}

/// The funding acknowledgement of a programme (L-08, ADR-036): the
/// approved text of the version its P-53 pins, moved to its current
/// version (ADR-036 section 8), filled with its name, grant
/// agreement number and acronym. `None` with the codes of what is
/// missing: `profile` when that version holds no approved text, else each slot without a value.
fn acknowledgement(
    spec: &Value,
    name: Option<&str>,
    number: Option<&str>,
    acronym: Option<&str>,
) -> (Option<String>, Vec<&'static str>) {
    // ADR-036 sections 4 and 8: the programme's own pin, moved to its
    // current version through the successor table.
    let version = spec
        .get("funder")
        .and_then(|f| f.get("p53_funder_profile"))
        .and_then(|p| p.get("version"))
        .and_then(Value::as_i64)
        .and_then(|v| u16::try_from(v).ok());
    let Some(w) = member(spec, &["funder", "p53_funder_profile", "profile"])
        .zip(version)
        .and_then(|(id, v)| fstp_report::profile::approved_acknowledgement_at(&id, v))
    else {
        return (None, vec!["profile"]);
    };
    let values = fstp_report::wording::SlotValues {
        programme_name: name,
        action_number: number,
        action_acronym: acronym,
    };
    match w.render(&values) {
        Some(s) => (Some(s), Vec::new()),
        None => (
            None,
            w.missing(&values).into_iter().map(|s| s.code()).collect(),
        ),
    }
}

/// The tenant's funding card defaults, if an admin set them.
pub(crate) fn defaults(state: &EngineState) -> Option<&FundingDefaults> {
    state.tenant.state()?.funding_defaults()
}

/// The active programmes of the tenant, in id order.
pub(crate) fn active_programmes(state: &EngineState) -> Vec<ProgrammeId> {
    let mut ids: Vec<ProgrammeId> = state
        .core
        .calls()
        .iter()
        .map(|(_, c)| c.programme())
        .chain(state.creator.drafts().map(|(p, _)| p))
        .filter(|p| programme_status(&state.core, *p) == Some(ProgrammeStatus::Active))
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// The card of `programme` with the tenant's defaults filling its gaps,
/// or `None` when the creator holds no draft of it.
pub(crate) fn card(state: &EngineState, programme: ProgrammeId) -> Option<FundingCard> {
    let view = fstp_creator::draft_view(&state.core, &state.creator, programme)?;
    Some(card_of_spec(programme, &view.spec).with_defaults(defaults(state)))
}

/// The card of each active programme of the tenant, in id order.
pub(crate) fn cards(state: &EngineState) -> Vec<FundingCard> {
    active_programmes(state)
        .into_iter()
        .filter_map(|p| card(state, p))
        .collect()
}

fn opt(v: Option<&str>) -> Value {
    v.map_or(Value::Null, Value::from)
}

/// The JSON answer of `GET /brand/funding` (ADR-034 section 4):
/// `{"cards": [...], "defaults": {...} | null}`. Each card holds
/// `programme` (a decimal string), `name`, `grant_number`,
/// `coordinator_name`, `coordinator_contact` and `acknowledgement`, each
/// a string or `null`, and `acknowledgement_missing`, a list of codes
/// (ADR-036).
pub fn cards_json(cards: &[FundingCard], defaults: Option<&FundingDefaults>) -> Value {
    let rows = cards
        .iter()
        .map(|c| {
            let mut o = Object::new();
            let _ = o.insert("programme", Value::String(c.programme.to_string()));
            let _ = o.insert("name", Value::from(c.name.as_str()));
            let _ = o.insert("grant_number", opt(c.grant_number.as_deref()));
            let _ = o.insert("coordinator_name", opt(c.coordinator_name.as_deref()));
            let _ = o.insert("coordinator_contact", opt(c.coordinator_contact.as_deref()));
            // L-08 (ADR-036): the sentence, and what keeps it from showing.
            let _ = o.insert("acknowledgement", opt(c.acknowledgement.as_deref()));
            let _ = o.insert(
                "acknowledgement_missing",
                Value::Array(
                    c.acknowledgement_missing
                        .iter()
                        .map(|m| Value::from(*m))
                        .collect(),
                ),
            );
            Value::Object(o)
        })
        .collect();
    let defaults = defaults.map_or(Value::Null, |d| {
        let mut o = Object::new();
        let _ = o.insert("name", Value::from(d.name()));
        let _ = o.insert("contact", Value::from(d.contact()));
        Value::Object(o)
    });
    let mut o = Object::new();
    let _ = o.insert("cards", Value::Array(rows));
    let _ = o.insert("defaults", defaults);
    Value::Object(o)
}

/// The funding card a public page of `programme` shows, each missing
/// value as "Not set yet" (ADR-034 section 4).
pub(crate) fn public_card(
    state: &EngineState,
    programme: ProgrammeId,
) -> Option<fstp_public::PublicFunding> {
    let c = card(state, programme)?;
    let [(_, grant), (_, coordinator), (_, contact)] = c.lines();
    Some(fstp_public::PublicFunding {
        grant_number: grant.to_owned(),
        coordinator: coordinator.to_owned(),
        contact: contact.to_owned(),
        acknowledgement: c.acknowledgement.clone(),
    })
}

/// The JSON answer of `GET /brand/funding` for `state`.
pub(crate) fn answer(state: &EngineState) -> Value {
    cards_json(&cards(state), defaults(state))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]
mod tests {
    use super::*;

    fn spec() -> Value {
        fstp_json::parse(
            br#"{"funder":{"action_number":"SYNTHETIC-000000000","coordinator_contact":null,"coordinator_name":"Synthetic coordinator"},"identity":{"name":"Synthetic programme"}}"#,
        )
        .unwrap()
    }

    /// I-69, ADR-034: a card reads the grant agreement number and the
    /// coordinator from the draft spec, and a gap stays a gap.
    #[test]
    fn i69_card_reads_the_draft_spec() {
        let c = card_of_spec(ProgrammeId::from_raw(7), &spec());
        assert_eq!(c.name, "Synthetic programme");
        assert_eq!(c.grant_number.as_deref(), Some("SYNTHETIC-000000000"));
        assert_eq!(c.coordinator_name.as_deref(), Some("Synthetic coordinator"));
        assert_eq!(c.coordinator_contact, None);
        assert!(!c.complete());
    }

    /// A spec with the Horizon Europe P-53 and the given funder values.
    fn he_spec(name: &str, number: &str, acronym: Option<&str>) -> Value {
        he_spec_at(name, number, acronym, 1)
    }

    /// [`he_spec`] with P-53 pinning `version`.
    fn he_spec_at(name: &str, number: &str, acronym: Option<&str>, version: u16) -> Value {
        let acronym = acronym.map_or("null".to_owned(), |a| format!("\"{a}\""));
        fstp_json::parse(
            format!(
                r#"{{"funder":{{"action_acronym":{acronym},"action_number":"{number}","coordinator_contact":null,"coordinator_name":null,"p53_funder_profile":{{"profile":"horizon-europe","version":{version}}}}},"identity":{{"name":"{name}"}}}}"#
            )
            .as_bytes(),
        )
        .unwrap()
    }

    /// L-08, I-69 (ADR-036): a programme with its name, grant agreement
    /// number and acronym shows the approved sentence. Its P-53 pins v1,
    /// which the card reads moved to v2 (ADR-036 section 8).
    #[test]
    fn l08_card_shows_the_approved_acknowledgement() {
        let c = card_of_spec(
            ProgrammeId::from_raw(7),
            &he_spec("Synthetic programme", "SYNTHETIC-000000000", Some("SYN")),
        );
        assert_eq!(
            c.acknowledgement.as_deref(),
            Some(
                "Synthetic programme is funded by the European Union under the Horizon Europe grant agreement SYNTHETIC-000000000, SYN."
            )
        );
        assert!(c.acknowledgement_missing.is_empty());
        let text = fstp_json::to_compact(&cards_json(&[c], None));
        assert!(
            text.contains(r#""acknowledgement":"Synthetic programme is funded"#),
            "{text}"
        );
        assert!(text.contains(r#""acknowledgement_missing":[]"#), "{text}");
    }

    /// ADR-036 sections 4 and 8: a v2 pin shows the same sentence, and a
    /// version no profile ships shows none and names `profile`.
    #[test]
    fn adr036_q1_card_reads_its_own_pin() {
        let v2 = card_of_spec(
            ProgrammeId::from_raw(7),
            &he_spec_at("Synthetic programme", "SYNTHETIC-000000000", Some("SYN"), 2),
        );
        let v1 = card_of_spec(
            ProgrammeId::from_raw(7),
            &he_spec("Synthetic programme", "SYNTHETIC-000000000", Some("SYN")),
        );
        assert!(v2.acknowledgement.is_some());
        assert_eq!(v2.acknowledgement, v1.acknowledgement);
        let v9 = card_of_spec(
            ProgrammeId::from_raw(7),
            &he_spec_at("Synthetic programme", "SYNTHETIC-000000000", Some("SYN"), 9),
        );
        assert_eq!(v9.acknowledgement, None);
        assert_eq!(v9.acknowledgement_missing, vec!["profile"]);
    }

    /// L-08 (Daniel, 2026-11-22): a missing value shows no sentence, and
    /// the card names what is missing so the branding page can say it.
    /// A programme without a shipped profile names `profile`.
    #[test]
    fn l08_missing_value_shows_no_sentence_and_says_why() {
        let c = card_of_spec(
            ProgrammeId::from_raw(7),
            &he_spec("Synthetic programme", "SYNTHETIC-000000000", None),
        );
        assert_eq!(c.acknowledgement, None);
        assert_eq!(c.acknowledgement_missing, vec!["action_acronym"]);
        let text = fstp_json::to_compact(&cards_json(&[c], None));
        assert!(text.contains(r#""acknowledgement":null"#), "{text}");
        assert!(
            text.contains(r#""acknowledgement_missing":["action_acronym"]"#),
            "{text}"
        );
        let c = card_of_spec(ProgrammeId::from_raw(7), &spec());
        assert_eq!(c.acknowledgement, None);
        assert_eq!(c.acknowledgement_missing, vec!["profile"]);
    }

    /// L-08 (ADR-034 section 1 "Usage rules"): in a contract PDF the EU
    /// logo is drawn so high that its flag, 44 of the artwork's 47.519501
    /// units of height, is at least 1 cm (28.35 pt).
    #[test]
    fn l08_pdf_letterhead_keeps_the_flag_one_centimetre() {
        let img = crate::dispatch::brand::pdf_of(fstp_brand::funding::FUNDED_BY_EU_PNG).unwrap();
        let (_, h) = fstp_pdf::letterhead_size(&img);
        let flag_pt = f64::from(i32::try_from(h).unwrap()) * 44.0 / 47.519501;
        assert!(flag_pt >= 72.0 / 2.54, "{flag_pt} pt");
    }

    /// ADR-034 section 3: the tenant default fills the contact gap, and
    /// the JSON answer carries the card and the defaults.
    #[test]
    fn adr034_default_contact_fills_the_gap_in_the_json() {
        let d = FundingDefaults::new("Default org", "role@example.org").unwrap();
        let c = card_of_spec(ProgrammeId::from_raw(7), &spec()).with_defaults(Some(&d));
        assert!(c.complete());
        let v = cards_json(&[c], Some(&d));
        let text = fstp_json::to_compact(&v);
        assert!(
            text.contains(r#""coordinator_contact":"role@example.org""#),
            "{text}"
        );
        assert!(text.contains(r#""programme":"7""#), "{text}");
        assert!(text.contains(r#""defaults":{"#), "{text}");
        let none = fstp_json::to_compact(&cards_json(&[], None));
        assert_eq!(none, r#"{"cards":[],"defaults":null}"#);
    }
}
