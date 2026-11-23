//! L-08, I-69, P-53, R-RP-01 (ADR-036): the approved wording store, the
//! `Approved` wording status, and version 2 of the Horizon Europe profile.
//!
//! Daniel approved the funding acknowledgement on 2026-11-22, with no
//! disclaimer. Version 1 of the profile never changes (P-53), so the
//! approval lives in version 2 and in the store behind its wording ref.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_prop::{check, prop_assert, prop_assert_eq};
use fstp_report::profile::{
    HORIZON_EUROPE_V1, HORIZON_EUROPE_V2, ProfileError, WordingStatus, approved_acknowledgement_at,
    parse_profile, shipped,
};
use fstp_report::wording::{self, Slot, SlotValues, WordingError, parse_text};

/// The sentence Daniel approved on 2026-11-22 (L-08).
const APPROVED: &str = "{{programme.name}} is funded by the European Union under the Horizon Europe grant agreement {{action.number}}, {{action.acronym}}.";

/// The ref of the acknowledgement element.
const ACK_REF: &str = "horizon-europe/visibility/acknowledgement";

/// P-53: the shipped version 1 never changes. Its SHA-256 is pinned.
#[test]
fn p53_horizon_europe_v1_never_changes() {
    let hex: String = fstp_crypto::sha256(HORIZON_EUROPE_V1)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        hex,
        "4b0f1269b3f6329d1601fdfb6da36fa8f3e3908a42966d2770ceae385f015e06"
    );
    let v1 = shipped("horizon-europe", 1).unwrap();
    for e in v1.visibility_elements() {
        assert_eq!(e.status(), WordingStatus::PendingLegal, "{}", e.key());
    }
}

/// L-08, I-69: version 2 marks the acknowledgement `Approved`, and the
/// store holds exactly the sentence Daniel approved. The emblem element
/// stays `TODO(legal)`.
#[test]
fn i69_l08_v2_acknowledgement_is_the_approved_sentence() {
    let v2 = shipped("horizon-europe", 2).unwrap();
    assert_eq!((v2.id(), v2.version()), ("horizon-europe", 2));
    let ack = v2
        .visibility_elements()
        .iter()
        .find(|e| e.key() == "acknowledgement")
        .unwrap();
    assert_eq!(ack.wording(), ACK_REF);
    assert_eq!(ack.status(), WordingStatus::Approved);
    let emblem = v2
        .visibility_elements()
        .iter()
        .find(|e| e.key() == "emblem")
        .unwrap();
    assert_eq!(emblem.status(), WordingStatus::PendingLegal);
    let w = wording::approved(ACK_REF).unwrap();
    assert_eq!(w.text(), APPROVED);
    assert_eq!(w.reference(), ACK_REF);
    assert_eq!(w.approved_by(), "Daniel");
    assert_eq!(w.approved_on(), "2026-11-22");
    assert!(!w.text().contains("TODO(legal)"));
}

/// R-RP-01: version 2 defines the same outputs, fields and periods as
/// version 1, so a report under either reads the same folds.
#[test]
fn r_rp_01_v2_keeps_the_outputs_of_v1() {
    let v1 = shipped("horizon-europe", 1).unwrap();
    let v2 = shipped("horizon-europe", 2).unwrap();
    assert_eq!(v1.outputs(), v2.outputs());
    assert_eq!(v1.reporting_periods(), v2.reporting_periods());
    assert_ne!(v1.digest(), v2.digest());
    assert_eq!(
        fstp_report::profile::for_p53(r#"{"profile":"horizon-europe","version":2}"#).unwrap(),
        v2
    );
    assert_eq!(
        parse_profile(HORIZON_EUROPE_V2).unwrap(),
        v2,
        "the shipped bytes"
    );
}

/// I-69 (ADR-036 section 2): the status `approved` is accepted only for a
/// ref whose text the store holds. A profile cannot claim approval for
/// text that does not exist.
#[test]
fn i69_approved_status_needs_a_stored_text() {
    let v2 = std::str::from_utf8(HORIZON_EUROPE_V2).unwrap();
    let emblem_claimed = v2.replace(
        r#"{"ref": "horizon-europe/visibility/emblem", "status": "TODO(legal)"}"#,
        r#"{"ref": "horizon-europe/visibility/emblem", "status": "approved"}"#,
    );
    assert_ne!(emblem_claimed, v2, "the replacement applies");
    assert!(matches!(
        parse_profile(emblem_claimed.as_bytes()),
        Err(ProfileError::Shape(_))
    ));
    let other_status = v2.replace(r#""status": "approved""#, r#""status": "Approved""#);
    assert_ne!(other_status, v2, "the replacement applies");
    assert!(matches!(
        parse_profile(other_status.as_bytes()),
        Err(ProfileError::Shape(_))
    ));
    // A tenant copy names its own refs, which the store never holds.
    let tenant = v2
        .replacen(r#""id": "horizon-europe""#, r#""id": "tenant-he""#, 1)
        .replace("\"horizon-europe/", "\"tenant-he/");
    assert!(matches!(
        parse_profile(tenant.as_bytes()),
        Err(ProfileError::Shape(_))
    ));
}

/// I-69 (ADR-036 sections 4 and 8): a card reads its pin moved to the
/// current version, whose acknowledgement is approved. Another id reads
/// nothing.
#[test]
fn i69_card_reads_the_approved_acknowledgement_of_its_moved_pin() {
    for v in [1, 2] {
        let w = approved_acknowledgement_at("horizon-europe", v).unwrap();
        assert_eq!(w.reference(), ACK_REF);
    }
    assert!(approved_acknowledgement_at("tenant-he", 1).is_none());
    assert!(approved_acknowledgement_at("", 1).is_none());
}

/// A slot value as a test draws it: absent, blank or text.
fn value(g: &mut fstp_prop::Gen) -> Option<String> {
    match g.u8_in(0..=3) {
        0 => None,
        1 => Some(" \t".to_owned()),
        _ => Some(format!("V{}", g.ascii_string(1..=12).trim())),
    }
}

/// L-08 (Daniel, 2026-11-22): the acknowledgement renders only when every
/// slot holds text. A missing or blank value gives no sentence at all,
/// never a broken one, and `missing` names exactly those slots.
#[test]
fn l08_acknowledgement_renders_only_with_every_slot() {
    let w = wording::approved(ACK_REF).unwrap();
    check("l08_acknowledgement_renders_only_with_every_slot", |g| {
        let name = value(g);
        let number = value(g);
        let acronym = value(g);
        let values = SlotValues {
            programme_name: name.as_deref(),
            action_number: number.as_deref(),
            action_acronym: acronym.as_deref(),
        };
        let blank = |v: &Option<String>| v.as_deref().is_none_or(|s| s.trim().is_empty());
        let mut want_missing = Vec::new();
        if blank(&name) {
            want_missing.push(Slot::ProgrammeName);
        }
        if blank(&number) {
            want_missing.push(Slot::ActionNumber);
        }
        if blank(&acronym) {
            want_missing.push(Slot::ActionAcronym);
        }
        prop_assert_eq!(w.missing(&values), want_missing.clone(), "missing");
        let got = w.render(&values);
        if want_missing.is_empty() {
            let want = format!(
                "{} is funded by the European Union under the Horizon Europe grant agreement {}, {}.",
                name.as_deref().unwrap().trim(),
                number.as_deref().unwrap().trim(),
                acronym.as_deref().unwrap().trim()
            );
            prop_assert_eq!(got, Some(want), "the sentence");
        } else {
            prop_assert!(got.is_none(), "a broken sentence: {got:?}");
        }
        Ok(())
    });
}

/// I-68: a slot value is inserted once, as text. A value that looks like
/// a slot or like markup stays literal.
#[test]
fn i68_slot_values_are_inserted_as_text_once() {
    let w = wording::approved(ACK_REF).unwrap();
    let got = w
        .render(&SlotValues {
            programme_name: Some("<b>{{action.number}}</b>"),
            action_number: Some("101342989"),
            action_acronym: Some("SuperSAFE"),
        })
        .unwrap();
    assert_eq!(
        got,
        "<b>{{action.number}}</b> is funded by the European Union under the Horizon Europe grant agreement 101342989, SuperSAFE."
    );
}

/// ADR-036 section 1: the text parser refuses an unknown slot, an
/// unclosed slot and a stray closing brace pair, and accepts the
/// approved sentence with its three slots.
#[test]
fn l08_wording_text_parser_rules() {
    assert_eq!(
        parse_text("{{programme.title}} x"),
        Err(WordingError::UnknownSlot)
    );
    assert_eq!(parse_text("a {{action.number"), Err(WordingError::Unclosed));
    assert_eq!(parse_text("a }} b"), Err(WordingError::StrayClose));
    assert_eq!(parse_text(""), Err(WordingError::Empty));
    let slots: Vec<Slot> = parse_text(APPROVED)
        .unwrap()
        .into_iter()
        .filter_map(|p| match p {
            wording::Piece::Slot(s) => Some(s),
            wording::Piece::Text(_) => None,
        })
        .collect();
    assert_eq!(
        slots,
        vec![Slot::ProgrammeName, Slot::ActionNumber, Slot::ActionAcronym]
    );
    for s in Slot::ALL {
        assert_eq!(Slot::from_name(s.name()), Some(s));
    }
}

/// ADR-036 section 1 (property): parsing never panics, is deterministic,
/// and an accepted text is its pieces joined again.
#[test]
fn l08_wording_text_parse_round_trips() {
    check("l08_wording_text_parse_round_trips", |g| {
        let mut text = String::new();
        for _ in 0..g.u8_in(0..=6) {
            let piece = match g.u8_in(0..=4) {
                0 => "{{".to_owned(),
                1 => "}}".to_owned(),
                2 => format!("{{{{{}}}}}", g.pick(&Slot::ALL).name()),
                3 => "{".to_owned(),
                _ => g.string(0..=8),
            };
            text.push_str(&piece);
        }
        let first = parse_text(&text);
        prop_assert_eq!(first.clone(), parse_text(&text), "deterministic");
        if let Ok(pieces) = first {
            let joined: String = pieces
                .iter()
                .map(|p| match p {
                    wording::Piece::Text(t) => (*t).to_owned(),
                    wording::Piece::Slot(s) => format!("{{{{{}}}}}", s.name()),
                })
                .collect();
            prop_assert_eq!(joined, text, "round trip");
        }
        Ok(())
    });
}

/// L-08: every stored text parses, names a ref of a shipped profile, and
/// carries who approved it and when.
#[test]
fn l08_every_stored_text_is_well_formed() {
    assert!(!wording::all().is_empty());
    for w in wording::all() {
        assert!(parse_text(w.text()).is_ok(), "{}", w.reference());
        assert!(!w.approved_by().is_empty() && w.approved_on().len() == 10);
        assert!(
            fstp_report::profile::shipped_all()
                .unwrap()
                .iter()
                .any(|p| p
                    .visibility_elements()
                    .iter()
                    .any(|e| e.wording() == w.reference())),
            "{}",
            w.reference()
        );
    }
}
