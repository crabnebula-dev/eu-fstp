//! O-55, I-96, R-JV-01: plain labels lead by default, the Voyage label shows as a secondary line only when the tenant switches it on, and formal state names stay visible.
//!
//! `Vocabulary::platform(voyage_on)` is the lookup a page uses. The plain
//! label is always the primary text. With the switch off no secondary
//! line exists. With it on, a Voyage label that differs from the plain
//! label is the secondary line. Every proposal state names its formal
//! state in both cases (I-96).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::rules::StateTag;
use fstp_journey::vocab::{LABEL_KEYS, Vocabulary, plain_v1, voyage_v1};

/// O-55: with the switch off, every label is the plain label and no
/// secondary line shows.
#[test]
fn o55_plain_is_the_default_and_shows_no_voyage_line() {
    let plain = plain_v1().unwrap();
    let v = Vocabulary::platform(false).unwrap();
    for key in LABEL_KEYS {
        let shown = v.label(key).unwrap();
        assert_eq!(Some(shown.plain), plain.get(key), "O-55: {key}");
        assert_eq!(shown.secondary, None, "O-55: {key} shows a Voyage line");
    }
}

/// O-55: with the switch on, the plain label still leads and the Voyage
/// label is the secondary line where it differs from the plain one.
#[test]
fn o55_voyage_shows_beside_the_plain_label_only_when_switched_on() {
    let plain = plain_v1().unwrap();
    let voyage = voyage_v1().unwrap();
    let v = Vocabulary::platform(true).unwrap();
    let mut lines = 0usize;
    for key in LABEL_KEYS {
        let shown = v.label(key).unwrap();
        assert_eq!(Some(shown.plain), plain.get(key), "O-55: {key} leads");
        let want = voyage.get(key).filter(|t| Some(*t) != plain.get(key));
        assert_eq!(shown.secondary, want, "O-55: {key}");
        lines += usize::from(shown.secondary.is_some());
    }
    assert!(lines > 0, "O-55: the check has teeth");
    let stage1 = v.label("journey.node.stage1").unwrap();
    assert_eq!(
        (stage1.plain, stage1.secondary),
        ("Stage 1 evaluation", Some("Crossing"))
    );
    assert!(v.label("journey.diary.erased").is_none(), "I-72");
}

/// I-96, R-JV-01: each of the 16 states shows its formal name and its
/// plain label in both packs, and the Voyage label only with the switch.
#[test]
fn i96_formal_state_names_stay_visible_in_both_packs() {
    for on in [false, true] {
        let v = Vocabulary::platform(on).unwrap();
        for state in StateTag::ALL {
            let shown = v
                .state(state)
                .unwrap_or_else(|| panic!("R-JV-01: {state:?}"));
            assert_eq!(shown.formal, state.spec_name(), "I-96");
            assert!(!shown.plain.is_empty(), "R-JV-01: {state:?}");
            if !on {
                assert_eq!(shown.secondary, None, "O-55: {state:?}");
            }
        }
    }
    let v = Vocabulary::platform(true).unwrap();
    let s = v.state(StateTag::Stage2).unwrap();
    assert_eq!(
        (s.formal, s.plain, s.secondary),
        (
            "STAGE2",
            "Stage 2 questions",
            Some("Ascent: questions from the scouts")
        )
    );
}

/// O-55: a lookup is built from a plain pack and an optional Voyage pack,
/// never the reverse.
#[test]
fn o55_lookup_refuses_swapped_packs() {
    assert!(Vocabulary::new(voyage_v1().unwrap(), None).is_err());
    assert!(Vocabulary::new(plain_v1().unwrap(), Some(plain_v1().unwrap())).is_err());
    assert!(Vocabulary::new(plain_v1().unwrap(), Some(voyage_v1().unwrap())).is_ok());
}
