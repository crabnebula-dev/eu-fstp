//! Review finding (lane m4glue, lens INVARIANTS): I-50 at save, as M4
//! design section 15.0 records Daniel's answer of 2026-10-31: "A creator
//! save or import resolution that would put P-05 above P-58 is refused
//! with I-50, naming both values".
//!
//! The creator's `CapAboveCeiling { p05, p58 }` names both values, and
//! `compose::creator_refusal` is the one mapping from it to the engine's
//! `Refusal`. When the review found this, that mapping kept the rule and
//! reason only, so no caller of the engine, the API included, saw either
//! value. The refusal now carries them as its `RefusalDetail`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_creator::CreatorRefusal;
use fstp_money::{Amount, Currency, NonNegAmount};

fn eur(minor: i64) -> NonNegAmount {
    NonNegAmount::new(Amount::from_minor(minor, Currency::Eur).unwrap()).unwrap()
}

/// I-50, R-PG-01 AC, M4 design section 15.0 (I-50 timing, 2026-10-31):
/// the engine's refusal of a save with P-05 above P-58 names both values.
#[test]
fn review_invariants_i50_engine_refusal_names_both_values() {
    let p05 = eur(6_000_001);
    let p58 = eur(6_000_000);
    let creator = CreatorRefusal::CapAboveCeiling { p05, p58 };
    let creator_text = creator.to_string();
    assert!(
        creator_text.contains(&p05.amount().to_string())
            && creator_text.contains(&p58.amount().to_string()),
        "story: the creator's refusal names both values: {creator_text}"
    );
    let engine = fstp_engine::compose::creator_refusal(creator);
    let text = format!("{engine} {engine:?}");
    assert!(
        text.contains(&p05.amount().to_string()) && text.contains(&p58.amount().to_string()),
        "M4 design 15.0: the I-50 refusal at save must name P-05 {} and P-58 {}, \
         but the engine's refusal is only {text}",
        p05.amount(),
        p58.amount()
    );
}
