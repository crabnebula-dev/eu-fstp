//! Tests of `fstp_release::licence::permits` (I-39, Q18, TH-33, design
//! section 10.2).
//!
//! The `permits` table marks evaluation, payments, notifications and
//! export as protected (I-39). Q18 interim (design section 17.2):
//! licence expiry blocks nothing in M3, so every row is permitted in
//! every state.
//!
//! The tests are red until lane W2j lands `permits` and the protected
//! rows of `GateKind` ([`seams::GATE_ROWS_SEAM`]).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/oracle.rs"]
mod oracle;
#[path = "support/seams.rs"]
mod seams;

use fstp_prop::{Gen, check, prop_assert};
use fstp_release::licence::GateKind;

use oracle::{DAY_S, P43_DAYS, State, T0, grace_len};
use seams::{gate_rows, permits};

fn gen_state(g: &mut Gen) -> State {
    let at = |g: &mut Gen| T0 + g.i64_in(-60 * DAY_S..=60 * DAY_S);
    match g.u8_in(0..=3) {
        0 => State::Valid { until: at(g) },
        1 => {
            let since = at(g);
            State::Grace {
                since,
                ends: since + grace_len(P43_DAYS),
            }
        }
        2 => State::Expired { since: at(g) },
        _ => State::Missing,
    }
}

/// I-39, design section 10.2: the gate has exactly four protected rows,
/// one each for evaluation, payments, notifications and export, and two
/// others (setup and applying an update). Production reports which rows
/// it protects, so a row cannot quietly lose protection.
#[test]
fn i39_gate_has_the_four_protected_rows() {
    let rows = gate_rows().unwrap_or_else(|e| panic!("{e}"));
    let protected = rows.iter().filter(|(_, p)| *p).count();
    assert_eq!(protected, 4, "I-39: protected rows {rows:?}");
    assert_eq!(rows.len(), 6, "I-39: rows {rows:?}");
    assert!(
        rows.iter().any(|(k, p)| *k == GateKind::ApplyUpdate && !*p),
        "applying an update is a row and not protected: {rows:?}"
    );
}

/// I-39, TH-33 (design section 14.4): in every licence state, the gate
/// permits every protected row. A later change to a protected row fails
/// here.
#[test]
fn i39_permits_every_protected_row_in_every_state() {
    check("i39_permits_every_protected_row_in_every_state", |g| {
        let s = gen_state(g);
        for (kind, _) in gate_rows()?.into_iter().filter(|(_, p)| *p) {
            prop_assert!(permits(s, kind)?, "I-39: {kind:?} blocked in {s:?}");
        }
        Ok(())
    });
}

/// Q18 interim (design section 17.2, "Licence expiry: blocks nothing"):
/// in M3 every row, protected or not, is permitted in every state.
#[test]
fn i39_q18_permits_every_row_in_m3() {
    check("i39_q18_permits_every_row_in_m3", |g| {
        let s = gen_state(g);
        for (kind, _) in gate_rows()? {
            prop_assert!(permits(s, kind)?, "Q18: {kind:?} blocked in {s:?}");
        }
        Ok(())
    });
}

/// Q18 interim, design section 10.3: applying an update is permitted in
/// every licence state. The update itself waits for I-91 in M9, not for
/// the licence.
#[test]
fn i39_q18_permits_apply_update_in_every_state() {
    check("i39_q18_permits_apply_update_in_every_state", |g| {
        let s = gen_state(g);
        prop_assert!(permits(s, GateKind::ApplyUpdate)?, "blocked in {s:?}");
        Ok(())
    });
}
