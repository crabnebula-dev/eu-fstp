//! I-67 with SoD-09 and `overview.md` NOTE 5: every vault answer of a
//! preview is recorded (M4 design sections 3.4 D3 and 8.4, "Property").
//!
//! The live SoD check of creator step 9 runs `preview_grant` for each
//! invitation with an account. Each vault answer it gets appears in the
//! audit log as a query digest and the answer bit, as a multiset. A
//! preview asks the vault at least once per invitee. Q13 is built
//! strictly as an interim reading, pending Daniel.
//!
//! Red until `preview_grant` (D3, lane W1b), the creator `Invite` path
//! (lane W2a) and the audit sink (lane W3b) exist.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::activate_model::production;
use fstp_api_testkit::reference::creator::{M2, SYBIL, TB, clean_plan};
use fstp_prop::{Gen, check, prop_assert};

/// I-67, SoD-09, NOTE 5: on production.
#[test]
fn i67_preview_vault_answers_are_recorded() {
    check("i67_preview_vault_answers_are_recorded", |g: &mut Gen| {
        let pool = [M2, SYBIL, TB];
        let invitees = g.vec(1..=3, |g| *g.pick(&pool));
        g.note("invitees", &invitees);
        let (asked, audited) = production::preview_vault_trace(&clean_plan(), &invitees)
            .map_err(|e| format!("production: {e}"))?;
        prop_assert!(!asked.is_empty(), "the previews asked the vault nothing");
        let mut left = audited.clone();
        for a in &asked {
            let Some(i) = left.iter().position(|b| b == a) else {
                return Err(format!(
                    "NOTE 5: the vault answer {a:?} is missing from the audit log {audited:?}"
                ));
            };
            left.swap_remove(i);
        }
        Ok(())
    });
}
