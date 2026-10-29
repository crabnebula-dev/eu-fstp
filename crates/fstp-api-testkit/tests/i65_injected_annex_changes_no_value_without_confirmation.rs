//! I-65, T-PG-IMPORT, TH-47 (M4 design section 8.4): corpus-style direct
//! and hidden injection documents change no value without confirmation.
//!
//! Each synthetic annex of `ANNEXES` holds instructions aimed at the
//! platform or at a proposer: direct sentences, a JSON command block, an
//! HTML comment, a link title, white text, Unicode format controls and a
//! value that tries to break out of its JSON string. On production the
//! annex is normalised and the fixture-driven fake proposer runs over it.
//! Its output must equal the fixture byte for byte, with every evidence
//! span inside the normalised text. Recording the proposals changes no
//! draft value and appends only import records. Activation stays refused
//! while any proposal is unresolved. One confirmation by M1 changes only
//! its own field, to the proposed value byte for byte.
//!
//! The production test is red until lanes W2a, W2b and W2e land.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::import_model::{ANNEXES, Backend, injected_annex_case};

fn run(backend: Backend) {
    assert!(
        ANNEXES.iter().any(|a| a.hidden) && ANNEXES.iter().any(|a| !a.hidden),
        "T-PG-IMPORT: the corpus needs direct and hidden injections"
    );
    let failures: Vec<String> = ANNEXES
        .iter()
        .filter_map(|a| {
            injected_annex_case(backend, a)
                .err()
                .map(|e| format!("{}: {e}", a.name))
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// I-65, T-PG-IMPORT: an injected annex changes no value without
/// confirmation, on production.
#[test]
fn i65_injected_annex_changes_no_value_without_confirmation() {
    run(Backend::Production);
}

/// I-65, T-PG-IMPORT: the corpus passes on the reference alone.
#[test]
fn i65_injected_annex_changes_no_value_without_confirmation_on_the_reference() {
    run(Backend::Reference);
}
