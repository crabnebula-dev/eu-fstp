//! I-11 on M-FIND (design 6.2 and 6.3).
//!
//! The start state comes from genesis through production commands: PR1
//! in STAGE2 of call 1, which pinned configuration 1. Actions: the
//! reduced clock, expiry to DEFERRED, publication of call 2 with
//! configuration 2, re-entry into call 2 and fresh assignments there.
//! Three findings are offered, each while its call is PR1's current call:
//! one of call 1 under its pin, one of call 2 under its pin, and one of
//! call 2 under call 1's configuration, which I-11 refuses. Each goes
//! through the engine's finding decider and is compared with the
//! reference in both directions.
//!
//! Properties: `always("two-way")`, `always("I-11")` over the production
//! store and the reference, and `transition("I-10")`. Witnesses: a stored
//! finding in each call, and call 1 keeping its finding after PR1
//! re-entered call 2 (`SPEC/02-domain/state-machine.md` NOTE 8).
//!
//! The production run is exhaustive under a tripwire at twice the count
//! measured on the references. The `_reference` twin runs the same model
//! on the references alone and must pass now.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::findings_model::{M_FIND_STATES, m_find_model, m_find_properties};

fn run(backend: Backend) {
    let model = m_find_model(backend).unwrap_or_else(|e| panic!("M-FIND start from genesis: {e}"));
    if let Err(e) = check_exhaustive(&model, &m_find_properties(&model), M_FIND_STATES) {
        panic!("{e}");
    }
}

/// I-11, NOTE 8, I-10: M-FIND through the engine's finding decider.
#[test]
fn i11_m_find() {
    run(Backend::Production);
}

/// I-11, NOTE 8: M-FIND passes on the references alone.
#[test]
fn i11_m_find_reference() {
    run(Backend::Reference);
}
