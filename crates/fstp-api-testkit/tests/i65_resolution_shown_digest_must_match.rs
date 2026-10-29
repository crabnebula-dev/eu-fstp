//! I-65, property (M4 design sections 3.3 and 8.4): a resolution names
//! the value the programme manager saw through its `shown` digest.
//!
//! On the standard draft, M1 uploads a document and records two or three
//! proposals with havoc values. A confirmation, edit or dismissal of one
//! of them by M1, with every other guard satisfied, carries a stale digest
//! (the value of another proposal or any other value) or forged digest
//! bytes. It is refused and appends nothing. The same resolution with the
//! digest of the stored value is then accepted.
//!
//! The production test is red until lanes W2a, W2b and W2e land.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::import_model::{Backend, shown_case};
use fstp_prop::check;

/// I-65: a stale or forged `shown` digest is refused, on production.
#[test]
fn i65_resolution_shown_digest_must_match() {
    check("i65_resolution_shown_digest_must_match", |g| {
        shown_case(Backend::Production, g)
    });
}

/// I-65: the property passes on the reference alone.
#[test]
fn i65_resolution_shown_digest_must_match_on_the_reference() {
    check(
        "i65_resolution_shown_digest_must_match_on_the_reference",
        |g| shown_case(Backend::Reference, g),
    );
}
