//! P-41 (lane m5/retention): the domain reads the funder retention years
//! from the canonical opaque text this crate gives the policy, so the
//! timeline and the mailbox read the value the creator saved.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::num::NonZeroU8;

use fstp_programme::kinds::FunderRetention;
use fstp_programme::{FieldValue, opaque_text};

/// P-41: every value from 1 to 255 years reads back through
/// `fstp_domain::retention::years_of`.
#[test]
fn p41_opaque_text_reads_back_as_the_domain_years() {
    for n in [1u8, 7, 10, 255] {
        let years = NonZeroU8::new(n).unwrap();
        let text = opaque_text(&FieldValue::P41(FunderRetention { years }));
        assert_eq!(
            fstp_domain::retention::years_of(&text),
            Some(years),
            "{text}"
        );
    }
}
