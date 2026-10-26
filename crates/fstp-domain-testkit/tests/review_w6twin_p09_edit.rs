//! Review reproducer for lane w6-twin: twin B's P-09 edits are invisible to the knock-out guard (I-12).
//!
//! The knock-out guard compares the recorded outcomes with the criterion
//! ids of the governing P-09. Every P-09 candidate of the twin keeps ids
//! 1, 2 and 3 and changes only the text. A guard that read the head P-09
//! instead of the call snapshot would therefore give the same outcome on
//! both twins, and the twin comparison could not catch it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::id::PolicyVersionId;
use fstp_domain::rules::ParamId;
use fstp_domain_testkit::r#gen::policy::base_version;
use fstp_domain_testkit::r#gen::roster::P1;
use fstp_domain_testkit::r#gen::twin::apply_frozen;

/// I-12, design 6.2 row I-12: some P-09 edit of twin B changes the set of
/// knock-out criterion ids, so a head read of P-09 changes an outcome.
#[test]
fn review_w6twin_i12_p09_edit_changes_the_knock_out_criterion_ids() {
    let base = base_version(PolicyVersionId::from_raw(1), P1, None).unwrap();
    let ids = |v: &fstp_domain::policy::PolicyVersion| -> BTreeSet<u128> {
        v.frozen.p09.0.iter().map(|k| k.id.raw()).collect()
    };
    let before = ids(&base);
    let changed = (0u8..=4).any(|pick| {
        let mut v = base.clone();
        apply_frozen(&mut v, ParamId::P09, pick).unwrap_or_else(|e| panic!("{e}"));
        ids(&v) != before
    });
    assert!(
        changed,
        "every P-09 edit of the twin keeps the criterion ids {before:?}, so a head read of P-09 \
         in the knock-out guard cannot change any twin outcome"
    );
}
