//! Review reproducer (lane W1g, reference fidelity). TH-32 and design
//! section 15: `release_metadata_decode` must check the signature before
//! any field is used. In M3 no metadata can be verified (I-91 lands in
//! M9). The reference store still takes `seq` from unverified metadata as
//! its rollback floor. One forged response with a huge `seq` then makes
//! every later genuine metadata a "rollback", which freezes updates.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_celltest::reference::licence::{
    self as r, DAY_S, MetadataRefusal, MetadataStore, RefChannel, RefMetadata, RefVersion,
};

const NOW: i64 = 1_800_000_000;

fn metadata(seq: u64) -> RefMetadata {
    RefMetadata {
        channel: RefChannel::Stable,
        seq,
        version: RefVersion {
            major: 1,
            minor: 5,
            patch: 0,
        },
        expires_at: NOW + 30 * DAY_S,
        artifact_sha256: [0x5a; 32],
    }
}

/// TH-32, design section 15 ("signature checked before use"): metadata that
/// cannot be verified never moves the rollback floor, so a forged
/// `seq = u64::MAX` cannot make genuine metadata look like a rollback.
#[test]
fn review_th_32_unverified_metadata_never_moves_the_rollback_floor() {
    const {
        assert!(
            !r::M3_METADATA_VERIFIABLE,
            "precondition: no metadata is verifiable in M3"
        );
    }
    let store = MetadataStore::default();
    let store = store.accept(&metadata(u64::MAX), NOW).unwrap_or(store);
    let genuine = store.accept(&metadata(7), NOW + 1);
    assert_ne!(
        genuine,
        Err(MetadataRefusal::Rollback),
        "TH-32: unverified metadata set the rollback floor to {:?}, so genuine metadata is refused",
        store.highest
    );
}
