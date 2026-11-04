//! I-95, ADR-015: a journey definition is checksummed like a migration.
//!
//! The checksum is the SHA-256 of the definition file's bytes, computed
//! with `fstp-crypto`, as `fstp-migrate` does for each migration. The bytes
//! include whitespace and line endings, so any change to the file changes
//! the checksum even when the graph stays the same.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use fstp_journey::definition::parse;

/// I-95: the parsed definition carries the SHA-256 of the shipped bytes.
#[test]
fn i95_definition_checksum_is_the_sha256_of_its_bytes() {
    let def = support::shipped();
    assert_eq!(
        def.checksum(),
        &fstp_crypto::sha256(fstp_journey::PROPOSAL_V1),
        "I-95: checksum of PROPOSAL_V1"
    );
}

/// I-95: a whitespace change keeps the graph and changes the checksum, so
/// a recorded checksum detects an edited file.
#[test]
fn i95_a_changed_byte_changes_the_checksum() {
    let mut bytes = fstp_journey::PROPOSAL_V1.to_vec();
    bytes.push(b'\n');
    let original = support::shipped();
    let changed = parse(&bytes).expect("trailing whitespace is valid JSON");
    assert_eq!(
        support::production_graph(&original),
        support::production_graph(&changed),
        "I-95: the graph is unchanged"
    );
    assert_ne!(original.checksum(), changed.checksum(), "I-95: checksum");
}
