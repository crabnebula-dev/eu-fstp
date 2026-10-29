//! Review reproducer for the key table surface of `fstp-keyd`
//! (independent review of lane W2f). It fails on the current code and
//! passes once the defect is fixed.

#![allow(clippy::unwrap_used, reason = "test code")]

/// I-80, design section 2.4 rule 7, ADR-004 part 2: the custody boundary
/// is the `fstp-keyd` process. `K(e)` opens the epoch file, so `K(e)`
/// and the epoch file together are the root. `open_key_table` and
/// `decode_key_table_body` are public and return `KeyTableEntry` with a
/// public `key: Option<EpochKey>`, and `EpochKey::expose` is public. So
/// any crate that links `fstp-keyd` can compute root bytes in its own
/// process without naming `RootMaterial`.
#[test]
fn review_keyd_epoch_key_bytes_never_leave_the_crate() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/table.rs");
    let src = std::fs::read_to_string(path).unwrap();
    let mut found = Vec::new();
    if src.contains("    pub fn expose(&self) -> &[u8; 32]") {
        found.push("EpochKey::expose is public");
    }
    if src.contains("    pub key: Option<EpochKey>") {
        found.push("KeyTableEntry::key is a public field");
    }
    assert!(
        found.is_empty(),
        "epoch keys K(e) leave fstp-keyd: {found:?}"
    );
}
