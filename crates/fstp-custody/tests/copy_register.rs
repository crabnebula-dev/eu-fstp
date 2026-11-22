//! The copy register of a sealed key file (ADR-004 record of lane L16,
//! Q-L16-3, decided by Daniel on 2026-11-21, I-81).
//!
//! An operator copy of `cell-keys.sealed` or of the witness receipt key
//! file is recorded with a digest of each key it holds. While a copy that
//! is not retired holds a key the owning process no longer holds, the
//! process reports reduced I-81 assurance.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

use fstp_custody::copies::{
    CopyId, CopyRecord, decode_register, encode_record, holds_replaced, key_digest, record_copy,
    retire_copy,
};

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("fstp-custody-l16-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.join("keys.copies")
}

/// I-81, ADR-004 record of lane L16 (Q-L16-3): a copy that holds a key
/// the owner has replaced is flagged until it is retired. A copy whose
/// keys the owner still holds, or a key it only added since, is not.
#[test]
fn i81_copy_register_flags_a_copy_holding_a_replaced_key() {
    let path = scratch("flag");
    let old = key_digest("cred_lookup", &[1; 32]);
    let kept = key_digest("anchor", &[2; 32]);
    let new = key_digest("cred_lookup", &[3; 32]);
    assert!(!holds_replaced(&path, &[old, kept]), "no copy yet");
    let id = record_copy(&path, vec![old, kept]).unwrap();
    assert!(!holds_replaced(&path, &[old, kept]));
    assert!(!holds_replaced(&path, &[old, kept, new]), "an added key");
    assert!(holds_replaced(&path, &[kept, new]), "the replaced key");
    retire_copy(&path, id).unwrap();
    assert!(!holds_replaced(&path, &[kept, new]));
    assert!(retire_copy(&path, id).is_err(), "retired twice");
    assert!(retire_copy(&path, CopyId([9; 16])).is_err(), "unknown id");
}

/// I-81, ADR-004 record of lane L16: a register that does not decode
/// counts as holding a replaced key, since nothing then shows the
/// contrary.
#[test]
fn i81_unreadable_copy_register_counts_as_reduced() {
    let path = scratch("broken");
    std::fs::write(&path, [7u8; 5]).unwrap();
    assert!(holds_replaced(&path, &[]));
}

/// I-80, ADR-004 record of lane L16: a digest names a key without
/// revealing it, and the label keeps two kinds of key apart.
#[test]
fn i80_copy_register_holds_no_key_bytes() {
    let path = scratch("bytes");
    let key = [0x5c; 32];
    record_copy(&path, vec![key_digest("ticket", &key)]).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.windows(32).any(|w| w == key));
    assert_ne!(key_digest("ticket", &key), key_digest("anchor", &key));
}

/// ADR-004 record of lane L16: the register decodes in one spelling and
/// refuses a cut record and an unknown tag.
#[test]
fn adr004_copy_register_round_trips_in_one_spelling() {
    let recs = vec![
        CopyRecord::Taken {
            id: CopyId([1; 16]),
            created: 5,
            keys: vec![[2; 32], [3; 32]],
        },
        CopyRecord::Retired {
            id: CopyId([1; 16]),
        },
    ];
    let mut bytes = Vec::new();
    for r in &recs {
        bytes.extend(encode_record(r).unwrap());
    }
    assert_eq!(decode_register(&bytes).unwrap(), recs);
    assert!(decode_register(&bytes[..bytes.len() - 1]).is_err());
    let mut bad = bytes.clone();
    bad[0] = 9;
    assert!(decode_register(&bad).is_err());
    assert_eq!(
        CopyId::parse(&CopyId([0xab; 16]).hex()),
        Some(CopyId([0xab; 16]))
    );
}
