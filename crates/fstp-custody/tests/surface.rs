//! The type surface of `fstp-custody` (I-80, design section 3.3, ADR-004
//! part 2, ADR-001 A1).
//!
//! ADR-004 part 2: `S(e)` "lives in `Zeroizing` memory, with no `Clone`
//! and no `Debug` output". Design section 3.3 adds "no `ToJson`". The
//! probes run at compile time through `common::impls!`, so a seal key
//! that gains a trait fails a test, not the build.
//!
//! State: the escape-trait test is green on the W0 stub, which derives
//! nothing on `SealKey`. The wipe test is red: the stub holds a plain
//! array (the zeroize seam of `docs/handoff/m3-base.md`, lane W2f).

mod common;

use common::impls;
use fstp_custody::SealKey;

/// I-80, ADR-004 part 2: a seal key has no `Clone`, `Copy`, `Debug`,
/// `Display`, `Default` or `ToJson`, so no log line, panic message or
/// response body can carry it, and no copy is made behind the caller.
#[test]
fn i80_seal_key_has_no_clone_copy_debug_or_json() {
    let mut found = Vec::new();
    if impls!(SealKey: Clone) {
        found.push("Clone");
    }
    if impls!(SealKey: Copy) {
        found.push("Copy");
    }
    if impls!(SealKey: std::fmt::Debug) {
        found.push("Debug");
    }
    if impls!(SealKey: std::fmt::Display) {
        found.push("Display");
    }
    if impls!(SealKey: Default) {
        found.push("Default");
    }
    if impls!(SealKey: fstp_json::ToJson) {
        found.push("ToJson");
    }
    assert!(found.is_empty(), "SealKey implements {found:?}");
}

/// I-80, ADR-004 part 2, ADR-001 A1: a seal key wipes itself on drop. It
/// is marked `ZeroizeOnDrop` and has drop glue, so dropping it runs the
/// wipe. The process memory scan of `fstp-celltest` covers the rest.
#[test]
fn i80_seal_key_zeroizes_on_drop() {
    assert!(
        impls!(SealKey: zeroize::ZeroizeOnDrop),
        "SealKey is not ZeroizeOnDrop"
    );
    assert!(
        std::mem::needs_drop::<SealKey>(),
        "SealKey has no drop glue, so nothing wipes it"
    );
}

/// Design section 3.3: `SealKey::from_bytes` keeps the 32 bytes it is
/// given, and `expose` returns them.
#[test]
fn adr004_seal_key_exposes_the_bytes_it_holds() {
    let key = SealKey::from_bytes([0x5a; 32]);
    assert_eq!(key.expose(), &[0x5a; 32]);
}

/// I-80, ADR-004 part 2 (no copy of a destroyed epoch's `S(e)` stays in
/// process memory): a seal key is one pointer, so a move copies no key
/// byte. Its bytes stay at one address through moves into and out of a
/// collection, a return and a replace, so the wipe on drop reaches the
/// only place they are.
#[test]
fn i80_seal_key_moves_without_copying_its_bytes() {
    assert_eq!(
        std::mem::size_of::<SealKey>(),
        std::mem::size_of::<usize>(),
        "SealKey holds its bytes inline, so every move copies them"
    );
    fn pass(k: SealKey) -> SealKey {
        k
    }
    let key = SealKey::generate().unwrap();
    let at = key.expose().as_ptr();
    let held = vec![Some(key)];
    let key = pass(held.into_iter().next().flatten().unwrap());
    assert_eq!(key.expose().as_ptr(), at);
    let mut slot = key;
    let old = std::mem::replace(&mut slot, SealKey::from_slice(&[1; 32]).unwrap());
    assert_eq!(old.expose().as_ptr(), at);
    assert_ne!(slot.expose().as_ptr(), at);
}

/// I-80: `SealKey::from_slice` copies straight into the key's heap
/// allocation and refuses any length but 32. `SealKey::from_box` takes
/// an allocation over without a copy.
#[test]
fn i80_seal_key_from_slice_and_from_box() {
    let key = SealKey::from_slice(&[0x5b; 32]).unwrap();
    assert_eq!(key.expose(), &[0x5b; 32]);
    assert!(SealKey::from_slice(&[0; 31]).is_err());
    assert!(SealKey::from_slice(&[0; 33]).is_err());
    let boxed = fstp_custody::key_box(&[0x5c; 32]).unwrap();
    let at = boxed.as_ptr();
    let key = SealKey::from_box(boxed);
    assert_eq!(key.expose().as_ptr(), at);
    assert_eq!(key.expose(), &[0x5c; 32]);
}
