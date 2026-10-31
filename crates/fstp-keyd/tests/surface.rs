//! The type surface of `fstp-keyd` (I-80, design sections 2.4 and 3.3,
//! ADR-004 part 2, ADR-001 A1).
//!
//! `RootMaterial` is "not `Clone`, not `Debug` and not serialisable"
//! (design section 0.4), and it wipes itself on drop (ADR-001 A1). The
//! probes run at compile time through `common::impls!`.
//!
//! State: the escape-trait tests are green on the W0 stub. The wipe test
//! is red: the stub holds a plain array (the zeroize seam of
//! `docs/handoff/m3-base.md`, lane W2f).

mod common;

use common::impls;
use fstp_keyd::{CustodyFile, RootMaterial};

/// The escape traits `$t` implements, by name.
macro_rules! escapes {
    ($t:ty) => {{
        let mut found: Vec<&str> = Vec::new();
        if impls!($t: Clone) {
            found.push("Clone");
        }
        if impls!($t: Copy) {
            found.push("Copy");
        }
        if impls!($t: std::fmt::Debug) {
            found.push("Debug");
        }
        if impls!($t: std::fmt::Display) {
            found.push("Display");
        }
        if impls!($t: Default) {
            found.push("Default");
        }
        found
    }};
}

/// I-80: root material has no `Clone`, `Copy`, `Debug`, `Display` or
/// `Default`, so no copy, log line or panic message can carry it.
#[test]
fn i80_root_material_has_no_escape_trait() {
    assert_eq!(escapes!(RootMaterial), Vec::<&str>::new());
}

/// I-80: the decoded custody file holds root material, so it has no
/// escape trait either.
#[test]
fn i80_custody_file_has_no_escape_trait() {
    assert_eq!(escapes!(CustodyFile), Vec::<&str>::new());
}

/// I-80, ADR-001 A1: root material is marked `ZeroizeOnDrop` and has drop
/// glue, so dropping it wipes the root bytes in `fstp-keyd` memory.
#[test]
fn i80_root_material_zeroizes_on_drop() {
    assert!(
        impls!(RootMaterial: zeroize::ZeroizeOnDrop),
        "RootMaterial is not ZeroizeOnDrop"
    );
    assert!(
        std::mem::needs_drop::<RootMaterial>(),
        "RootMaterial has no drop glue, so nothing wipes it"
    );
}
