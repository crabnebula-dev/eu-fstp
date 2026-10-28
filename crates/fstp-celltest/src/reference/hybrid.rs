//! The reference hybrid KEM combiner, built on the aws-lc-rs ML-KEM-768
//! and X25519 oracles (design section 3.2, ADR-004 part 1). The W1h test
//! agent owns this file.
//!
//! The aws-lc-rs post-quantum APIs serve only as test oracles, and only
//! from this crate (layering rule 9, ADR-001 A6).
//!
//! Status: W0 stub. It refuses with [`NotImplemented`]. aws-lc-rs is not a
//! dependency of this crate yet; the lead adds the line when W1h starts.

use crate::NotImplemented;

/// The reference combiner over the inputs ADR-004 names.
pub fn combine(
    ss_m: &[u8; 32],
    ss_x: &[u8; 32],
    ct_m: &[u8; 1088],
    e: &[u8; 32],
    pk_x: &[u8; 32],
    pk_m: &[u8; 1184],
) -> Result<[u8; 32], NotImplemented> {
    let _ = (ss_m, ss_x, ct_m, e, pk_x, pk_m);
    Err(NotImplemented::new(
        "fstp_celltest::reference::hybrid::combine",
    ))
}
