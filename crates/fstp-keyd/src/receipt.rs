//! The destroy receipt of file custody (ADR-004 part 2: "The receipt
//! records each step").
//!
//! The receipt bytes and their decoder live in `fstp_custody::keyd`, so
//! the `KeydCustody` client checks every receipt it gets: it must name
//! the destroyed chain and epoch and list every step once and in order.
//! No ADR fixed these bytes before lane W2f wrote them at first use, and
//! their record in ADR-004 is with the lead.
//!
//! ```text
//! receipt = "FKR1" | version u8 = 1 | chain u8 | epoch u64 | count u8 | count step codes
//! steps   = 1 overwrite K(e) | 2 fsync table | 3 unlink epoch file
//!           | 4 fsync directory | 5 read back
//! ```

pub use fstp_custody::keyd::{DestroyStep, RECEIPT_MAGIC, RECEIPT_VERSION, Receipt};

use crate::KeydError;

/// Decodes a destroy receipt of `fstp-keyd`.
///
/// # Errors
///
/// Refuses any input that is not one receipt in its one spelling, and a
/// receipt whose steps are not exactly [`DestroyStep::ALL`] in order.
pub fn decode_receipt(bytes: &[u8]) -> Result<Receipt, KeydError> {
    fstp_custody::keyd::decode_receipt(bytes)
        .map_err(|_| KeydError::Malformed("not one complete destroy receipt"))
}
