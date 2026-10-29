//! Receipt signing and the anchor signature check at the witness
//! (ADR-010 "Receipt", R-CR-03).
//!
//! Lane W2g hard limit (ADR-010 "Composite encoding"): no production code
//! in `fstp-witness` signs or verifies before Daniel accepts the composite
//! encoding table. Both functions refuse for every input, read no key
//! byte, and never fall back to Ed25519 alone or to the aws-lc-rs oracle.
//! The witness therefore gives no receipt, and the cell refuses writes, as
//! ADR-010 says for the time before the moduletto pull request lands.

use fstp_audit::anchor::{Anchor, Receipt, ReceiptFields};
use fstp_audit::{COMPOSITE_ENCODING_ACCEPTANCE, CellId, ChainId, CompositeSigningKey};

use crate::WitnessError;

/// Signs the receipt `fields` for `cell`'s `chain` with the witness's
/// composite receipt key, over [`fstp_audit::anchor::receipt_message`].
///
/// # Errors
///
/// [`WitnessError::AwaitsAcceptance`] naming
/// [`COMPOSITE_ENCODING_ACCEPTANCE`], for every input.
pub fn sign_receipt(
    key: &CompositeSigningKey,
    cell: CellId,
    chain: ChainId,
    fields: &ReceiptFields,
) -> Result<Receipt, WitnessError> {
    let _ = (key, cell, chain, fields);
    Err(WitnessError::AwaitsAcceptance(
        COMPOSITE_ENCODING_ACCEPTANCE,
    ))
}

/// Checks a prepare's anchor signature under the chain's pinned anchor
/// key history, before the witness core sees the prepare.
///
/// # Errors
///
/// [`WitnessError::AwaitsAcceptance`] naming
/// [`COMPOSITE_ENCODING_ACCEPTANCE`], for every input.
pub fn check_anchor_signature(
    anchor: &Anchor,
    anchor_keys: &[Vec<u8>],
) -> Result<(), WitnessError> {
    let _ = (anchor, anchor_keys);
    Err(WitnessError::AwaitsAcceptance(
        COMPOSITE_ENCODING_ACCEPTANCE,
    ))
}
