//! Receipt signing and the anchor signature check at the witness
//! (ADR-010 "Receipt" and "Keys", R-CR-03, I-90).
//!
//! Both follow the ADR-010 "Composite encoding" table, which Daniel
//! accepted on 2026-10-29, through `fstp_crypto::composite` as
//! `fstp_audit` re-exports it. A receipt is signed over
//! [`fstp_audit::anchor::receipt_message`] under
//! [`fstp_audit::anchor::RECEIPT_CONTEXT`]. An anchor is checked over
//! [`fstp_audit::anchor::anchor_message`] under
//! [`fstp_audit::anchor::ANCHOR_CONTEXT`], with the same function the
//! chain verifier uses. Both contexts are interim readings of lane W2g
//! (ADR-010 open point 2). Nothing signs or checks with one half alone.

use fstp_audit::anchor::{
    Anchor, RECEIPT_CONTEXT, Receipt, ReceiptFields, anchor_signature_verifies, receipt_message,
};
use fstp_audit::{CellId, ChainId, CompositeSigningKey, Invalid};

use crate::WitnessError;

/// Signs the receipt `fields` for `cell`'s `chain` with the witness's
/// composite receipt key, over [`fstp_audit::anchor::receipt_message`]
/// under [`RECEIPT_CONTEXT`] (ADR-010 "Receipt"). The service signs the
/// fields that [`crate::ChainWitness::prepare`] gave. Custody of `key`
/// stays with the caller.
///
/// # Errors
///
/// [`WitnessError::Invalid`] with [`Invalid::RowNumberZero`] when
/// `fields.n` is 0, or [`Invalid::WitnessSeqZero`] when
/// `fields.witness_seq` is 0. Neither could be encoded or stored. Then
/// [`WitnessError::Signing`] when the composite signer gives no
/// signature.
pub fn sign_receipt(
    key: &CompositeSigningKey,
    cell: CellId,
    chain: ChainId,
    fields: &ReceiptFields,
) -> Result<Receipt, WitnessError> {
    if fields.n == 0 {
        return Err(Invalid::RowNumberZero.into());
    }
    if fields.witness_seq == 0 {
        return Err(Invalid::WitnessSeqZero.into());
    }
    let message = receipt_message(cell, chain, fields);
    let signature = key
        .sign_with_context(&message, RECEIPT_CONTEXT)
        .map_err(WitnessError::Signing)?;
    Ok(Receipt {
        cell,
        chain,
        fields: *fields,
        signature: signature.to_bytes().to_vec(),
    })
}

/// Checks a prepare's anchor signature under the chain's anchor key
/// history, before the witness core sees the prepare (ADR-010 "Keys").
/// Any key of the history may have signed, since old public keys stay in
/// it. Both halves must verify (I-90).
///
/// # Errors
///
/// [`WitnessError::BadSignature`] when no key of `anchor_keys` verifies
/// the signature. That covers an empty history, a malformed key, a
/// signature of another length, another context and either half alone.
pub fn check_anchor_signature(
    anchor: &Anchor,
    anchor_keys: &[Vec<u8>],
) -> Result<(), WitnessError> {
    if anchor_signature_verifies(anchor, anchor_keys) {
        Ok(())
    } else {
        Err(WitnessError::BadSignature)
    }
}
