//! The retention sweep of stored documents (ADR-007 section "Decided by
//! Daniel on 2026-11-23", decision 1b, lane L39; R-KY-02, P-41).
//!
//! Daniel decided on 2026-11-23 that the erasure runner erases a document
//! automatically when its retention period ends, with the periods the
//! SPEC defines. Where a period is missing it is `TODO(legal)` and
//! nothing of that class is erased.
//!
//! - [`rule`] is the closed table of the `doc.blob` kinds. Contract
//!   documents (kinds 1 to 4) are kept for P-41 per grant, but a row names
//!   no grant and the production cell stores none yet, so they are
//!   [`DocumentRetention::Undefined`] here. Import documents (kind 5) have
//!   no SPEC period: `TODO(legal)`. A brand asset (kind 6) is never erased
//!   by a trigger (Daniel, 2026-11-23). Any other kind fails closed.
//! - [`due`] plans the rows whose period ended. It never plans a brand
//!   asset, whatever the rule says.
//! - [`sweep_once`] reads the clear columns of `doc.blob` as the `app`
//!   role and asks the erasure runner to erase each due document, with the
//!   cause `retention_expiry` and the system authoriser
//!   [`fstp_cell_core::ERASURE_SYSTEM`]. [`run`] does so once an
//!   [`INTERVAL_US`].
//!
//! With today's table the sweep erases nothing. A SPEC period becomes a
//! change of [`rule`] alone. The sweep writes no log line with a count or
//! an id (I-21).

use fstp_rt::Runtime;

use crate::CellError;
use crate::tasks::Clock;
use crate::tasks::erasure::ErasureHandle;

/// How often the sweep runs: once an hour.
pub const INTERVAL_US: i64 = 3_600 * crate::tasks::SECOND_US;

/// The `doc.blob.kind` of an import document (R-PG-02). Kinds 1 to 4 are
/// the contract documents of `fstp_contract::BlobKind`.
pub const KIND_IMPORT_DOCUMENT: i16 = 5;

/// The `doc.blob.kind` of a brand asset, a checked logo (ADR-030).
pub const KIND_BRAND_ASSET: i16 = 6;

/// The cause code of a retention expiry (ADR-007 causes).
const RETENTION_EXPIRY: u16 = 1;

/// How long a class of document is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DocumentRetention {
    /// Never erased by a trigger.
    Never,
    /// No period applies to a stored row: the SPEC sets none, or the row
    /// does not name what the period counts from. Nothing is erased.
    Undefined,
    /// Erased this many microseconds after the row was stored.
    After {
        /// The period.
        micros: i64,
    },
}

/// The retention of the `doc.blob` rows of `kind` (module documentation).
pub const fn rule(kind: i16) -> DocumentRetention {
    match kind {
        // Contract documents: P-41 counted per grant from its last
        // confirmed payment (`SPEC/02-domain/contracts.md`,
        // `fstp_domain::retention`). A row names no grant, and the
        // production cell stores none yet (`SystemTask::ContractPort`).
        1..=4 => DocumentRetention::Undefined,
        // TODO(legal): the retention period of an import document. The
        // SPEC sets none, so none is erased.
        KIND_IMPORT_DOCUMENT => DocumentRetention::Undefined,
        // Daniel, 2026-11-23: a logo is stored without a salt, so no
        // trigger erases one.
        KIND_BRAND_ASSET => DocumentRetention::Never,
        _ => DocumentRetention::Undefined,
    }
}

/// The clear columns of one `doc.blob` row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DocumentRow {
    /// The class.
    pub kind: i16,
    /// The data key id, which names the erasure-log entry.
    pub dek: [u8; 16],
    /// When it was stored, in UTC microseconds.
    pub stored_at: i64,
}

/// The data keys of `rows` whose period under `rule` ended at `now`, in
/// row order. A brand asset is never due, and an end past the range of
/// instants is never reached.
pub fn due(
    rows: &[DocumentRow],
    rule: impl Fn(i16) -> DocumentRetention,
    now: i64,
) -> Vec<[u8; 16]> {
    rows.iter()
        .filter(|r| r.kind != KIND_BRAND_ASSET)
        .filter(|r| match rule(r.kind) {
            DocumentRetention::After { micros } => r
                .stored_at
                .checked_add(micros)
                .is_some_and(|end| end <= now),
            DocumentRetention::Never | DocumentRetention::Undefined => false,
        })
        .map(|r| r.dek)
        .collect()
}

/// One sweep at `now`: reads the rows through `store`, and asks `erasure`
/// to erase each due document, with the cause retention expiry and the
/// system as authoriser. Gives the number of documents it asked for. A
/// document already erased is a no-op of the runner.
///
/// # Errors
///
/// A failed read, or the runner's first refusal. The next sweep retries.
pub async fn sweep_once<R: Runtime>(
    store: &fstp_pgstore::ApiStore<R>,
    erasure: &ErasureHandle,
    rule: impl Fn(i16) -> DocumentRetention,
    now: i64,
) -> Result<usize, CellError> {
    let rows: Vec<DocumentRow> = store
        .document_rows()
        .await
        .map_err(|_| CellError::Keys("the document rows"))?
        .into_iter()
        .map(|(kind, dek, stored_at)| DocumentRow {
            kind,
            dek,
            stored_at,
        })
        .collect();
    let planned = due(&rows, rule, now);
    for dek in &planned {
        erasure
            .erase_document(*dek, RETENTION_EXPIRY, fstp_cell_core::ERASURE_SYSTEM, None)
            .await?;
    }
    Ok(planned.len())
}

/// Sweeps once an [`INTERVAL_US`] with the production table [`rule`]
/// until `stop` (module documentation).
pub async fn run<C: Clock, R: Runtime>(
    clock: &C,
    store: fstp_pgstore::ApiStore<R>,
    erasure: ErasureHandle,
    stop: &fstp_rt::ShutdownSignal,
) {
    use fstp_rt::future::{Either, race};
    loop {
        let now = clock.now();
        let _ = sweep_once(&store, &erasure, rule, now).await;
        let next = now.saturating_add(INTERVAL_US);
        match race(stop.notified(), clock.sleep_until(next)).await {
            Either::Left(()) => return,
            Either::Right(()) => {}
        }
    }
}
