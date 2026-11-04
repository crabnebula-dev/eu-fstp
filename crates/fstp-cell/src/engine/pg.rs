//! The engine's store over `fstp_pgstore::PgRecordStore` (design sections
//! 5.3 and 7.2, ADR-007, ADR-010, I-23, I-24, I-78).
//!
//! [`PgCellStore`] is the [`CellStore`] of a serving cell. It runs every
//! append through `PgRecordStore::append_committed`, the protocol of
//! design section 5.3 with the prepare, receipt and commit tail of section
//! 7.2, and reports the chain link and the witness receipt of the commit.
//! The vault acknowledgement names that link (NOTE 4).
//!
//! The driver's side effects carry ids only. [`side_effects`] finds the
//! record of each in the batch, so every `auth_log` row names the entry of
//! the record it belongs to:
//!
//! - The consumed step-up is keyed by its challenge id, which is the
//!   step-up id end to end (`fstp_cell_core::stepup_id`). Its row names the
//!   entry of the batch's `StepUpConsumed` record.
//! - Each ended session is one `auth_log.session_end` row, which names the
//!   entry of its `SessionEnded` record.
//!
//! A replayed step-up or a second end of one session violates a primary
//! key, and the whole append aborts. A stale step-up at the commit instant
//! is refused by the store's own clock. Both refuse as [`CellAppendError`]
//! and commit nothing.

use std::sync::Arc;

use fstp_audit::anchorer::PrepareWitness;
use fstp_cell_core::CellRecord;
use fstp_cell_core::driver::ReceiptRef;
use fstp_ledger::{AppendError, AsyncRecordStore, Entry, Seq, StoreError};
use fstp_pgstore::{
    AnchorSigner, AppendFault, DecodeError, LedgerKeys, OutboxKeys, PgRecordStore, Pool,
    SessionEnd, StepUpUse, StoreFault,
};
use fstp_rt::Runtime;

use super::{AppendRequest, CellAppendError, CellStore, Committed, StoredCommit};

/// The decoder `fstp-cell` passes to `PgRecordStore` (design section 5.3):
/// `fstp_cell_core::record_from_canonical_at`, with its refusal as the
/// store's typed decode error. No refusal quotes the record.
///
/// # Errors
///
/// [`DecodeError::Record`] for a schema version outside the cell's
/// published versions, or text that is not one cell record.
pub fn decode_cell_record(canonical: &[u8], schema: u16) -> Result<CellRecord, DecodeError> {
    fstp_cell_core::record_from_canonical_at(canonical, schema)
        .map_err(|_| DecodeError::Record("a cell record that does not decode at its schema"))
}

/// The record store of a cell over its writer role, as the engine reaches
/// it (design section 5.3).
pub struct PgCellStore<R: Runtime, W> {
    inner: PgRecordStore<R, CellRecord, W>,
}

impl<R: Runtime, W: PrepareWitness> std::fmt::Debug for PgCellStore<R, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgCellStore")
            .field("cell", &self.inner.cell())
            .finish_non_exhaustive()
    }
}

impl<R: Runtime, W: PrepareWitness> PgCellStore<R, W> {
    /// The store of the cell of `pool`, which must serve the writer role,
    /// with the cell's record decoder ([`decode_cell_record`]). The other
    /// arguments are those of `PgRecordStore::new`.
    ///
    /// # Errors
    ///
    /// `PgRecordStore::new`'s refusal: a pool of another role, an empty
    /// witness pin set, or a pinned key that is not a composite key.
    pub fn new(
        pool: Pool<R>,
        keys: Arc<LedgerKeys>,
        signer: Arc<dyn AnchorSigner>,
        witness: W,
        witness_keys: Vec<Vec<u8>>,
        outbox_keys: Arc<dyn OutboxKeys>,
    ) -> Result<PgCellStore<R, W>, StoreFault> {
        let inner = PgRecordStore::new(
            pool,
            keys,
            signer,
            witness,
            witness_keys,
            outbox_keys,
            decode_cell_record,
        )?;
        Ok(PgCellStore { inner })
    }

    /// A cell store over `inner`, a record store built with
    /// [`decode_cell_record`] or a decoder with the same results.
    pub fn from_store(inner: PgRecordStore<R, CellRecord, W>) -> PgCellStore<R, W> {
        PgCellStore { inner }
    }

    /// The record store.
    pub fn inner(&self) -> &PgRecordStore<R, CellRecord, W> {
        &self.inner
    }

    /// The record store, mutably, for the start-up resolution of an open
    /// prepare (`PgRecordStore::resolve_in_doubt`).
    pub fn inner_mut(&mut self) -> &mut PgRecordStore<R, CellRecord, W> {
        &mut self.inner
    }

    /// The record store, for a restart.
    pub fn into_inner(self) -> PgRecordStore<R, CellRecord, W> {
        self.inner
    }
}

/// The store's side effects of the driver's append `req` (design section
/// 5.3 step 6), each with the index of its record in the batch.
///
/// The driver's consumed step-up must be exactly the batch's
/// `StepUpConsumed` records: none when it names none, and else one, of
/// the same id. Each ended session names its `SessionEnded` record, and
/// the driver's list of ended sessions must be exactly those records. A
/// batch that breaks either rule is refused before any row is written,
/// since it would leave an `auth_log` row without its record or a record
/// without its row. So no `StepUpConsumed` record commits without the
/// `auth_log.stepup_consumed` primary key behind it (design section 4.2).
///
/// # Errors
///
/// [`StoreError::Unavailable`] as a ledger refusal for a batch that breaks
/// the rules above.
pub fn side_effects(req: &AppendRequest) -> Result<fstp_pgstore::SideEffects, CellAppendError> {
    let refuse = || CellAppendError::Ledger(AppendError::Store(StoreError::Unavailable));
    let consumed: Vec<(usize, [u8; 16])> = req
        .batch
        .iter()
        .enumerate()
        .filter_map(|(record, r)| match r {
            CellRecord::Auth(fstp_auth::AuthRecord::StepUpConsumed { id }) => Some((record, *id)),
            _ => None,
        })
        .collect();
    let stepup_consumed = match (req.side.stepup_consumed, consumed.as_slice()) {
        (None, []) => None,
        (Some(id), [(record, c)]) if *c == id => Some(StepUpUse {
            challenge: id,
            record: *record,
        }),
        _ => return Err(refuse()),
    };
    let sessions_ended: Vec<SessionEnd> = req
        .batch
        .iter()
        .enumerate()
        .filter_map(|(record, r)| match r {
            CellRecord::Auth(fstp_auth::AuthRecord::SessionEnded { session }) => Some(SessionEnd {
                session: *session,
                record,
            }),
            _ => None,
        })
        .collect();
    let named: Vec<[u8; 16]> = sessions_ended.iter().map(|s| s.session).collect();
    if named != req.side.sessions_ended {
        return Err(refuse());
    }
    Ok(fstp_pgstore::SideEffects {
        stepup_consumed,
        stepup_fresh_until: req.side.stepup_fresh_until,
        sessions_ended,
        outbox: Vec::new(),
    })
}

/// The engine's error of a refused append.
fn append_error(f: AppendFault) -> CellAppendError {
    match f {
        AppendFault::Refused(e) => CellAppendError::Ledger(e),
        AppendFault::StepUpStale => CellAppendError::StepUpStale,
        // The step-up row conflicted: the one replay the fold does not rule
        // out before the append (I-78). A session-end row that conflicts
        // is a store that disagrees with the fold, which never names an
        // ended session again, so it reads as the store failing.
        AppendFault::StepUpReplayed => CellAppendError::StepUpReplayed,
        AppendFault::SessionEndReplayed
        | AppendFault::OutboxDuplicate
        | AppendFault::Pending(_)
        | AppendFault::Unknown
        | AppendFault::Fault(_) => {
            CellAppendError::Ledger(AppendError::Store(StoreError::Unavailable))
        }
    }
}

impl<R, W> AsyncRecordStore<CellRecord> for PgCellStore<R, W>
where
    R: Runtime,
    W: PrepareWitness + Send + Sync + 'static,
{
    fn head(&self) -> impl std::future::Future<Output = Result<Seq, StoreError>> + Send {
        AsyncRecordStore::head(&self.inner)
    }

    async fn append(
        &mut self,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: Vec<CellRecord>,
    ) -> Result<Seq, AppendError> {
        let req = AppendRequest {
            expected,
            at,
            command,
            batch,
            side: fstp_cell_core::driver::SideEffects::default(),
        };
        self.append_cell(req)
            .await
            .map(|c| c.head)
            .map_err(CellAppendError::into_ledger)
    }

    fn read(
        &self,
        from: Seq,
        limit: usize,
        out: &mut Vec<Entry<CellRecord>>,
    ) -> impl std::future::Future<Output = Result<(), StoreError>> + Send {
        AsyncRecordStore::read(&self.inner, from, limit, out)
    }
}

impl<R, W> CellStore for PgCellStore<R, W>
where
    R: Runtime,
    W: PrepareWitness + Send + Sync + 'static,
{
    async fn append_cell(&mut self, req: AppendRequest) -> Result<Committed, CellAppendError> {
        let side = side_effects(&req)?;
        let c = self
            .inner
            .append_committed(req.expected, req.at, req.command, req.batch, &side)
            .await
            .map_err(append_error)?;
        Ok(Committed {
            head: c.head,
            link: c.link.0,
            receipt: Some(ReceiptRef {
                witness_seq: c.witness_seq,
            }),
        })
    }

    async fn stored_commit(&self, seq: Seq) -> Result<Option<StoredCommit>, StoreError> {
        let c = self
            .inner
            .stored_commit(seq)
            .await
            .map_err(StoreError::from)?;
        Ok(c.map(|c| StoredCommit {
            link: c.link.0,
            receipt: c.witness_seq.map(|witness_seq| ReceiptRef { witness_seq }),
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use fstp_auth::AuthRecord;
    use fstp_cell_core::text::TextRecord;

    fn request(batch: Vec<CellRecord>, side: fstp_cell_core::driver::SideEffects) -> AppendRequest {
        AppendRequest {
            expected: Seq::ZERO,
            at: 1,
            command: [0x42; 16],
            batch,
            side,
        }
    }

    /// I-77, I-78, design section 5.3 step 6: each `auth_log` row names
    /// the record of the batch it belongs to. The step-up row is keyed by
    /// the step-up id, the challenge id end to end, and names its
    /// `StepUpConsumed` record. Each session row names its `SessionEnded`
    /// record.
    #[test]
    fn i78_side_effects_name_the_records_they_belong_to() {
        let id = [0xC4; 16];
        let batch = vec![
            CellRecord::Text(TextRecord::TextPut { id: [1; 16] }),
            CellRecord::Auth(AuthRecord::SessionEnded { session: [2; 16] }),
            CellRecord::Auth(AuthRecord::SessionEnded { session: [3; 16] }),
            CellRecord::Auth(AuthRecord::StepUpConsumed { id }),
        ];
        let side = fstp_cell_core::driver::SideEffects {
            stepup_consumed: Some(id),
            stepup_fresh_until: Some(7),
            sessions_ended: vec![[2; 16], [3; 16]],
        };
        let got = side_effects(&request(batch, side)).unwrap();
        assert_eq!(
            got.stepup_consumed,
            Some(StepUpUse {
                challenge: id,
                record: 3,
            })
        );
        assert_eq!(got.stepup_fresh_until, Some(7));
        assert_eq!(
            got.sessions_ended,
            vec![
                SessionEnd {
                    session: [2; 16],
                    record: 1,
                },
                SessionEnd {
                    session: [3; 16],
                    record: 2,
                },
            ]
        );
        assert!(got.outbox.is_empty());
    }

    /// I-77, I-78, design section 5.3: a side effect with no record of its
    /// batch, or a record with no side effect, is refused before any row
    /// is written, so no `auth_log` row ever lacks its ledger entry.
    #[test]
    fn i78_side_effects_without_their_records_are_refused() {
        let refused = Err(CellAppendError::Ledger(AppendError::Store(
            StoreError::Unavailable,
        )));
        let consumed = |id| CellRecord::Auth(AuthRecord::StepUpConsumed { id });
        let side = |stepup: Option<[u8; 16]>, sessions: Vec<[u8; 16]>| {
            fstp_cell_core::driver::SideEffects {
                stepup_consumed: stepup,
                stepup_fresh_until: None,
                sessions_ended: sessions,
            }
        };
        assert_eq!(
            side_effects(&request(
                vec![consumed([1; 16])],
                side(Some([2; 16]), Vec::new())
            )),
            refused
        );
        assert_eq!(
            side_effects(&request(vec![consumed([1; 16])], side(None, vec![[5; 16]]))),
            refused
        );
        let ended = CellRecord::Auth(AuthRecord::SessionEnded { session: [5; 16] });
        assert_eq!(
            side_effects(&request(vec![ended], side(None, Vec::new()))),
            refused
        );
    }

    /// I-78, design sections 4.2 and 5.3: a `StepUpConsumed` record that
    /// the driver's side effects do not name is refused before any row is
    /// written, as is a second one. So the plain `AsyncRecordStore::append`
    /// path, which names no side effects, never commits a consumption
    /// without the `auth_log.stepup_consumed` primary key behind it.
    #[test]
    fn i78_a_step_up_consumption_never_commits_without_its_row() {
        let refused = Err(CellAppendError::Ledger(AppendError::Store(
            StoreError::Unavailable,
        )));
        let consumed = |id| CellRecord::Auth(AuthRecord::StepUpConsumed { id });
        let side = |stepup: Option<[u8; 16]>| fstp_cell_core::driver::SideEffects {
            stepup_consumed: stepup,
            stepup_fresh_until: None,
            sessions_ended: Vec::new(),
        };
        assert_eq!(
            side_effects(&request(vec![consumed([1; 16])], side(None))),
            refused
        );
        assert_eq!(
            side_effects(&request(
                vec![consumed([1; 16]), consumed([1; 16])],
                side(Some([1; 16]))
            )),
            refused
        );
        assert_eq!(
            side_effects(&request(
                vec![consumed([1; 16]), consumed([2; 16])],
                side(Some([1; 16]))
            )),
            refused
        );
        let text = CellRecord::Text(TextRecord::TextPut { id: [3; 16] });
        assert!(side_effects(&request(vec![text], side(None))).is_ok());
    }

    /// I-78, design section 8.4: a stale or replayed step-up refuses the
    /// commit as a step-up refusal, never as an outage. A session-end row
    /// that conflicts is never read as a step-up replay, even in a batch
    /// that consumes a step-up. Contract refusals pass through, and every
    /// other fault is the store failing.
    #[test]
    fn i78_store_refusals_map_to_the_engine_refusals() {
        assert_eq!(
            append_error(AppendFault::StepUpStale),
            CellAppendError::StepUpStale
        );
        assert_eq!(
            append_error(AppendFault::StepUpReplayed),
            CellAppendError::StepUpReplayed
        );
        let unavailable = CellAppendError::Ledger(AppendError::Store(StoreError::Unavailable));
        assert_eq!(append_error(AppendFault::SessionEndReplayed), unavailable);
        assert_eq!(append_error(AppendFault::Unknown), unavailable);
        let dup = AppendError::DuplicateCommand {
            at: Seq::from_raw(4),
        };
        assert_eq!(
            append_error(AppendFault::Refused(dup)),
            CellAppendError::Ledger(dup)
        );
    }

    /// ADR-007, design section 5.3: the store decodes a cell record at a
    /// published schema, and refuses an unpublished schema with a typed
    /// error that quotes nothing.
    #[test]
    fn adr007_cell_decoder_refuses_an_unpublished_schema() {
        let r = CellRecord::Text(TextRecord::TextPut { id: [1; 16] });
        let bytes = fstp_cell_core::encode_cell_record(&r);
        assert_eq!(decode_cell_record(&bytes, fstp_ledger::SCHEMA_V1), Ok(r));
        assert!(matches!(
            decode_cell_record(&bytes, 999),
            Err(DecodeError::Record(_))
        ));
    }
}
