//! Typed errors of the store. No error holds or shows a stored value,
//! a key byte or SQL text (R-NF-02).

use std::fmt;

use fstp_audit::AuditError;
use fstp_audit::anchorer::WitnessFault;
use fstp_ledger::{AppendError, StoreError};

use crate::pool::PoolError;

/// Why a stored row or a record did not decode (TH-26).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The input ended inside a value.
    Truncated,
    /// Bytes follow the value.
    TrailingBytes,
    /// The format version byte is not known.
    UnknownFormat(u8),
    /// The sequence number is 0. Entries are numbered from 1.
    SeqZero,
    /// The time is beyond `fstp_ledger::MAX_AT` in magnitude.
    TimeOutOfRange,
    /// The schema version is 0. Versions start at 1.
    SchemaZero,
    /// The sealed body is shorter than a nonce and a tag.
    SealedTooShort,
    /// The sealed body is longer than [`crate::MAX_SEALED_LEN`].
    SealedTooLong,
    /// The record decoder of the composer refused the record. It names
    /// what it refused, never a value.
    Record(&'static str),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated => f.write_str("stored row truncated"),
            DecodeError::TrailingBytes => f.write_str("bytes after the stored row"),
            DecodeError::UnknownFormat(v) => write!(f, "unknown stored row format {v}"),
            DecodeError::SeqZero => f.write_str("stored row with sequence 0"),
            DecodeError::TimeOutOfRange => f.write_str("stored row time out of range"),
            DecodeError::SchemaZero => f.write_str("stored row with schema version 0"),
            DecodeError::SealedTooShort => f.write_str("sealed body shorter than nonce and tag"),
            DecodeError::SealedTooLong => f.write_str("sealed body over its limit"),
            DecodeError::Record(what) => write!(f, "record refused: {what}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// A database failure: the client's error class and the SQLSTATE, when
/// the server sent one. The server's message is never kept, since it can
/// quote data (R-NF-02).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DbFault {
    /// The client's error class.
    pub kind: fstp_pgwire::ErrorKind,
    /// The SQLSTATE, for a server error.
    pub sqlstate: Option<String>,
}

impl DbFault {
    /// Whether the server refused with a unique violation (23505).
    pub fn is_unique_violation(&self) -> bool {
        self.sqlstate.as_deref() == Some("23505")
    }
}

impl From<fstp_pgwire::Error> for DbFault {
    fn from(e: fstp_pgwire::Error) -> DbFault {
        DbFault {
            kind: e.kind(),
            sqlstate: e.code().map(str::to_owned),
        }
    }
}

impl fmt::Display for DbFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.sqlstate {
            Some(code) => write!(f, "database error {:?}, SQLSTATE {code}", self.kind),
            None => write!(f, "database error {:?}", self.kind),
        }
    }
}

/// Why a store operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreFault {
    /// The database refused or could not be reached.
    Database(DbFault),
    /// The pool refused.
    Pool(PoolError),
    /// The pool serves another role than the operation needs.
    WrongRole,
    /// No ledger key can seal: the current key reached
    /// [`crate::LEDGER_KEY_SEALS`], or the generator failed.
    SealRefused,
    /// A stored body did not open under its key and context. Either it
    /// was moved or changed, or its key is unknown to this process.
    OpenFailed,
    /// A stored row or record did not decode.
    Decode(DecodeError),
    /// Stored rows break a rule of the store, such as a gap in the
    /// ledger. It names the rule.
    Corrupt(&'static str),
    /// `fstp-audit` refused, for example to sign an anchor.
    Audit(AuditError),
    /// The witness gave no answer the protocol can use.
    Witness(WitnessFault),
    /// The anchorer core refused a step: its state is not the one the
    /// call needs.
    OutOfOrder,
    /// The anchorer core waits on another head than the one named.
    OtherHeadPending,
    /// An input is outside what the store accepts. It names the rule.
    Refused(&'static str),
    /// The current ledger key generation already names a stored row,
    /// before this process sealed with it. ADR-004 gives every process
    /// start a new generation, since a seal count lives in memory only.
    KeyGenerationReused,
    /// The witness receipt is not signed by a pinned witness key (ADR-010
    /// "Keys"). The store rolls back and sends the abort.
    ReceiptUnsigned,
}

impl fmt::Display for StoreFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreFault::Database(e) => write!(f, "{e}"),
            StoreFault::Pool(e) => write!(f, "pool: {e}"),
            StoreFault::WrongRole => f.write_str("the pool serves another role"),
            StoreFault::SealRefused => f.write_str("no ledger key can seal"),
            StoreFault::OpenFailed => f.write_str("a stored body did not open"),
            StoreFault::Decode(e) => write!(f, "{e}"),
            StoreFault::Corrupt(rule) => write!(f, "stored rows break a store rule: {rule}"),
            StoreFault::Audit(e) => write!(f, "audit: {e}"),
            StoreFault::Witness(e) => write!(f, "witness: {e:?}"),
            StoreFault::OutOfOrder => f.write_str("the anchorer core refused the step"),
            StoreFault::OtherHeadPending => f.write_str("another prepared head is pending"),
            StoreFault::Refused(rule) => write!(f, "refused: {rule}"),
            StoreFault::KeyGenerationReused => {
                f.write_str("the ledger key generation already sealed stored rows")
            }
            StoreFault::ReceiptUnsigned => {
                f.write_str("the receipt is not signed by a pinned witness key")
            }
        }
    }
}

impl std::error::Error for StoreFault {}

impl From<fstp_pgwire::Error> for StoreFault {
    fn from(e: fstp_pgwire::Error) -> StoreFault {
        StoreFault::Database(DbFault::from(e))
    }
}

impl From<PoolError> for StoreFault {
    fn from(e: PoolError) -> StoreFault {
        StoreFault::Pool(e)
    }
}

impl From<DecodeError> for StoreFault {
    fn from(e: DecodeError) -> StoreFault {
        StoreFault::Decode(e)
    }
}

impl From<AuditError> for StoreFault {
    fn from(e: AuditError) -> StoreFault {
        StoreFault::Audit(e)
    }
}

/// Why an append with side effects was not committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppendFault {
    /// A refusal of the store contract, in the order of
    /// `fstp_ledger::RecordStore::append`: a duplicate command, a stale
    /// head, then a time out of range, an empty batch or a full ledger.
    Refused(AppendError),
    /// The batch's step-up is past its freshness bound at commit, or the
    /// store has no clock to check it with (I-78).
    StepUpStale,
    /// A side-effect row already exists: a step-up consumed again or a
    /// session ended again. The whole append aborted (I-77, I-78).
    SideEffectReplayed,
    /// An outbox row of the side effects has the `id` or the `idem` of a
    /// stored row, or of another row of the same append. The whole append
    /// aborted (TH-21).
    OutboxDuplicate,
    /// An earlier prepare is still unresolved: its abort or its in-doubt
    /// record has not reached the witness. No write is admitted until it
    /// is (ADR-010).
    Pending(StoreFault),
    /// COMMIT was sent and its outcome is unknown. The store resolves it
    /// before its next append (design section 7.2 "In doubt").
    Unknown,
    /// The append failed before COMMIT. Nothing was committed.
    Fault(StoreFault),
}

impl fmt::Display for AppendFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppendFault::Refused(e) => write!(f, "{e}"),
            AppendFault::StepUpStale => f.write_str("the step-up is past its freshness bound"),
            AppendFault::SideEffectReplayed => f.write_str("a side-effect row already exists"),
            AppendFault::OutboxDuplicate => f.write_str("an outbox row already exists"),
            AppendFault::Pending(e) => write!(f, "an earlier prepare is unresolved: {e}"),
            AppendFault::Unknown => f.write_str("the commit outcome is unknown"),
            AppendFault::Fault(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AppendFault {}

impl From<StoreFault> for AppendFault {
    fn from(e: StoreFault) -> AppendFault {
        AppendFault::Fault(e)
    }
}

impl From<AppendFault> for AppendError {
    /// The contract refusals pass through. Every other failure is the
    /// store failing, which `fstp_ledger` names `Unavailable`.
    fn from(e: AppendFault) -> AppendError {
        match e {
            AppendFault::Refused(r) => r,
            AppendFault::StepUpStale
            | AppendFault::SideEffectReplayed
            | AppendFault::OutboxDuplicate
            | AppendFault::Pending(_)
            | AppendFault::Unknown
            | AppendFault::Fault(_) => AppendError::Store(StoreError::Unavailable),
        }
    }
}

impl From<StoreFault> for StoreError {
    /// `fstp_ledger::StoreError` has one class for a failing store.
    fn from(_: StoreFault) -> StoreError {
        StoreError::Unavailable
    }
}
