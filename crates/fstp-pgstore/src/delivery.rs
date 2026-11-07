//! The delivery log `ops.delivery` of the M6 dispatcher (M6 design
//! sections 3.2 and 5.1, I-25, I-26).
//!
//! Each step of an attempt inserts one row. Rows are never changed. The
//! head of a message is its row with the highest (attempt, phase).
//!
//! The rules over the head are pure functions here ([`next_step`],
//! [`may_commit`], [`may_record`]), so the store over PostgreSQL
//! ([`DeliveryLog`]) and the in-memory model of the dispatcher tests apply
//! the same rules. [`DeliveryLog`] applies each under the transaction
//! advisory lock of the message, so the read of the head and the insert
//! are one step for every worker of the cell.
//!
//! The attempt number is the fencing token. A worker passes the commit
//! point (S4) only while the head is its own CLAIMED row of that attempt.
//! A worker whose lease was taken over fails S4 and never sends the end of
//! DATA, so at most one end of DATA exists per message (I-26).

use fstp_pgwire::Uuid;
use fstp_rt::Runtime;

use std::sync::Arc;

use fstp_keys::{DekId, ObjectId};

use crate::error::StoreFault;
use crate::outbox::{OutboxKeys, open_outbox_body};
use crate::pool::{Pool, Role};

/// The lease of a claim, in microseconds: 60 seconds (M6 design section
/// 5.1, S1).
pub const DELIVERY_LEASE_US: i64 = 60_000_000;

/// The most attempts of one message. After a transient failure of the
/// last one, the message is recorded PERMANENT (M6 design section 5.1).
pub const MAX_ATTEMPTS: u32 = 8;

const MINUTE_US: i64 = 60_000_000;

/// The phase of a delivery row (M6 design section 3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Phase {
    /// S1: a worker claimed the attempt under a lease.
    Claimed,
    /// S4: the commit point. The end of DATA may follow.
    Committing,
    /// The server answered 250 to the end of DATA.
    Sent,
    /// A 4xx reply, or a failure before the commit point. Retried.
    Transient,
    /// A 5xx reply, or the last attempt failed. Never retried.
    Permanent,
    /// The outcome after the commit point is unknown. Never sent again
    /// automatically.
    InDoubt,
}

impl Phase {
    /// Every phase, in code order.
    pub const ALL: [Phase; 6] = [
        Phase::Claimed,
        Phase::Committing,
        Phase::Sent,
        Phase::Transient,
        Phase::Permanent,
        Phase::InDoubt,
    ];

    /// The `ops.delivery.phase` code.
    pub fn code(self) -> i16 {
        match self {
            Phase::Claimed => 1,
            Phase::Committing => 2,
            Phase::Sent => 3,
            Phase::Transient => 4,
            Phase::Permanent => 5,
            Phase::InDoubt => 6,
        }
    }

    /// The phase of a code.
    pub fn from_code(code: i16) -> Option<Phase> {
        Phase::ALL.into_iter().find(|p| p.code() == code)
    }

    /// Whether no row follows this one: SENT, PERMANENT or IN_DOUBT.
    pub fn is_terminal(self) -> bool {
        matches!(self, Phase::Sent | Phase::Permanent | Phase::InDoubt)
    }
}

/// What the COMMITTING row records in clear (M6 design section 3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CommitFacts {
    /// The event id.
    pub event: [u8; 32],
    /// The template version.
    pub template_version: u16,
    /// The HMAC-SHA256 of the rendered body under a cell key (m4-design
    /// section 15.0, 2026-11-07).
    pub body_digest: [u8; 32],
}

/// One row of `ops.delivery`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DeliveryRow {
    /// The `ops.outbox` row.
    pub outbox: [u8; 16],
    /// The attempt, from 1.
    pub attempt: u32,
    /// The phase.
    pub phase: Phase,
    /// When it was written, UTC microseconds.
    pub at: i64,
    /// The worker that wrote it.
    pub worker: [u8; 16],
    /// The lease of a CLAIMED or COMMITTING row.
    pub lease_until: Option<i64>,
    /// The facts of a COMMITTING row.
    pub commit: Option<CommitFacts>,
    /// The reply code of a SENT, TRANSIENT or PERMANENT row.
    pub reply_code: Option<u16>,
}

impl DeliveryRow {
    /// The row's key in head order.
    pub fn order(&self) -> (u32, Phase) {
        (self.attempt, self.phase)
    }

    /// Whether the row meets the CHECK constraints of `ops.delivery`.
    pub fn is_well_formed(&self) -> bool {
        let leased = matches!(self.phase, Phase::Claimed | Phase::Committing);
        self.attempt >= 1
            && leased == self.lease_until.is_some()
            && (self.phase == Phase::Committing) == self.commit.is_some()
            && self.reply_code.is_none_or(|c| {
                (200..=599).contains(&c)
                    && matches!(
                        self.phase,
                        Phase::Sent | Phase::Transient | Phase::Permanent
                    )
            })
    }
}

/// What a worker may do next with a message, read from its head (M6
/// design section 5.1, recovery).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Next {
    /// Claim attempt `attempt`.
    Claim {
        /// The attempt to claim.
        attempt: u32,
    },
    /// Another worker holds a live lease until `until`.
    Busy {
        /// The end of the lease.
        until: i64,
    },
    /// A transient failure backs off until `until`.
    Wait {
        /// The end of the backoff.
        until: i64,
    },
    /// The head is COMMITTING with an ended lease: record IN_DOUBT for
    /// `attempt`.
    RecordInDoubt {
        /// The attempt.
        attempt: u32,
    },
    /// The last attempt failed transiently: record PERMANENT for
    /// `attempt`.
    GiveUp {
        /// The attempt.
        attempt: u32,
    },
    /// The message has its terminal row.
    Done,
}

/// The backoff after transient attempt `attempt`: 1, 5 and 30 minutes,
/// then hourly (M6 design section 5.1).
pub fn backoff_us(attempt: u32) -> i64 {
    match attempt {
        0 | 1 => MINUTE_US,
        2 => MINUTE_US.saturating_mul(5),
        3 => MINUTE_US.saturating_mul(30),
        _ => MINUTE_US.saturating_mul(60),
    }
}

/// What may happen next to a message whose head is `head`, at `now`.
pub fn next_step(head: Option<&DeliveryRow>, now: i64) -> Next {
    let Some(h) = head else {
        return Next::Claim { attempt: 1 };
    };
    let lease = h.lease_until.unwrap_or(i64::MIN);
    let after = h.attempt.saturating_add(1);
    match h.phase {
        Phase::Sent | Phase::Permanent | Phase::InDoubt => Next::Done,
        Phase::Claimed | Phase::Committing if now < lease => Next::Busy { until: lease },
        // The server never saw the end of DATA, so it discarded the
        // message.
        Phase::Claimed => Next::Claim { attempt: after },
        Phase::Committing => Next::RecordInDoubt { attempt: h.attempt },
        Phase::Transient if h.attempt >= MAX_ATTEMPTS => Next::GiveUp { attempt: h.attempt },
        Phase::Transient => {
            let until = h.at.saturating_add(backoff_us(h.attempt));
            if now < until {
                Next::Wait { until }
            } else {
                Next::Claim { attempt: after }
            }
        }
    }
}

/// Whether `worker` may pass the commit point (S4) of `attempt`: the head
/// is still its own CLAIMED row of that attempt.
pub fn may_commit(head: Option<&DeliveryRow>, worker: [u8; 16], attempt: u32) -> bool {
    head.is_some_and(|h| h.phase == Phase::Claimed && h.attempt == attempt && h.worker == worker)
}

/// Whether `worker` may record `phase` for `attempt` (S6). SENT follows
/// only its own COMMITTING row. TRANSIENT and PERMANENT follow its own
/// CLAIMED or COMMITTING row of that attempt.
pub fn may_record(
    head: Option<&DeliveryRow>,
    worker: [u8; 16],
    attempt: u32,
    phase: Phase,
) -> bool {
    let Some(h) = head else {
        return false;
    };
    let own = h.attempt == attempt && h.worker == worker;
    match phase {
        Phase::Sent => own && h.phase == Phase::Committing,
        Phase::Transient | Phase::Permanent => {
            own && matches!(h.phase, Phase::Claimed | Phase::Committing)
        }
        Phase::Claimed | Phase::Committing | Phase::InDoubt => false,
    }
}

const LOCK_SQL: &str =
    "SELECT pg_catalog.pg_advisory_xact_lock(6::pg_catalog.int4, $1::pg_catalog.int4)";

const HEAD_SQL: &str = "SELECT outbox_id, attempt, phase, at, worker, lease_until, event, \
     template_version, body_digest, reply_code FROM ops.delivery WHERE outbox_id = $1 \
     ORDER BY attempt DESC, phase DESC LIMIT 1";

const ROWS_SQL: &str = "SELECT outbox_id, attempt, phase, at, worker, lease_until, event, \
     template_version, body_digest, reply_code FROM ops.delivery WHERE outbox_id = $1 \
     ORDER BY attempt, phase";

const INSERT_SQL: &str = "INSERT INTO ops.delivery (outbox_id, attempt, phase, at, worker, \
     lease_until, event, template_version, body_digest, reply_code) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)";

const PENDING_SQL: &str = "SELECT o.id FROM ops.outbox o WHERE o.kind = $1 AND NOT EXISTS \
     (SELECT 1 FROM ops.delivery d WHERE d.outbox_id = o.id AND d.phase IN (3, 5, 6)) \
     ORDER BY o.created_at, o.id LIMIT $2";

/// The lock key of a message: its first four bytes.
fn lock_key(outbox: &[u8; 16]) -> i32 {
    i32::from_be_bytes([outbox[0], outbox[1], outbox[2], outbox[3]])
}

fn row_of(row: &fstp_pgwire::Row) -> Result<DeliveryRow, StoreFault> {
    let corrupt = || StoreFault::Corrupt("an ops.delivery row outside its constraints");
    let outbox: Uuid = row.get(0)?;
    let attempt: i32 = row.get(1)?;
    let phase: i16 = row.get(2)?;
    let at: i64 = row.get(3)?;
    let worker: Uuid = row.get(4)?;
    let lease_until: Option<i64> = row.get(5)?;
    let event: Option<Vec<u8>> = row.get(6)?;
    let template_version: Option<i32> = row.get(7)?;
    let body_digest: Option<Vec<u8>> = row.get(8)?;
    let reply_code: Option<i16> = row.get(9)?;
    let commit = match (event, template_version, body_digest) {
        (Some(e), Some(v), Some(d)) => Some(CommitFacts {
            event: <[u8; 32]>::try_from(e.as_slice()).map_err(|_| corrupt())?,
            template_version: u16::try_from(v).map_err(|_| corrupt())?,
            body_digest: <[u8; 32]>::try_from(d.as_slice()).map_err(|_| corrupt())?,
        }),
        (None, None, None) => None,
        _ => return Err(corrupt()),
    };
    Ok(DeliveryRow {
        outbox: *outbox.as_bytes(),
        attempt: u32::try_from(attempt).map_err(|_| corrupt())?,
        phase: Phase::from_code(phase).ok_or_else(corrupt)?,
        at,
        worker: *worker.as_bytes(),
        lease_until,
        commit,
        reply_code: reply_code
            .map(|c| u16::try_from(c).map_err(|_| corrupt()))
            .transpose()?,
    })
}

/// The delivery log of one cell over its app role (M6 design section
/// 3.2).
pub struct DeliveryLog<R: Runtime> {
    pool: Pool<R>,
}

impl<R: Runtime> DeliveryLog<R> {
    /// The log over `pool`, which must serve the app role.
    ///
    /// # Errors
    ///
    /// [`StoreFault::WrongRole`] for a pool of another role.
    pub fn new(pool: Pool<R>) -> Result<DeliveryLog<R>, StoreFault> {
        if pool.role() != Role::App {
            return Err(StoreFault::WrongRole);
        }
        Ok(DeliveryLog { pool })
    }

    /// Every row of `outbox`, in head order.
    ///
    /// # Errors
    ///
    /// A pool or database fault, or a stored row outside its constraints.
    pub async fn rows(&self, outbox: [u8; 16]) -> Result<Vec<DeliveryRow>, StoreFault> {
        let mut client = self.pool.get().await?;
        let rows = client.query(ROWS_SQL, &[&Uuid::from_bytes(outbox)]).await?;
        client.release();
        rows.iter().map(row_of).collect()
    }

    /// The head of `outbox`.
    ///
    /// # Errors
    ///
    /// As [`DeliveryLog::rows`].
    pub async fn head(&self, outbox: [u8; 16]) -> Result<Option<DeliveryRow>, StoreFault> {
        let mut client = self.pool.get().await?;
        let row = client
            .query_opt(HEAD_SQL, &[&Uuid::from_bytes(outbox)])
            .await?;
        client.release();
        row.as_ref().map(row_of).transpose()
    }

    /// Up to `limit` outbox rows of `kind` without a terminal delivery
    /// row, oldest first.
    ///
    /// # Errors
    ///
    /// A pool or database fault.
    pub async fn pending(&self, kind: u16, limit: u16) -> Result<Vec<[u8; 16]>, StoreFault> {
        let kind = i16::try_from(kind).map_err(|_| StoreFault::Refused("an outbox kind"))?;
        let mut client = self.pool.get().await?;
        let rows = client
            .query(PENDING_SQL, &[&kind, &i64::from(limit)])
            .await?;
        client.release();
        rows.iter()
            .map(|r| {
                r.get::<Uuid>(0)
                    .map(|u| *u.as_bytes())
                    .map_err(StoreFault::from)
            })
            .collect()
    }

    /// S1 and recovery, under the message's lock: reads the head, and by
    /// [`next_step`] claims the next attempt for `worker` with a lease,
    /// records IN_DOUBT after an ended COMMITTING lease, or records
    /// PERMANENT after the last transient attempt. It returns the rule's
    /// answer. Only a [`Next::Claim`] lets the worker go on.
    ///
    /// # Errors
    ///
    /// A pool or database fault. A unique violation means another worker
    /// wrote first, and the caller reads the head again.
    pub async fn claim(
        &self,
        outbox: [u8; 16],
        worker: [u8; 16],
        now: i64,
    ) -> Result<Next, StoreFault> {
        self.locked(outbox, |head| {
            let next = next_step(head, now);
            let row = |attempt, phase, lease_until| DeliveryRow {
                outbox,
                attempt,
                phase,
                at: now,
                worker,
                lease_until,
                commit: None,
                reply_code: None,
            };
            let write = match next {
                Next::Claim { attempt } => Some(row(
                    attempt,
                    Phase::Claimed,
                    Some(now.saturating_add(DELIVERY_LEASE_US)),
                )),
                Next::RecordInDoubt { attempt } => Some(row(attempt, Phase::InDoubt, None)),
                Next::GiveUp { attempt } => Some(row(attempt, Phase::Permanent, None)),
                Next::Busy { .. } | Next::Wait { .. } | Next::Done => None,
            };
            (write, next)
        })
        .await
    }

    /// S4, the commit point, under the message's lock: inserts COMMITTING
    /// with `facts` and a new lease only while the head is `worker`'s own
    /// CLAIMED row of `attempt` ([`may_commit`]). `false` means the worker
    /// must QUIT without the end of DATA.
    ///
    /// # Errors
    ///
    /// A pool or database fault. The outcome of a COMMIT that fails may be
    /// unknown, and the worker must not send the end of DATA.
    pub async fn commit_point(
        &self,
        outbox: [u8; 16],
        worker: [u8; 16],
        attempt: u32,
        facts: CommitFacts,
        now: i64,
    ) -> Result<bool, StoreFault> {
        self.locked(outbox, |head| {
            let ok = may_commit(head, worker, attempt);
            let write = ok.then_some(DeliveryRow {
                outbox,
                attempt,
                phase: Phase::Committing,
                at: now,
                worker,
                lease_until: Some(now.saturating_add(DELIVERY_LEASE_US)),
                commit: Some(facts),
                reply_code: None,
            });
            (write, ok)
        })
        .await
    }

    /// S6, under the message's lock: records `phase` with `reply_code` for
    /// `attempt` when [`may_record`] allows it. `false` means another
    /// worker settled the message first, such as an IN_DOUBT by recovery.
    ///
    /// # Errors
    ///
    /// A pool or database fault.
    pub async fn record(
        &self,
        outbox: [u8; 16],
        worker: [u8; 16],
        attempt: u32,
        phase: Phase,
        reply_code: Option<u16>,
        now: i64,
    ) -> Result<bool, StoreFault> {
        self.locked(outbox, |head| {
            let ok = may_record(head, worker, attempt, phase);
            let write = ok.then_some(DeliveryRow {
                outbox,
                attempt,
                phase,
                at: now,
                worker,
                lease_until: None,
                commit: None,
                reply_code,
            });
            (write, ok)
        })
        .await
    }

    /// One transaction under the message's lock: reads the head, asks
    /// `decide`, inserts the row it names, and commits.
    async fn locked<T>(
        &self,
        outbox: [u8; 16],
        decide: impl FnOnce(Option<&DeliveryRow>) -> (Option<DeliveryRow>, T),
    ) -> Result<T, StoreFault> {
        let mut client = self.pool.get().await?;
        let mut tx = client.transaction().await?;
        tx.execute(LOCK_SQL, &[&lock_key(&outbox)]).await?;
        let head = tx
            .query_opt(HEAD_SQL, &[&Uuid::from_bytes(outbox)])
            .await?
            .as_ref()
            .map(row_of)
            .transpose()?;
        let (write, out) = decide(head.as_ref());
        if let Some(r) = write {
            if !r.is_well_formed() {
                return Err(StoreFault::Refused(
                    "an ops.delivery row outside its constraints",
                ));
            }
            let attempt =
                i32::try_from(r.attempt).map_err(|_| StoreFault::Refused("an attempt number"))?;
            tx.execute(
                INSERT_SQL,
                &[
                    &Uuid::from_bytes(r.outbox),
                    &attempt,
                    &r.phase.code(),
                    &r.at,
                    &Uuid::from_bytes(r.worker),
                    &r.lease_until,
                    &r.commit.map(|c| c.event.to_vec()),
                    &r.commit.map(|c| i32::from(c.template_version)),
                    &r.commit.map(|c| c.body_digest.to_vec()),
                    &r.reply_code.map(|c| i16::try_from(c).unwrap_or(i16::MAX)),
                ],
            )
            .await?;
        }
        tx.commit().await?;
        client.release();
        Ok(out)
    }
}

const OUTBOX_SQL: &str = "SELECT kind, idem, dek, body FROM ops.outbox WHERE id = $1";

/// The stored messages of `ops.outbox`, opened for the dispatcher (M6
/// design section 5.1, S2). Lane L6-DISP.
pub struct OutboxReader<R: Runtime> {
    pool: Pool<R>,
    keys: Arc<dyn OutboxKeys>,
}

impl<R: Runtime> OutboxReader<R> {
    /// The reader over `pool`, which must serve the app role, opening
    /// bodies with `keys`.
    ///
    /// # Errors
    ///
    /// [`StoreFault::WrongRole`] for a pool of another role.
    pub fn new(pool: Pool<R>, keys: Arc<dyn OutboxKeys>) -> Result<OutboxReader<R>, StoreFault> {
        if pool.role() != Role::App {
            return Err(StoreFault::WrongRole);
        }
        Ok(OutboxReader { pool, keys })
    }

    /// The opened body of the outbox row `id` of `kind`, or `None` when no
    /// such row exists or the keystore refuses its key.
    ///
    /// # Errors
    ///
    /// A pool or database fault, the key provider's refusal, or a body
    /// that does not open under its row.
    pub async fn open(&self, id: [u8; 16], kind: u16) -> Result<Option<Vec<u8>>, StoreFault> {
        let mut client = self.pool.get().await?;
        let row = client
            .query_opt(OUTBOX_SQL, &[&Uuid::from_bytes(id)])
            .await?;
        client.release();
        let Some(row) = row else {
            return Ok(None);
        };
        let stored_kind: i16 = row.get(0)?;
        let idem: Vec<u8> = row.get(1)?;
        let dek: Uuid = row.get(2)?;
        let body: Vec<u8> = row.get(3)?;
        if u16::try_from(stored_kind).ok() != Some(kind) {
            return Ok(None);
        }
        let Some(key) = self.keys.open(DekId(*dek.as_bytes()), ObjectId(id)).await? else {
            return Ok(None);
        };
        if key.dek.0 != *dek.as_bytes() {
            return Err(StoreFault::OpenFailed);
        }
        let plain = open_outbox_body(&self.pool.cell(), &key, &id, kind, &idem, &body)?;
        Ok(Some(plain.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        reason = "test code computes known-small times"
    )]

    use super::*;

    fn row(attempt: u32, phase: Phase, at: i64, worker: u8) -> DeliveryRow {
        DeliveryRow {
            outbox: [1; 16],
            attempt,
            phase,
            at,
            worker: [worker; 16],
            lease_until: matches!(phase, Phase::Claimed | Phase::Committing)
                .then_some(at + DELIVERY_LEASE_US),
            commit: None,
            reply_code: None,
        }
    }

    /// M6 design section 3.2: the phase codes of `ops.delivery`.
    #[test]
    fn i26_phase_codes_follow_the_design() {
        let codes: Vec<i16> = Phase::ALL.iter().map(|p| p.code()).collect();
        assert_eq!(codes, vec![1, 2, 3, 4, 5, 6]);
        for p in Phase::ALL {
            assert_eq!(Phase::from_code(p.code()), Some(p));
        }
        assert_eq!(Phase::from_code(0), None);
        assert_eq!(Phase::from_code(7), None);
        let terminal: Vec<Phase> = Phase::ALL.into_iter().filter(|p| p.is_terminal()).collect();
        assert_eq!(
            terminal,
            vec![Phase::Sent, Phase::Permanent, Phase::InDoubt]
        );
    }

    /// I-26, M6 design section 5.1 recovery: a live lease is busy, an
    /// ended CLAIMED lease is claimed again, an ended COMMITTING lease is
    /// IN_DOUBT and never claimed again, and a terminal head is done.
    #[test]
    fn i26_recovery_never_reclaims_after_the_commit_point() {
        let t = 1_000_000_000;
        assert_eq!(next_step(None, t), Next::Claim { attempt: 1 });
        let c = row(1, Phase::Claimed, t, 1);
        assert_eq!(
            next_step(Some(&c), t + 1),
            Next::Busy {
                until: t + DELIVERY_LEASE_US
            }
        );
        assert_eq!(
            next_step(Some(&c), t + DELIVERY_LEASE_US),
            Next::Claim { attempt: 2 }
        );
        let k = row(3, Phase::Committing, t, 1);
        assert!(matches!(next_step(Some(&k), t), Next::Busy { .. }));
        assert_eq!(
            next_step(Some(&k), t + DELIVERY_LEASE_US),
            Next::RecordInDoubt { attempt: 3 }
        );
        for p in [Phase::Sent, Phase::Permanent, Phase::InDoubt] {
            assert_eq!(next_step(Some(&row(2, p, t, 1)), i64::MAX), Next::Done);
        }
    }

    /// M6 design section 5.1: a transient failure backs off 1, 5 and 30
    /// minutes, then hourly, and the eighth gives up.
    #[test]
    fn i26_transient_backoff_and_give_up() {
        let t = 1_000_000_000;
        for (attempt, minutes) in [(1, 1), (2, 5), (3, 30), (4, 60), (7, 60)] {
            let h = row(attempt, Phase::Transient, t, 1);
            let until = t + minutes * MINUTE_US;
            assert_eq!(next_step(Some(&h), until - 1), Next::Wait { until });
            assert_eq!(
                next_step(Some(&h), until),
                Next::Claim {
                    attempt: attempt + 1
                }
            );
        }
        let last = row(MAX_ATTEMPTS, Phase::Transient, t, 1);
        assert_eq!(
            next_step(Some(&last), i64::MAX),
            Next::GiveUp {
                attempt: MAX_ATTEMPTS
            }
        );
    }

    /// I-26, M6 design section 5.1: the attempt number fences the commit
    /// point. Only the worker whose CLAIMED row heads the message passes
    /// S4, and SENT follows only its own COMMITTING row.
    #[test]
    fn i26_attempt_number_fences_the_commit_point() {
        let t = 5;
        let h = row(2, Phase::Claimed, t, 7);
        assert!(may_commit(Some(&h), [7; 16], 2));
        assert!(!may_commit(Some(&h), [8; 16], 2), "another worker");
        assert!(!may_commit(Some(&h), [7; 16], 1), "a stale attempt");
        assert!(!may_commit(None, [7; 16], 1));
        let k = row(2, Phase::Committing, t, 7);
        assert!(!may_commit(Some(&k), [7; 16], 2), "a second commit point");
        assert!(may_record(Some(&k), [7; 16], 2, Phase::Sent));
        assert!(
            !may_record(Some(&h), [7; 16], 2, Phase::Sent),
            "SENT without S4"
        );
        assert!(may_record(Some(&h), [7; 16], 2, Phase::Transient));
        assert!(!may_record(Some(&k), [8; 16], 2, Phase::Sent));
        let d = row(2, Phase::InDoubt, t, 9);
        for p in Phase::ALL {
            assert!(!may_record(Some(&d), [7; 16], 2, p), "after IN_DOUBT");
        }
    }
}
