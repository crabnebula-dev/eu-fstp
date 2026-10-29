//! The input format and the run of the fuzz target `driver_core_sequence`
//! (M3 design section 15). The target and the crate's tests share this
//! file, so a seed is checked under the format the target reads.
//!
//! One admitted command runs through `DriverCore`: the erasure runner's
//! `RecordEpochDestroyed`, admitted by `gate::admit_system` under a system
//! task command id. That admission needs no session, so the run needs no
//! `fstp-auth` (lane W2b).
//!
//! Each input byte picks the next event, of any kind, including events
//! that fit no need. Its low three bits pick the kind and its high nibble
//! the argument. Bit 3 picks the fault, or for answers the fault or the
//! answers. Answers to a `Need::Ask` take one more byte per query: bits 0
//! and 1 give the answer epoch, bit 2 the answer bit, and the high nibble
//! the changed account of a `ChangedSince` answer (zero for none). So the
//! input reaches the reaction's decision, its append and its
//! acknowledgement (NOTE 4).

use std::collections::BTreeSet;

use fstp_cell_core::driver::{Done, DriverCore, Event, ExecError, Need, Step, VaultFault};
use fstp_cell_core::gate::{self, Action};
use fstp_cell_core::text::TextRecord;
use fstp_cell_core::{CellCommand, CellRecord, KeyCommand, SystemTask, replay, system_command_id};
use fstp_domain::id::{AccountId, ContentDigest, VaultEpoch};
use fstp_domain::oracle::{Answer, Answers, Query};
use fstp_domain::time::Timestamp;
use fstp_ledger::{AppendError, MemStore, RecordStore, Seq, StoreError};

/// The most driver steps one input runs.
pub(crate) const MAX_STEPS: usize = 128;

const NOW: Timestamp = Timestamp::from_micros(3_600_000_000);

/// What one run did.
#[derive(Debug, Default)]
pub(crate) struct Outcome {
    /// The number of reaction acknowledgements the driver asked for with
    /// a nonzero link: one per reaction it appended.
    pub(crate) reaction_acks: usize,
    /// How the command ended, if it did within the input.
    pub(crate) done: Option<Result<Done, ExecError>>,
}

/// The answers to `queries`, one input byte per query. A missing byte
/// counts as zero.
fn answers_for(queries: &[Query], bytes: &mut impl Iterator<Item = u8>) -> Answers {
    let mut out = Answers::new();
    for q in queries {
        let b = bytes.next().unwrap_or(0);
        let accounts = matches!(q, Query::ChangedSince { .. }).then(|| {
            let n = b >> 4;
            let mut set = BTreeSet::new();
            if n != 0 {
                set.insert(AccountId::from_raw(u128::from(n)));
            }
            set
        });
        out.insert(
            q.clone(),
            Answer {
                holds: b & 0x04 != 0,
                accounts,
                epoch: VaultEpoch::from_raw(u64::from(b & 0x03)),
                digest: ContentDigest::from_bytes([0; 32]),
            },
        );
    }
    out
}

/// Runs the events of `data`. It checks that no need and no event panics,
/// and that every need and result formats.
pub(crate) fn run(data: &[u8]) -> Outcome {
    let mut outcome = Outcome::default();
    let state = match replay(&[]) {
        Ok(s) => s,
        Err(e) => {
            assert!(!format!("{e:?}").is_empty());
            return outcome;
        }
    };
    let action = Action::Command(CellCommand::Key(KeyCommand::RecordEpochDestroyed {
        epoch: 1,
        receipt: [0xD5; 32],
    }));
    let id = system_command_id([0x7E; 8]);
    let admitted = match gate::admit_system(&state, action, SystemTask::ErasureRunner, id, NOW) {
        Ok(a) => a,
        Err(e) => {
            assert!(!format!("{e:?}").is_empty());
            return outcome;
        }
    };
    let mut store = MemStore::new();
    for i in 0..4u8 {
        let r = CellRecord::Text(TextRecord::TextPut { id: [i; 16] });
        if store
            .append(store.head(), NOW.micros(), [i; 16], vec![r])
            .is_err()
        {
            return outcome;
        }
    }
    let mut entries = Vec::new();
    if store.read(Seq::ZERO, usize::MAX, &mut entries).is_err() {
        return outcome;
    }
    let mut state = state;
    let mut driver = DriverCore::start(admitted);
    let mut bytes = data.iter().copied();
    let mut ev = None;
    for _ in 0..MAX_STEPS {
        let need = match driver.step(&mut state, ev.take()) {
            Step::Done(r) => {
                assert!(!format!("{r:?}").is_empty());
                outcome.done = Some(r);
                return outcome;
            }
            Step::Need(n) => {
                assert!(!format!("{n:?}").is_empty());
                n
            }
        };
        if matches!(need, Need::Ack { link, .. } if link != [0; 32]) {
            outcome.reaction_acks = outcome.reaction_acks.saturating_add(1);
        }
        let Some(b) = bytes.next() else {
            return outcome;
        };
        let fault = if b & 0x08 == 0 {
            VaultFault::Unavailable
        } else {
            VaultFault::Refused
        };
        let arg = u64::from(b >> 4);
        let small = usize::from(b >> 4);
        ev = Some(match b & 0x07 {
            0 => Event::Read(entries.iter().take(small % 5).cloned().collect()),
            1 => Event::Epoch(Ok(VaultEpoch::from_raw(arg % 4))),
            2 => Event::Epoch(Err(fault)),
            3 => Event::Answers(if b & 0x08 == 0 {
                match &need {
                    Need::Ask { queries, .. } => Ok(answers_for(queries, &mut bytes)),
                    _ => Ok(Answers::new()),
                }
            } else {
                Err(fault)
            }),
            4 => Event::Appended(Ok((Seq::from_raw(arg % 6), [b | 0x80; 32]))),
            5 => Event::Appended(Err(match arg % 3 {
                0 => AppendError::StaleHead {
                    head: Seq::from_raw(arg % 6),
                },
                1 => AppendError::DuplicateCommand {
                    at: Seq::from_raw(arg % 6),
                },
                _ => AppendError::Store(StoreError::Unavailable),
            })),
            6 => Event::Acked(Ok(())),
            _ => Event::Acked(Err(fault)),
        });
    }
    outcome
}
