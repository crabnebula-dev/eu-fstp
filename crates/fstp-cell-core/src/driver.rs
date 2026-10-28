//! `DriverCore`, the sans-IO state machine that runs one admitted command
//! (design section 5.2, NOTE 2 to NOTE 5, I-23).
//!
//! It follows `fstp_engine::Engine::execute` step for step and adds the
//! acknowledgement of NOTE 4. The M2 `Engine` stays its reference oracle.
//!
//! Status: W0 stub. Lane W2c fills it. [`DriverCore::step`] finishes with
//! [`ExecError::NotImplemented`].

use fstp_domain::id::VaultEpoch;
use fstp_domain::oracle::{Answers, Query};
use fstp_ledger::{AppendError, Entry, Seq};

use crate::gate::Admitted;
use crate::{CellRecord, CellState};

/// A chain link, SHA-256.
pub type Link = [u8; 32];

/// The insert-only side effects of an append (design section 5.3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SideEffects {
    /// A consumed step-up id.
    pub stepup_consumed: Option<[u8; 16]>,
    /// Ended sessions.
    pub sessions_ended: Vec<[u8; 16]>,
}

/// What the driver needs from the shell.
#[derive(Clone, Debug)]
pub enum Need {
    /// Ledger entries after a sequence.
    ReadFrom(Seq),
    /// The vault epoch.
    Epoch,
    /// Answers to queries.
    Ask {
        /// The queries.
        queries: Vec<Query>,
        /// The epoch of a reaction, if this asks for one.
        reaction_for: Option<VaultEpoch>,
    },
    /// An append.
    Append {
        /// The expected head.
        expected: Seq,
        /// UTC microseconds.
        at: i64,
        /// The command id.
        command: [u8; 16],
        /// The records.
        batch: Vec<CellRecord>,
        /// The side effects.
        side: SideEffects,
    },
    /// An acknowledgement to the vault.
    Ack {
        /// The epoch.
        epoch: VaultEpoch,
        /// The ledger sequence of the reaction.
        seq: Seq,
        /// Its chain link.
        link: Link,
    },
}

/// Why the vault did not answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultFault {
    /// The vault is unavailable.
    Unavailable,
    /// The vault refused.
    Refused,
}

/// What the shell reports back.
#[derive(Clone, Debug)]
pub enum Event {
    /// Ledger entries.
    Read(Vec<Entry<CellRecord>>),
    /// The vault epoch.
    Epoch(Result<VaultEpoch, VaultFault>),
    /// Answers.
    Answers(Result<Answers, VaultFault>),
    /// The append result.
    Appended(Result<(Seq, Link), AppendError>),
    /// The acknowledgement result.
    Acked(Result<(), VaultFault>),
}

/// A reference to the witness receipt of a committed append.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptRef {
    /// The witness sequence.
    pub witness_seq: u64,
}

/// A finished command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Done {
    /// The ledger head after the command.
    pub head: Seq,
    /// The witness receipt of the append.
    pub receipt: ReceiptRef,
}

/// Why a command did not finish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecError {
    /// The command id carries the reserved prefix `fstp:vc:`.
    ReservedCommandId,
    /// The vault failed, so the command fails closed (NOTE 2).
    VaultFault,
    /// The command was refused.
    Refused(crate::CellRefusal),
    /// The driver is a W0 stub. It names the operation.
    NotImplemented(&'static str),
}

/// One step of the driver.
#[derive(Clone, Debug)]
pub enum Step {
    /// The driver needs something from the shell.
    Need(Need),
    /// The command finished.
    Done(Result<Done, ExecError>),
}

/// The sans-IO driver of one admitted command.
#[derive(Clone, Debug)]
pub struct DriverCore {
    admitted: Admitted,
    attempts: u32,
}

impl DriverCore {
    /// Starts the driver for an admitted command.
    pub fn start(admitted: Admitted) -> DriverCore {
        DriverCore {
            admitted,
            attempts: 0,
        }
    }

    /// The admitted command.
    pub fn admitted(&self) -> &Admitted {
        &self.admitted
    }

    /// Advances the driver with the shell's last event.
    pub fn step(&mut self, state: &mut CellState, ev: Option<Event>) -> Step {
        let _ = (state, ev, self.attempts);
        Step::Done(Err(ExecError::NotImplemented(
            "fstp_cell_core::driver::DriverCore::step",
        )))
    }
}
