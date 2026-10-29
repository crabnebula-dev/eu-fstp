//! The witness client and the anchoring store of a cell (design sections
//! 1.3, 5.3 steps 7 and 8, and 7.2; I-24, R-NF-09, risk R8).
//!
//! - [`WitnessClient`] carries the anchorer's messages to the witness
//!   over a [`WitnessLink`]. It authenticates the peer before every
//!   message: the link reports the digest of the CA that issued the
//!   certificate of the peer on its current connection, and a peer from
//!   any CA other than the pinned witness CA receives nothing (R-NF-09).
//!   A reconnect therefore never skips the check. It checks every receipt
//!   against the prepare it answers.
//! - [`store::AnchoredStore`] runs the append protocol of design section
//!   5.3 over a [`store::Database`], with the `fstp_audit` anchorer core:
//!   prepare, receipt, commit, abort and in-doubt resolution.
//!
//! # Seams
//!
//! - The witness wire format and the witness service are lane W2g's.
//!   `fstp_witness::run` is not written and no reply format is fixed, so
//!   no TLS link is built here. A transport implements [`WitnessLink`].
//!
//! # Receipts
//!
//! [`store::AnchoredStore`] takes each receipt through
//! `Anchorer::signed_receipt` with the pinned witness keys of
//! [`store::StoreKeys::witness`], never through `Anchorer::receipt` alone
//! (ADR-010 "Keys", I-24, I-90). A receipt for another cell or chain, one
//! that no pinned key verifies, or one for another head is never
//! committed on, and its prepare is aborted. The start-up verification
//! (`fstp_audit::verify`) checks every stored receipt under the same pins.

pub mod store;

use std::future::Future;

use fstp_audit::anchor::Receipt;
use fstp_audit::anchorer::{PrepareWitness, WitnessFault};
use fstp_audit::witness::{Prepare, WitnessRecord};
use fstp_audit::{CellId, ChainId, Link};

/// A message to the witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WitnessMessage {
    /// A prepare of the prospective head.
    Prepare(Prepare),
    /// `Abort { n, link }` of the outstanding prepare.
    Abort {
        /// The row.
        n: u64,
        /// The prepared link.
        link: Link,
    },
    /// `InDoubtAbsent { n, link }` of the outstanding prepare.
    InDoubtAbsent {
        /// The row.
        n: u64,
        /// The prepared link.
        link: Link,
    },
}

/// The witness's answer to a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WitnessReply {
    /// The receipt of a prepare.
    Receipt(Receipt),
    /// An abort or in-doubt record was recorded.
    Recorded,
    /// The witness refused the message, which changed nothing.
    Refused,
    /// The witness holds no outstanding prepare of that head.
    UnknownPrepare,
}

/// The byte link to the witness (design section 1.3). A transport opens
/// it over mutual TLS with the cell's `cell-witness` certificate and the
/// witness CA as its only root.
pub trait WitnessLink: Send + Sync + 'static {
    /// Opens the link if needed and gives the SHA-256 digest of the
    /// SubjectPublicKeyInfo of the CA that issued the peer's certificate
    /// on the current connection. The client calls it before every
    /// message, so a link caches the digest per connection.
    fn peer_issuer(&self) -> impl Future<Output = Result<[u8; 32], WitnessFault>> + Send;

    /// Sends one message over the connection that [`Self::peer_issuer`]
    /// last reported on, and waits for its answer. It never opens a new
    /// connection: a lost connection fails with
    /// [`WitnessFault::Unreachable`], and the next `peer_issuer` call
    /// opens and checks the next one.
    fn send(
        &self,
        message: WitnessMessage,
    ) -> impl Future<Output = Result<WitnessReply, WitnessFault>> + Send;

    /// The outstanding prepare of `cell`'s `chain`, if any (ADR-010
    /// "Start-up").
    fn outstanding(
        &self,
        cell: CellId,
        chain: ChainId,
    ) -> impl Future<Output = Result<Option<(u64, Link)>, WitnessFault>> + Send;

    /// The witness log of `cell`'s `chain`, in witness order, for the
    /// start-up verification.
    fn log(
        &self,
        cell: CellId,
        chain: ChainId,
    ) -> impl Future<Output = Result<Vec<WitnessRecord>, WitnessFault>> + Send;
}

/// The witness client of one chain of one cell.
#[derive(Debug)]
pub struct WitnessClient<L> {
    link: L,
    cell: CellId,
    chain: ChainId,
    pinned_ca: [u8; 32],
}

impl<L: WitnessLink> WitnessClient<L> {
    /// A client for `cell`'s `chain` that accepts only a witness whose
    /// certificate the CA with SPKI digest `pinned_ca` issued.
    pub fn new(link: L, cell: CellId, chain: ChainId, pinned_ca: [u8; 32]) -> WitnessClient<L> {
        WitnessClient {
            link,
            cell,
            chain,
            pinned_ca,
        }
    }

    /// The link.
    pub fn link(&self) -> &L {
        &self.link
    }

    /// The cell.
    pub fn cell(&self) -> CellId {
        self.cell
    }

    /// The chain.
    pub fn chain(&self) -> ChainId {
        self.chain
    }

    /// Checks the peer of the current connection before each message
    /// (R-NF-09). A foreign peer is treated as unreachable: nothing is
    /// sent to it.
    async fn authenticate(&self) -> Result<(), WitnessFault> {
        let issuer = self.link.peer_issuer().await?;
        if issuer != self.pinned_ca {
            return Err(WitnessFault::Unreachable);
        }
        Ok(())
    }

    /// The outstanding prepare at the witness, after authentication.
    ///
    /// # Errors
    ///
    /// The link's fault.
    pub async fn outstanding(&self) -> Result<Option<(u64, Link)>, WitnessFault> {
        self.authenticate().await?;
        self.link.outstanding(self.cell, self.chain).await
    }

    /// The witness log, after authentication.
    ///
    /// # Errors
    ///
    /// The link's fault.
    pub async fn log(&self) -> Result<Vec<WitnessRecord>, WitnessFault> {
        self.authenticate().await?;
        self.link.log(self.cell, self.chain).await
    }

    async fn withdraw(&self, message: WitnessMessage) -> Result<(), WitnessFault> {
        self.authenticate().await?;
        match self.link.send(message).await? {
            WitnessReply::Recorded => Ok(()),
            WitnessReply::UnknownPrepare => Err(WitnessFault::UnknownPrepare),
            WitnessReply::Refused | WitnessReply::Receipt(_) => Err(WitnessFault::Refused),
        }
    }
}

impl<L: WitnessLink> PrepareWitness for WitnessClient<L> {
    fn prepare(&self, p: &Prepare) -> impl Future<Output = Result<Receipt, WitnessFault>> + Send {
        let p = p.clone();
        async move {
            self.authenticate().await?;
            match self.link.send(WitnessMessage::Prepare(p.clone())).await? {
                WitnessReply::Receipt(r) => {
                    if r.cell != self.cell || r.chain != self.chain {
                        // A receipt for another cell or chain receipts
                        // nothing here. The witness answered, so it may
                        // hold this prepare outstanding: the fault leads
                        // to `Anchorer::failed`, which sends Abort before
                        // the same n is prepared again.
                        return Err(WitnessFault::Unreachable);
                    }
                    Ok(r)
                }
                // Only a refusal changes nothing at the witness.
                WitnessReply::Refused => Err(WitnessFault::Refused),
                // An answer that fits no prepare leaves the witness's
                // state unknown, so it is treated as a lost answer and
                // aborted.
                WitnessReply::Recorded | WitnessReply::UnknownPrepare => {
                    Err(WitnessFault::Unreachable)
                }
            }
        }
    }

    fn abort(&self, head: (u64, Link)) -> impl Future<Output = Result<(), WitnessFault>> + Send {
        self.withdraw(WitnessMessage::Abort {
            n: head.0,
            link: head.1,
        })
    }

    fn in_doubt_absent(
        &self,
        head: (u64, Link),
    ) -> impl Future<Output = Result<(), WitnessFault>> + Send {
        self.withdraw(WitnessMessage::InDoubtAbsent {
            n: head.0,
            link: head.1,
        })
    }
}
