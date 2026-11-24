//! The guard of the off-host key copies (ADR-004 record of lane
//! `m10/guard-key`, F-018, TH-30, TH-59, I-81).
//!
//! Decided by Daniel on 2026-11-23 (Q-L16-1, option A): the second
//! custodian is required. It holds one hybrid KEM key pair per pilot
//! `fstp-keyd` entry, the guard, and serves the pilot over mutual TLS.
//!
//! - `fstp-keyd export` seals each copy once more to the guard's public
//!   half ([`copy`]).
//! - Every destroy the pilot entry serves replaces that entry's guard
//!   before its receipt goes out ([`state`], [`crate::server`]). A copy
//!   made before the destroy then opens nowhere, so an old copy, its
//!   passphrase and a database backup of the same age open no data erased
//!   later.
//! - An import asks the custodian to open the outer seal.
//!
//! The custodian keeps each guard in a slot of its own key table and a
//! sealed file ([`store`]). The link is one exchange per connection over
//! TLS 1.3 ([`wire`], [`link`]). Every decoder here is fuzzed
//! (`guard_link_decode`).

use zeroize::Zeroizing;

use fstp_crypto::hybrid_kem::HybridPublicKey;
use fstp_custody::Refusal;

pub mod copy;
pub mod link;
pub mod state;
pub mod store;
pub mod wire;

/// The class byte of a guard slot in the key table. No Unix socket role
/// knows it, so no socket reaches a guard (R-NF-08).
pub const GUARD_CLASS: u8 = 0x10;

/// The port the custodian listens on unless configured otherwise.
pub const DEFAULT_PORT: u16 = 7460;

/// The subject CN of the custodian's server certificate.
pub const CUSTODIAN_CN: &str = "keyd-custodian";

/// The prefix of the subject CN of a pilot entry's client certificate.
pub const CLIENT_CN_PREFIX: &str = "keyd-guard-";

/// One `fstp-keyd` entry of the pilot, which has a guard sequence of its
/// own at the custodian (ADR-028 "Custody entries").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GuardEntry {
    /// `cell`: App and CellBackup.
    Cell,
    /// `cell-keys`: the root of the cell key file.
    CellKeys,
    /// `vault`: Vault and VaultBackup.
    Vault,
    /// `witness`: the witness receipt key.
    Witness,
    /// `control`: the route feed key.
    Control,
}

impl GuardEntry {
    /// Every entry, in code order.
    pub const ALL: [GuardEntry; 5] = [
        GuardEntry::Cell,
        GuardEntry::CellKeys,
        GuardEntry::Vault,
        GuardEntry::Witness,
        GuardEntry::Control,
    ];

    /// The one-byte code of the entry.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            GuardEntry::Cell => 1,
            GuardEntry::CellKeys => 2,
            GuardEntry::Vault => 3,
            GuardEntry::Witness => 4,
            GuardEntry::Control => 5,
        }
    }

    /// The entry of `code`, if known.
    #[must_use]
    pub fn from_code(code: u8) -> Option<GuardEntry> {
        GuardEntry::ALL.into_iter().find(|e| e.code() == code)
    }

    /// The entry's name, as `fstp-admin` names it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            GuardEntry::Cell => "cell",
            GuardEntry::CellKeys => "cell-keys",
            GuardEntry::Vault => "vault",
            GuardEntry::Witness => "witness",
            GuardEntry::Control => "control",
        }
    }

    /// The entry of `name`, if known.
    #[must_use]
    pub fn from_name(name: &str) -> Option<GuardEntry> {
        GuardEntry::ALL.into_iter().find(|e| e.name() == name)
    }

    /// The subject CN of this entry's client certificate.
    #[must_use]
    pub fn client_cn(self) -> String {
        format!("{CLIENT_CN_PREFIX}{}", self.name())
    }

    /// The entry a client certificate's one CN names, if any.
    #[must_use]
    pub fn of_client_cn(cn: &str) -> Option<GuardEntry> {
        cn.strip_prefix(CLIENT_CN_PREFIX)
            .and_then(GuardEntry::from_name)
    }
}

/// Why a guard request did not succeed. No variant carries input bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardFault {
    /// The custodian did not answer: no connection, a failed handshake, a
    /// timeout or a reply that does not decode.
    Unreachable,
    /// The custodian answered with a refusal.
    Refused(Refusal),
}

impl std::fmt::Display for GuardFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardFault::Unreachable => f.write_str("the second custodian did not answer"),
            GuardFault::Refused(r) => write!(
                f,
                "the second custodian: {}",
                fstp_custody::CustodyError::Refused(*r)
            ),
        }
    }
}

impl std::error::Error for GuardFault {}

/// The answer to a rotation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rotated {
    /// The newest generation destroyed, or 0 when none was live.
    pub destroyed: u32,
    /// The generation now current.
    pub generation: u32,
    /// Its public half.
    pub public: [u8; fstp_crypto::hybrid_kem::PUBLIC_KEY_LEN],
    /// The `"FKS1"` receipt of the destroyed generation, or empty.
    pub receipt: Vec<u8>,
}

/// What a pilot entry asks of its custodian. [`link::TlsGuard`] asks over
/// the network, [`store::LocalCustodian`] in process.
pub trait GuardClient: Send + Sync {
    /// The current generation of `entry`'s guard and its public half. The
    /// custodian creates generation 1 at the first ask.
    ///
    /// # Errors
    ///
    /// [`GuardFault`] when the custodian does not answer or refuses.
    fn public(&self, entry: GuardEntry) -> Result<(u32, HybridPublicKey), GuardFault>;

    /// Replaces `entry`'s guard for the owed `event`: the next generation
    /// is made and every older one destroyed. A retry of the same event
    /// answers the same result.
    ///
    /// # Errors
    ///
    /// [`GuardFault`] when the custodian does not answer or refuses.
    fn rotate(&self, entry: GuardEntry, event: [u8; 16]) -> Result<Rotated, GuardFault>;

    /// The key of the outer seal of a copy under `generation`.
    ///
    /// # Errors
    ///
    /// [`GuardFault::Refused`] with [`Refusal::Destroyed`] for a destroyed
    /// generation, and [`GuardFault::Unreachable`].
    fn open(
        &self,
        entry: GuardEntry,
        generation: u32,
        header: &[u8; copy::HEADER_LEN],
        ciphertext: &[u8; fstp_crypto::hybrid_kem::CIPHERTEXT_LEN],
    ) -> Result<Zeroizing<[u8; 32]>, GuardFault>;

    /// Stores `copy`, a guarded copy of `entry`, as the custodian's held
    /// copy (ADR-004 "The custodian's copy"), and answers its generation.
    ///
    /// # Errors
    ///
    /// [`GuardFault::Refused`] with [`Refusal::Destroyed`] for a copy sealed
    /// to a destroyed generation, [`Refusal::BadRequest`] for one of another
    /// entry or generation, and [`GuardFault::Unreachable`].
    fn put(&self, entry: GuardEntry, copy: &[u8]) -> Result<u32, GuardFault>;

    /// The custodian's held copy of `entry`.
    ///
    /// # Errors
    ///
    /// [`GuardFault::Refused`] with [`Refusal::UnknownRoot`] when none is
    /// held, and [`GuardFault::Unreachable`].
    fn fetch(&self, entry: GuardEntry) -> Result<Vec<u8>, GuardFault>;
}

/// The guard of one pilot entry: the entry and how to reach its
/// custodian.
pub struct GuardLink {
    /// The pilot entry.
    pub entry: GuardEntry,
    /// The custodian.
    pub client: Box<dyn GuardClient>,
}

impl std::fmt::Debug for GuardLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardLink")
            .field("entry", &self.entry)
            .finish_non_exhaustive()
    }
}

/// A request id or event id from the system generator.
pub(crate) fn fresh_id() -> Result<[u8; 16], GuardFault> {
    fstp_crypto::random_array().map_err(|_| GuardFault::Unreachable)
}
