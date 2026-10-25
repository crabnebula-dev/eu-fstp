//! Finding commands and finding records (design section 2.13).
//!
//! A finding command yields only finding records, and a finding record
//! folds only into the [`FindingStore`](crate::FindingStore). Neither can
//! name a core record (I-10).

use fstp_domain::id::{AccountId, CallId, LlmConfigId};
use fstp_domain::policy::ModelRef;

use crate::finding::{Finding, FindingId, Mark};

/// A command on findings, decided by `decide_finding` in `fstp-engine`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum FindingCommand {
    /// Store one finding under its call's pinned configuration (I-11).
    Record(Finding),
    /// The acting reviewer marks a finding.
    Mark {
        /// The finding.
        finding: FindingId,
        /// The mark.
        mark: Mark,
    },
    /// Replace every finding of `call` with `findings` under `config`, in
    /// one step (P-21 NOTE 10).
    ///
    /// The replacement takes the next model on the frozen P-21 list. The
    /// decider reads its position from
    /// [`FindingStore::next_fallback`](crate::FindingStore::next_fallback)
    /// and checks that `config_model` is the frozen fallback at that
    /// position, as `PublishCall` checks the primary.
    Regenerate {
        /// The call whose findings are replaced.
        call: CallId,
        /// The replacement configuration.
        config: LlmConfigId,
        /// The model that `config` pins.
        config_model: ModelRef,
        /// The whole new set of the call's findings.
        findings: Vec<Finding>,
    },
}

/// A ledger record on findings, folded by
/// [`FindingStore::apply`](crate::FindingStore::apply).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum FindingRecord {
    /// One finding was stored.
    Recorded(Finding),
    /// A reviewer marked a finding.
    Marked {
        /// The finding.
        finding: FindingId,
        /// The reviewer's account.
        by: AccountId,
        /// The mark.
        mark: Mark,
    },
    /// Every finding of `call` was replaced with `findings` under `config`
    /// (P-21 NOTE 10). The earlier findings and their marks are retired.
    Regenerated {
        /// The call.
        call: CallId,
        /// The position of `config_model` in the frozen P-21 fallback
        /// list, counted from 0. The fold refuses any position but the
        /// call's next one.
        fallback: u32,
        /// The model that `config` pins, the frozen fallback at `fallback`.
        config_model: ModelRef,
        /// The replacement configuration.
        config: LlmConfigId,
        /// The whole new set of the call's findings.
        findings: Vec<Finding>,
    },
}
