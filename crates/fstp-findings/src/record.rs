//! Finding commands and finding records (design section 2.13).
//!
//! A finding command yields only finding records, and a finding record
//! folds only into the [`FindingStore`](crate::FindingStore). Neither can
//! name a core record (I-10).

use fstp_domain::id::{AccountId, CallId, LlmConfigId, ProposalId};
use fstp_domain::policy::ModelRef;

use fstp_domain::id::ContentDigest;

use crate::finding::{ClientRun, Finding, FindingId, Mark, RefusedStage, RerunEnd};

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
    /// The FSTP coordinator of the call asks for the assessment of
    /// `proposal` to run again (issue 6 M3, I-10). The decider refuses it
    /// while a re-run is in flight and after `MAX_RERUNS` re-runs.
    RequestRerun {
        /// The call the proposal belongs to.
        call: CallId,
        /// The proposal.
        proposal: ProposalId,
    },
    /// The assessment of `proposal` ended, and these are the stages the
    /// validator dropped. The list replaces the earlier one and ends a
    /// re-run in flight. By the assessor's system path only.
    RecordRefusals {
        /// The call.
        call: CallId,
        /// The proposal.
        proposal: ProposalId,
        /// The dropped stages, possibly none.
        refused: Vec<RefusedStage>,
    },
    /// The re-run of `proposal` in flight is abandoned (issue 6 M3): its
    /// run died with the cell process, or it has been in flight for
    /// `RERUN_TIMEOUT_US`. By the cell as the system only. It frees the
    /// in-flight slot, and the re-run still counts toward `MAX_RERUNS`.
    AbandonRerun {
        /// The call.
        call: CallId,
        /// The proposal.
        proposal: ProposalId,
        /// Why.
        reason: RerunEnd,
    },
    /// The FSTP coordinator of the call reads the assessable input of
    /// `proposal` for its connected agent (ADR-033, R-AU-01). `input` is
    /// the digest of what the cell serves. The decider asks the vault
    /// for a conflict, as for every read of content (I-03).
    ReadAssessmentInput {
        /// The call.
        call: CallId,
        /// The proposal.
        proposal: ProposalId,
        /// The digest of the served input.
        input: ContentDigest,
    },
    /// The FSTP coordinator of the call records the assessment its
    /// connected agent made of `proposal` (ADR-033). The findings carry
    /// the call's pin and the run's trace. The refused replies are
    /// stages and codes only (I-10).
    RecordClientAssessment {
        /// The call.
        call: CallId,
        /// The proposal.
        proposal: ProposalId,
        /// The provenance of the run.
        run: ClientRun,
        /// The validated findings with located evidence.
        findings: Vec<Finding>,
        /// The replies the validator dropped, possibly none.
        refused: Vec<RefusedStage>,
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
    /// A re-run of the assessment of `proposal` was requested by `by`.
    /// This is the re-run's audit record in the ledger.
    RerunRequested {
        /// The call.
        call: CallId,
        /// The proposal.
        proposal: ProposalId,
        /// The coordinator's account.
        by: AccountId,
    },
    /// The stages dropped from the last assessment of `proposal`. The
    /// list supersedes the earlier one, and it ends a re-run in flight.
    RefusalsRecorded {
        /// The call.
        call: CallId,
        /// The proposal.
        proposal: ProposalId,
        /// The dropped stages, possibly none.
        refused: Vec<RefusedStage>,
    },
    /// The re-run of `proposal` in flight was abandoned, for `reason`
    /// (issue 6 M3). This is the abandonment's audit record in the
    /// ledger. It frees the in-flight slot, and the re-run still counts.
    RerunAbandoned {
        /// The call.
        call: CallId,
        /// The proposal.
        proposal: ProposalId,
        /// Why.
        reason: RerunEnd,
    },
    /// `by`, the FSTP coordinator of the call, read the assessable input
    /// of `proposal` for a connected agent (ADR-033). This is the
    /// read's ledger record (R-AU-01). The latest one of each account
    /// binds its next client assessment of the proposal.
    AssessmentInputRead {
        /// The call.
        call: CallId,
        /// The proposal.
        proposal: ProposalId,
        /// The coordinator's account.
        by: AccountId,
        /// The digest of the served input.
        input: ContentDigest,
    },
    /// `by` recorded the assessment its connected agent made of
    /// `proposal` (ADR-033). It precedes the run's `Recorded` findings
    /// and its `RefusalsRecorded`, in the same entry.
    ClientAssessed {
        /// The call.
        call: CallId,
        /// The proposal.
        proposal: ProposalId,
        /// The coordinator's account.
        by: AccountId,
        /// The provenance of the run.
        run: ClientRun,
    },
}
