//! The catalogue keys of diary sentences (`SPEC/12-journey-ui.md`
//! sections 7.1 and 11, `summary_key`).
//!
//! A journey row stores the index of its sentence's key, never the
//! sentence. The interface localises the key at read time, with the
//! parameters the diary read derives from the source record (I-97). The
//! codes are stored, so a code never changes meaning: a new key takes
//! the next free code.

/// The key of one diary sentence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(missing_docs, reason = "each variant is named after its catalogue key")]
pub enum SummaryKey {
    StateTransitioned,
    DeadlineSet,
    DeadlineMoved,
    QuestionAsked,
    AnswersRecorded,
    NoQuestions,
    ScoreRecorded,
    ScoreVoided,
    RankingSummary,
    ConflictDeclared,
    ConflictDetected,
    Reassigned,
    OutcomeNotice,
    IrcConcernNotice,
    ContractEffective,
    AmountDetermined,
    GrantAccepted,
    GrantApproved,
    GrantDecided,
    Terminated,
    AmendmentProposed,
    PaymentRequested,
    LineAccepted,
    PaymentApproved,
    PaymentReleased,
    PaymentConfirmed,
    PaymentWithdrawn,
    PaymentChangesRequested,
    PaymentClosed,
    MilestoneClosed,
    DeliverableRecorded,
    GuardianAdded,
}

impl SummaryKey {
    /// Every key, in code order.
    pub const ALL: [SummaryKey; 32] = [
        SummaryKey::StateTransitioned,
        SummaryKey::DeadlineSet,
        SummaryKey::DeadlineMoved,
        SummaryKey::QuestionAsked,
        SummaryKey::AnswersRecorded,
        SummaryKey::NoQuestions,
        SummaryKey::ScoreRecorded,
        SummaryKey::ScoreVoided,
        SummaryKey::RankingSummary,
        SummaryKey::ConflictDeclared,
        SummaryKey::ConflictDetected,
        SummaryKey::Reassigned,
        SummaryKey::OutcomeNotice,
        SummaryKey::IrcConcernNotice,
        SummaryKey::ContractEffective,
        SummaryKey::AmountDetermined,
        SummaryKey::GrantAccepted,
        SummaryKey::GrantApproved,
        SummaryKey::GrantDecided,
        SummaryKey::Terminated,
        SummaryKey::AmendmentProposed,
        SummaryKey::PaymentRequested,
        SummaryKey::LineAccepted,
        SummaryKey::PaymentApproved,
        SummaryKey::PaymentReleased,
        SummaryKey::PaymentConfirmed,
        SummaryKey::PaymentWithdrawn,
        SummaryKey::PaymentChangesRequested,
        SummaryKey::PaymentClosed,
        SummaryKey::MilestoneClosed,
        SummaryKey::DeliverableRecorded,
        SummaryKey::GuardianAdded,
    ];

    /// The stored code, from 1.
    pub const fn code(self) -> u16 {
        match self {
            SummaryKey::StateTransitioned => 1,
            SummaryKey::DeadlineSet => 2,
            SummaryKey::DeadlineMoved => 3,
            SummaryKey::QuestionAsked => 4,
            SummaryKey::AnswersRecorded => 5,
            SummaryKey::NoQuestions => 6,
            SummaryKey::ScoreRecorded => 7,
            SummaryKey::ScoreVoided => 8,
            SummaryKey::RankingSummary => 9,
            SummaryKey::ConflictDeclared => 10,
            SummaryKey::ConflictDetected => 11,
            SummaryKey::Reassigned => 12,
            SummaryKey::OutcomeNotice => 13,
            SummaryKey::IrcConcernNotice => 14,
            SummaryKey::ContractEffective => 15,
            SummaryKey::AmountDetermined => 16,
            SummaryKey::GrantAccepted => 17,
            SummaryKey::GrantApproved => 18,
            SummaryKey::GrantDecided => 19,
            SummaryKey::Terminated => 20,
            SummaryKey::AmendmentProposed => 21,
            SummaryKey::PaymentRequested => 22,
            SummaryKey::LineAccepted => 23,
            SummaryKey::PaymentApproved => 24,
            SummaryKey::PaymentReleased => 25,
            SummaryKey::PaymentConfirmed => 26,
            SummaryKey::PaymentWithdrawn => 27,
            SummaryKey::PaymentChangesRequested => 28,
            SummaryKey::PaymentClosed => 29,
            SummaryKey::MilestoneClosed => 30,
            SummaryKey::DeliverableRecorded => 31,
            SummaryKey::GuardianAdded => 32,
        }
    }

    /// The catalogue key the interface localises.
    pub const fn name(self) -> &'static str {
        match self {
            SummaryKey::StateTransitioned => "journey.state.transitioned",
            SummaryKey::DeadlineSet => "journey.deadline.set",
            SummaryKey::DeadlineMoved => "journey.deadline.moved",
            SummaryKey::QuestionAsked => "journey.clarification.question",
            SummaryKey::AnswersRecorded => "journey.clarification.answer",
            SummaryKey::NoQuestions => "journey.clarification.none",
            SummaryKey::ScoreRecorded => "journey.score.recorded",
            SummaryKey::ScoreVoided => "journey.score.voided",
            SummaryKey::RankingSummary => "journey.score.ranking_summary",
            SummaryKey::ConflictDeclared => "journey.conflict.declared",
            SummaryKey::ConflictDetected => "journey.conflict.detected",
            SummaryKey::Reassigned => "journey.conflict.reassigned",
            SummaryKey::OutcomeNotice => "journey.notice.outcome",
            SummaryKey::IrcConcernNotice => "journey.notice.irc_concern",
            SummaryKey::ContractEffective => "journey.contract.effective",
            SummaryKey::AmountDetermined => "journey.contract.amount_determined",
            SummaryKey::GrantAccepted => "journey.contract.grant_accepted",
            SummaryKey::GrantApproved => "journey.contract.grant_approved",
            SummaryKey::GrantDecided => "journey.contract.grant_decided",
            SummaryKey::Terminated => "journey.contract.terminated",
            SummaryKey::AmendmentProposed => "journey.contract.amendment_proposed",
            SummaryKey::PaymentRequested => "journey.payment.requested",
            SummaryKey::LineAccepted => "journey.payment.line_accepted",
            SummaryKey::PaymentApproved => "journey.payment.approved",
            SummaryKey::PaymentReleased => "journey.payment.released",
            SummaryKey::PaymentConfirmed => "journey.payment.confirmed",
            SummaryKey::PaymentWithdrawn => "journey.payment.withdrawn",
            SummaryKey::PaymentChangesRequested => "journey.payment.changes_requested",
            SummaryKey::PaymentClosed => "journey.payment.closed",
            SummaryKey::MilestoneClosed => "journey.milestone.closed",
            SummaryKey::DeliverableRecorded => "journey.milestone.deliverable",
            SummaryKey::GuardianAdded => "journey.guardian.added",
        }
    }

    /// The key of a stored code, or `None` for a code no key has.
    pub fn from_code(code: u16) -> Option<SummaryKey> {
        SummaryKey::ALL.into_iter().find(|k| k.code() == code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I-97, section 11: each key has its own code and name, and each
    /// code reads back its key. The codes run from 1 without a gap.
    #[test]
    fn i97_summary_keys_have_distinct_codes_and_names() {
        let mut codes = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        for k in SummaryKey::ALL {
            assert!(codes.insert(k.code()), "{k:?}");
            assert!(names.insert(k.name()), "{k:?}");
            assert_eq!(SummaryKey::from_code(k.code()), Some(k));
        }
        let want: std::collections::BTreeSet<u16> = (1..=32).collect();
        assert_eq!(codes, want);
        assert_eq!(SummaryKey::from_code(0), None);
    }
}
