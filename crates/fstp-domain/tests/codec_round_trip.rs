//! Round trip of the JSON codecs for every `Record` variant, every `Command`
//! kind and `PolicyVersion` (design sections 2.10, 5.1 and 7).
//!
//! Each property draws a value of one variant, encodes it, writes the RFC
//! 8785 text, parses and decodes it, and checks:
//!
//! - the decoded value equals the drawn one;
//! - the canonical bytes are the same after the round trip;
//! - encoding is deterministic.
//!
//! Stored record bytes are the hashed bytes (ADR-007), and an entry never
//! changes after it is appended (I-23). So canonical bytes must be stable.
//!
//! The witness payloads, the four of M2 and `ProgrammeActivated` since M4
//! change D2, have no public constructor. Their round trip
//! runs over the decoded seeds of the `record_decode` fuzz corpus, which
//! lane L-CODEC supplies with the codec.

mod codec_support;

use codec_support::{Draw, RecordTag, codec_for, command, decoded_seeds, policy, record};
use fstp_domain::command::{Command, CommandKind};
use fstp_domain::policy::PolicyVersion;
use fstp_domain::record::Record;
use fstp_prop::{check, prop_assert_eq};

macro_rules! record_round_trip {
    ($($name:ident => $tag:ident),* $(,)?) => { $(
        #[doc = concat!(
            "I-23, ADR-007: a generated `Record::", stringify!($tag),
            "` survives encode, canonical text, parse and decode, with stable bytes."
        )]
        #[test]
        fn $name() {
            let codec = codec_for!(Record);
            check(stringify!($name), |g| {
                let mut d = Draw::plain();
                let r = record(g, &mut d, RecordTag::$tag)?;
                codec.round_trip(&r)?;
                Ok(())
            });
        }
    )* };
}

macro_rules! witness_round_trip {
    ($($name:ident => $tag:ident),* $(,)?) => { $(
        #[doc = concat!(
            "I-23, ADR-007: every seed of `Record::", stringify!($tag),
            "` in the `record_decode` corpus is canonical and survives a round trip. ",
            "The payload has no public constructor, so at least one seed must exist."
        )]
        #[test]
        fn $name() {
            let codec = codec_for!(Record);
            let seeds = decoded_seeds(&codec, "record_decode");
            assert!(seeds.is_ok(), "{}", seeds.err().unwrap_or_default());
            let found = seeds
                .unwrap_or_default()
                .into_iter()
                .filter(|(_, r)| RecordTag::of(r) == RecordTag::$tag)
                .count();
            assert!(
                found > 0,
                "no seed in fuzz/seeds/record_decode decodes to Record::{}",
                stringify!($tag)
            );
        }
    )* };
}

macro_rules! command_round_trip {
    ($($name:ident => $kind:ident),* $(,)?) => { $(
        #[doc = concat!(
            "TH-26: a generated `Command::", stringify!($kind),
            "` survives encode, canonical text, parse and decode, with stable bytes."
        )]
        #[test]
        fn $name() {
            let codec = codec_for!(Command);
            check(stringify!($name), |g| {
                let mut d = Draw::plain();
                let c = command(g, &mut d, CommandKind::$kind)?;
                codec.round_trip(&c)?;
                Ok(())
            });
        }
    )* };
}

record_round_trip! {
    i23_codec_round_trip_record_programme_created => ProgrammeCreated,
    i23_codec_round_trip_record_policy_version_recorded => PolicyVersionRecorded,
    i23_codec_round_trip_record_call_drafted => CallDrafted,
    i23_codec_round_trip_record_call_edited => CallEdited,
    i23_codec_round_trip_record_call_approved => CallApproved,
    i23_codec_round_trip_record_call_published => CallPublished,
    i23_codec_round_trip_record_binding_granted => BindingGranted,
    i23_codec_round_trip_record_binding_ended => BindingEnded,
    i23_codec_round_trip_record_binding_suspended => BindingSuspended,
    i23_codec_round_trip_record_binding_voided => BindingVoided,
    i23_codec_round_trip_record_binding_reinstated => BindingReinstated,
    i01_codec_round_trip_record_binding_end_scheduled => BindingEndScheduled,
    i23_codec_round_trip_record_vault_epoch_processed => VaultEpochProcessed,
    i23_codec_round_trip_record_proposal_created => ProposalCreated,
    i23_codec_round_trip_record_plan_version_recorded => PlanVersionRecorded,
    i23_codec_round_trip_record_submitted => Submitted,
    i23_codec_round_trip_record_assigned => Assigned,
    i23_codec_round_trip_record_conflict_declared => ConflictDeclared,
    i23_codec_round_trip_record_conflict_detected => ConflictDetected,
    i23_codec_round_trip_record_assignment_released => AssignmentReleased,
    i23_codec_round_trip_record_content_read => ContentRead,
    i23_codec_round_trip_record_knock_out_recorded => KnockOutRecorded,
    i23_codec_round_trip_record_score_recorded => ScoreRecorded,
    i23_codec_round_trip_record_score_voided => ScoreVoided,
    i23_codec_round_trip_record_ranking_summary_recorded => RankingSummaryRecorded,
    i23_codec_round_trip_record_question_asked => QuestionAsked,
    i23_codec_round_trip_record_no_questions_recorded => NoQuestionsRecorded,
    i23_codec_round_trip_record_answers_recorded => AnswersRecorded,
    i23_codec_round_trip_record_revision_submitted => RevisionSubmitted,
    i23_codec_round_trip_record_cut_off_recorded => CutOffRecorded,
    i23_codec_round_trip_record_irc_review_recorded => IrcReviewRecorded,
    i23_codec_round_trip_record_deferral_recorded => DeferralRecorded,
    i23_codec_round_trip_record_re_entered => ReEntered,
    i23_codec_round_trip_record_amount_determined => AmountDetermined,
    i23_codec_round_trip_record_cap_reserved => CapReserved,
    i23_codec_round_trip_record_cap_released => CapReleased,
    i23_codec_round_trip_record_grant_accepted => GrantAccepted,
    i23_codec_round_trip_record_grant_approved => GrantApproved,
    i23_codec_round_trip_record_contract_fact_recorded => ContractFactRecorded,
    i23_codec_round_trip_record_negotiation_declined => NegotiationDeclined,
    i23_codec_round_trip_record_termination_recorded => TerminationRecorded,
    i23_codec_round_trip_record_transitioned => Transitioned,
    i23_codec_round_trip_record_vault_outcome => VaultOutcome,
    i23_codec_round_trip_record_terms_accepted => TermsAccepted,
    i23_codec_round_trip_record_outbox_enqueued => OutboxEnqueued,
    i23_codec_round_trip_record_payment_requested => PaymentRequested,
    i23_codec_round_trip_record_line_accepted => LineAccepted,
    i23_codec_round_trip_record_payment_approved => PaymentApproved,
    i23_codec_round_trip_record_payment_confirmed => PaymentConfirmed,
    i23_codec_round_trip_record_payment_request_withdrawn => PaymentRequestWithdrawn,
    i23_codec_round_trip_record_payment_changes_requested => PaymentChangesRequested,
    i32_codec_round_trip_record_checks_recorded => ChecksRecorded,
    i23_codec_round_trip_record_deliverable_recorded => DeliverableRecorded,
    i23_codec_round_trip_record_amendment_proposed => AmendmentProposed,
    i23_codec_round_trip_record_amendment_routed => AmendmentRouted,
    i23_codec_round_trip_record_amendment_activated => AmendmentActivated,
    r_ev_09_codec_round_trip_record_cut_off_round_opened => CutOffRoundOpened,
    r_ev_09_codec_round_trip_record_ballot_cast => BallotCast,
    r_ev_09_codec_round_trip_record_vote_delegated => VoteDelegated,
    r_ga_01_codec_round_trip_record_guide_published => GuidePublished,
}

witness_round_trip! {
    i23_codec_round_trip_record_stage1_closed => Stage1Closed,
    i23_codec_round_trip_record_effective_score_set => EffectiveScoreSet,
    i23_codec_round_trip_record_grant_decided => GrantDecided,
    i23_codec_round_trip_record_payment_released => PaymentReleased,
    i67_codec_round_trip_record_programme_activated => ProgrammeActivated,
}

command_round_trip! {
    th26_codec_round_trip_command_create_programme => CreateProgramme,
    i67_codec_round_trip_command_activate_programme => ActivateProgramme,
    th26_codec_round_trip_command_edit_policy => EditPolicy,
    th26_codec_round_trip_command_draft_call => DraftCall,
    th26_codec_round_trip_command_edit_call => EditCall,
    th26_codec_round_trip_command_approve_call_publication => ApproveCallPublication,
    th26_codec_round_trip_command_publish_call => PublishCall,
    th26_codec_round_trip_command_grant_role => GrantRole,
    th26_codec_round_trip_command_end_role => EndRole,
    i01_codec_round_trip_command_end_scheduled_role => EndScheduledRole,
    th26_codec_round_trip_command_reinstate_binding => ReinstateBinding,
    th26_codec_round_trip_command_vault_changed => VaultChanged,
    th26_codec_round_trip_command_create_draft => CreateDraft,
    th26_codec_round_trip_command_add_team_member => AddTeamMember,
    th26_codec_round_trip_command_add_guardian => AddGuardian,
    th26_codec_round_trip_command_record_plan_version => RecordPlanVersion,
    th26_codec_round_trip_command_submit => Submit,
    th26_codec_round_trip_command_declare_conflict => DeclareConflict,
    th26_codec_round_trip_command_assign => Assign,
    th26_codec_round_trip_command_unassign => Unassign,
    th26_codec_round_trip_command_read_content => ReadContent,
    th26_codec_round_trip_command_record_knock_out => RecordKnockOut,
    th26_codec_round_trip_command_admit_to_stage1 => AdmitToStage1,
    th26_codec_round_trip_command_record_score => RecordScore,
    th26_codec_round_trip_command_correct_score => CorrectScore,
    th26_codec_round_trip_command_record_ranking_summary => RecordRankingSummary,
    th26_codec_round_trip_command_close_stage1 => CloseStage1,
    th26_codec_round_trip_command_ask_question => AskQuestion,
    th26_codec_round_trip_command_record_no_questions => RecordNoQuestions,
    th26_codec_round_trip_command_answer_questions => AnswerQuestions,
    th26_codec_round_trip_command_submit_revision => SubmitRevision,
    th26_codec_round_trip_command_rank_after_stage2 => RankAfterStage2,
    th26_codec_round_trip_command_expire_stage2 => ExpireStage2,
    r_ev_09_codec_round_trip_command_open_cut_off_round => OpenCutOffRound,
    r_ev_09_codec_round_trip_command_cast_ballot => CastBallot,
    r_ev_09_codec_round_trip_command_delegate_vote => DelegateVote,
    th26_codec_round_trip_command_record_cut_off => RecordCutOff,
    th26_codec_round_trip_command_record_irc_review => RecordIrcReview,
    th26_codec_round_trip_command_decline_after_concern => DeclineAfterConcern,
    th26_codec_round_trip_command_re_enter => ReEnter,
    th26_codec_round_trip_command_determine_amount => DetermineAmount,
    th26_codec_round_trip_command_accept_grant => AcceptGrant,
    th26_codec_round_trip_command_approve_grant => ApproveGrant,
    th26_codec_round_trip_command_contract_fact => ContractFact,
    th26_codec_round_trip_command_decline_negotiation => DeclineNegotiation,
    th26_codec_round_trip_command_withdraw => Withdraw,
    th26_codec_round_trip_command_start_execution => StartExecution,
    th26_codec_round_trip_command_complete => Complete,
    th26_codec_round_trip_command_terminate => Terminate,
    th26_codec_round_trip_command_request_payment => RequestPayment,
    th26_codec_round_trip_command_accept_line => AcceptLine,
    th26_codec_round_trip_command_approve_payment => ApprovePayment,
    th26_codec_round_trip_command_release_payment => ReleasePayment,
    th26_codec_round_trip_command_confirm_paid => ConfirmPaid,
    th26_codec_round_trip_command_withdraw_payment_request => WithdrawPaymentRequest,
    th26_codec_round_trip_command_request_payment_changes => RequestPaymentChanges,
    i32_codec_round_trip_command_record_checks => RecordChecks,
    th26_codec_round_trip_command_record_deliverable => RecordDeliverable,
    th26_codec_round_trip_command_propose_amendment => ProposeAmendment,
    th26_codec_round_trip_command_route_amendment => RouteAmendment,
    th26_codec_round_trip_command_activate_amendment => ActivateAmendment,
}

/// I-23, I-12, ADR-007: a generated policy version survives encode,
/// canonical text, parse and decode, with stable bytes. The decoder is
/// structural, so it keeps values that policy validation would refuse.
#[test]
fn i23_codec_round_trip_policy_version() {
    let codec = codec_for!(PolicyVersion);
    check("i23_codec_round_trip_policy_version", |g| {
        let mut d = Draw::plain();
        let p = policy(g, &mut d)?;
        codec.round_trip(&p)?;
        Ok(())
    });
}

/// Harness self-test: the record generator builds every non-witness
/// variant, each under its own tag. Green without the codec.
#[test]
fn codec_generators_cover_every_record_variant() {
    let tags = RecordTag::generated();
    check("codec_generators_cover_every_record_variant", |g| {
        for tag in &tags {
            let mut d = Draw::plain();
            let r = record(g, &mut d, *tag)?;
            prop_assert_eq!(RecordTag::of(&r), *tag);
        }
        Ok(())
    });
}

/// Harness self-test: the command generator builds every command kind,
/// each under its own kind. Green without the codec.
#[test]
fn codec_generators_cover_every_command_kind() {
    check("codec_generators_cover_every_command_kind", |g| {
        for kind in CommandKind::ALL {
            let mut d = Draw::plain();
            let c = command(g, &mut d, kind)?;
            prop_assert_eq!(c.kind(), kind);
        }
        Ok(())
    });
}

/// Harness self-test: the record tags are distinct, and exactly five of
/// them are witness payloads, with `ProgrammeActivated` since M4 change
/// D2. Green without the codec.
#[test]
fn codec_record_tags_are_distinct() {
    let all: std::collections::BTreeSet<RecordTag> = RecordTag::ALL.into_iter().collect();
    assert_eq!(all.len(), RecordTag::ALL.len());
    assert_eq!(
        RecordTag::generated().len().saturating_add(5),
        RecordTag::ALL.len()
    );
}
