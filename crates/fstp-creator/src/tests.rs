//! Unit tests of the creator (M4 design sections 3.2 and 8.4).
//!
//! The lane's invariant suites live in `fstp-api-testkit`. These tests
//! check the decider, the fold, the report, the witnesses and the codecs
//! directly, over explicit draft facts where the parallel lanes' sources
//! are not there yet.

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU8, NonZeroU16};

use fstp_domain::command::{Actor, Ctx, Via};
use fstp_domain::id::{
    AccountId, BindingId, CommandId, ContentDigest, CriterionId, DecisionId, OrganisationId,
    PolicyVersionId, ProgrammeId, TextId, TextRef, VaultEpoch,
};
use fstp_domain::policy::{
    AgentContentAccess, EffectiveScoreRule, ExclusionClasses, FrozenValues, FunderProfileRef,
    InferenceBinding, IrcExemptions, KnockOutCriteria, LicenceSet, LiveValues, McpBindingActions,
    ModelRef, OpaqueValue, PolicyVersion, ProximityLists, ReadAccess, ReviewerAnonymity,
    TieBreakRule, VotingRules, is_frozen_opaque,
};
use fstp_domain::record::{
    BindingEnded, BindingGranted, BindingReinstated, BindingSuspended, BindingVoided, Record,
};
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::{BindingScope, CoolingOff, Role};
use fstp_domain::rules::CATALOGUE;
use fstp_domain::scoring::{Criteria, Criterion};
use fstp_domain::state::State;
use fstp_domain::time::{Days, Timestamp};
use fstp_json::{FromJson, ToJson, Value};
use fstp_ledger::Seq;
use fstp_money::{Amount, AmountRange, Currency, NonNegAmount, Percent};

use crate::check::{CHECKS, CheckDetail, CheckId, CheckSubject, Severity, WarningKey};
use crate::decide::{CreatorDecision, CreatorRefusal, decide_creator, decide_with};
use crate::ids::{InvitationId, TemplateId};
use crate::inputs::{
    CreatorInputs, PortPresence, PreviewOutcome, SodPreview, VaultChecks, preview_targets,
    vault_questions,
};
use crate::model::{CreatorCommand, CreatorRecord, DraftRevision, Invitee, StartingPoint};
use crate::probe::{ProbeKind, ProbeOutcome, ProbeSet};
use crate::state::{CreatorFoldError, CreatorState};
use crate::theme::{Rgb, Theme, meets_aa};
use crate::validate::{ContentFacts, DraftFacts, ProfileFacts, validate_at};
use crate::witness::{AckSet, Uncleared, clean, clear_activation};

// ---------------------------------------------------------------------------
// The synthetic cast and a draft world
// ---------------------------------------------------------------------------

const TA: AccountId = AccountId::from_raw(0xA1);
const TB: AccountId = AccountId::from_raw(0xA2);
const M1: AccountId = AccountId::from_raw(0xB1);
const M2: AccountId = AccountId::from_raw(0xB2);
const P: ProgrammeId = ProgrammeId::from_raw(7);
const NOW: Timestamp = Timestamp::from_micros(1_000_000);

fn eur(minor: i64) -> NonNegAmount {
    NonNegAmount::new(Amount::from_minor(minor, Currency::Eur).unwrap()).unwrap()
}

fn opaque() -> OpaqueValue {
    OpaqueValue::from_value(&Value::Null).unwrap()
}

/// A synthetic policy: 0 to 5 scale, P-03 2, P-39 2, P-15 2, the given
/// P-05 and P-58.
fn policy(p05: i64, p58: Option<i64>) -> PolicyVersion {
    let criteria = Criteria::new(
        NonZeroU8::new(5).unwrap(),
        vec![Criterion {
            id: CriterionId::from_raw(1),
            weight: NonZeroU16::new(30).unwrap(),
        }],
    )
    .unwrap();
    let mut frozen_opaque = BTreeMap::new();
    for spec in CATALOGUE {
        if is_frozen_opaque(spec.id) {
            frozen_opaque.insert(spec.id, opaque());
        }
    }
    PolicyVersion {
        id: PolicyVersionId::from_raw(1),
        programme: P,
        parent: None,
        currency: Currency::Eur,
        frozen: FrozenValues {
            p01: criteria,
            p02: Percent::from_bp(7500).unwrap(),
            p03: NonZeroU8::new(2).unwrap(),
            p04: AmountRange::new(eur(500_000), eur(p05.min(10_000_000))).unwrap(),
            p07: Days::new(28),
            p09: KnockOutCriteria(Vec::new()),
            p10: ReadAccess::AssignedReviewersOnly,
            p11: ReviewerAnonymity::Anonymous,
            p14: IrcExemptions(opaque()),
            p15: NonZeroU8::new(2).unwrap(),
            p16: VotingRules(opaque()),
            p17: TieBreakRule(opaque()),
            p21: InferenceBinding {
                provider: opaque(),
                primary: ModelRef("synthetic-model".to_owned()),
                fallbacks: Vec::new(),
            },
            p24: EffectiveScoreRule::HigherOfOriginalAndRevised,
            p26: LicenceSet(BTreeSet::new()),
            p39: NonZeroU8::new(2).unwrap(),
            p53: profile_ref(),
            p75: AgentContentAccess::Off,
            p77: McpBindingActions::DraftOnly,
            opaque: frozen_opaque,
        },
        live: LiveValues {
            p05: eur(p05),
            p12: CoolingOff(1),
            p13: ExclusionClasses(BTreeSet::new()),
            p38: ProximityLists(BTreeMap::new()),
            p56: None,
            p58: p58.map(eur),
            opaque: BTreeMap::new(),
        },
    }
}

fn profile_ref() -> FunderProfileRef {
    FunderProfileRef(OpaqueValue::from_value(&Value::String("horizon-europe".to_owned())).unwrap())
}

fn ctx(actor: AccountId) -> Ctx {
    Ctx {
        now: NOW,
        actor: Actor::Account(actor),
        command: CommandId::from_bytes([0; 16]),
        via: Via::Web,
        tenant_admin: [TA, TB].contains(&actor),
        second_tenant_admin: None,
        binds_tenant_admin: false,
    }
}

/// The core and creator state of one draft, with its ledger position.
struct World {
    core: State,
    creator: CreatorState,
    seq: u64,
}

impl World {
    /// A1 opens the draft with a valid policy and grants M1 the programme
    /// manager role, in two entries.
    fn opened(policy: PolicyVersion) -> World {
        let mut w = World {
            core: State::genesis(),
            creator: CreatorState::genesis(),
            seq: 0,
        };
        w.entry(
            vec![CreatorRecord::DraftOpened {
                programme: P,
                profile: profile_ref(),
                by: TA,
            }],
            vec![
                Record::ProgrammeCreated {
                    programme: P,
                    currency: Currency::Eur,
                    by: TA,
                },
                Record::PolicyVersionRecorded {
                    version: Box::new(policy),
                    author: TA,
                },
            ],
        );
        w.grant(TA, M1, 1);
        w
    }

    fn grant(&mut self, by: AccountId, to: AccountId, binding: u128) {
        self.entry(
            Vec::new(),
            vec![Record::BindingGranted(BindingGranted {
                binding: BindingId::from_raw(binding),
                account: to,
                programme: P,
                role: Role::ProgrammeManager,
                scope: BindingScope::Programme,
                start: NOW,
                granted_by: by,
                second_admin: None,
                confidentiality: None,
                organisation: None,
                verified_epoch: None,
            })],
        );
    }

    /// Appends one ledger entry of creator and core records.
    fn entry(&mut self, creator: Vec<CreatorRecord>, core: Vec<Record>) {
        self.seq = self.seq.saturating_add(1);
        let seq = Seq::from_raw(self.seq);
        for r in &creator {
            self.creator.apply(seq, r).unwrap();
        }
        for r in &core {
            fstp_domain::apply(&mut self.core, seq, NOW, r).unwrap();
            self.creator.observe_core(seq, r).unwrap();
        }
    }

    fn head(&self) -> DraftRevision {
        self.creator.head(P).unwrap()
    }

    /// Decides `cmd` over clean draft facts and appends its records.
    fn run(
        &mut self,
        cmd: &CreatorCommand,
        actor: AccountId,
        inputs: &CreatorInputs,
    ) -> Result<(), CreatorRefusal> {
        let d = decide_with(
            &self.core,
            &self.creator,
            cmd,
            &ctx(actor),
            inputs,
            &clean_facts(),
        )?;
        assert!(d.core.is_empty());
        self.entry(d.records, Vec::new());
        Ok(())
    }

    fn acknowledge(
        &mut self,
        by: AccountId,
        check: CheckId,
        inputs: &CreatorInputs,
    ) -> Result<(), CreatorRefusal> {
        let cmd = CreatorCommand::AcknowledgeWarning {
            programme: P,
            revision: self.head(),
            warning: WarningKey {
                check,
                subject: CheckSubject::Draft,
            },
        };
        self.run(&cmd, by, inputs)
    }

    fn request(&mut self, by: AccountId, inputs: &CreatorInputs) -> Result<(), CreatorRefusal> {
        let cmd = CreatorCommand::RequestActivation {
            programme: P,
            revision: self.head(),
        };
        self.run(&cmd, by, inputs)
    }

    fn approve(&mut self, by: AccountId, inputs: &CreatorInputs) -> Result<(), CreatorRefusal> {
        let cmd = CreatorCommand::ApproveActivation {
            programme: P,
            revision: self.head(),
            decision: DecisionId::from_raw(99),
        };
        self.run(&cmd, by, inputs)
    }

    /// ADR-022: the override of I-67 by `by` at the head, with a
    /// synthetic stored reason.
    fn override_activation(
        &mut self,
        by: AccountId,
        inputs: &CreatorInputs,
    ) -> Result<(), CreatorRefusal> {
        let cmd = CreatorCommand::OverrideActivation {
            programme: P,
            revision: self.head(),
            decision: DecisionId::from_raw(98),
            reason: override_reason(),
        };
        self.run(&cmd, by, inputs)
    }

    fn report(&self, inputs: &CreatorInputs) -> crate::ValidationReport {
        validate_at(&self.core, &self.creator, P, &clean_facts(), inputs)
    }
}

/// Draft facts with approved wording and a complete compiled draft.
fn clean_facts() -> DraftFacts {
    DraftFacts {
        profile: ProfileFacts {
            wording_pending: false,
            unknown: None,
            ceiling: None,
        },
        content: Ok(empty_content()),
    }
}

fn empty_content() -> ContentFacts {
    ContentFacts {
        unset: BTreeSet::new(),
        action_dates_reversed: Ok(false),
        call_package_missing: BTreeSet::new(),
        guide: Ok(crate::guide::GuideScan::default()),
        flow_down_missing: Ok(BTreeSet::new()),
        precheck_enabled: false,
    }
}

/// Inputs where every probe passes, the cast is verified and no two cast
/// members share an identity.
fn passing() -> CreatorInputs {
    let cast = [TA, TB, M1, M2];
    CreatorInputs {
        unresolved_imports: 0,
        probes: ProbeSet::passing(),
        sod: SodPreview::default(),
        vault: VaultChecks {
            is_verified: cast.iter().map(|a| (*a, true)).collect(),
            same_identity: cast.iter().map(|a| (*a, false)).collect(),
            exclusion_classes_known: Some(true),
            proximity_lists_declared: Some(true),
        },
        tenant_admins: [TA, TB].into_iter().collect(),
        ports: PortPresence::default(),
        theme: Theme::m4_default(),
        profile: None,
    }
}

fn opened() -> World {
    World::opened(policy(40_000_000, Some(40_000_000)))
}

// ---------------------------------------------------------------------------
// The catalogue and the theme
// ---------------------------------------------------------------------------

/// I-66: `CHECKS` lists every check once, in `CheckId::ALL` order, with
/// the severity the check gives itself.
#[test]
fn i66_checks_table_lists_every_check_once() {
    let ids: Vec<CheckId> = CHECKS.iter().map(|c| c.id).collect();
    assert_eq!(ids, CheckId::ALL.to_vec());
    for c in CHECKS {
        assert_eq!(c.severity, c.id.severity(), "{}", c.id.name());
        assert_eq!(CheckId::from_name(c.id.name()), Some(c.id));
        assert!(!c.source.is_empty() && !c.implementation.is_empty());
    }
}

/// I-70: every default token pair meets AA in both themes.
#[test]
fn i70_default_tokens_meet_aa_in_both_themes() {
    let t = Theme::m4_default();
    assert!(t.pairs.iter().all(|p| meets_aa(p.text, p.background)));
    let modes: BTreeSet<_> = t.pairs.iter().map(|p| p.mode).collect();
    assert_eq!(modes.len(), 2);
}

/// I-70: the integer bounds decide the 4.5:1 edge as WCAG does. Grey
/// 0x767676 on white is 4.54:1 and passes; 0x777777 is 4.48:1 and fails.
#[test]
fn i70_contrast_edge_is_exact_at_four_point_five() {
    let white = Rgb::hex(0xFF_FF_FF);
    assert!(meets_aa(Rgb::hex(0x76_76_76), white));
    assert!(!meets_aa(Rgb::hex(0x77_77_77), white));
    assert!(meets_aa(white, Rgb::hex(0x76_76_76)));
    assert!(meets_aa(Rgb::hex(0), white));
    assert!(!meets_aa(white, white));
}

/// I-69, I-70: a theme without an element or with a weak pair fails.
#[test]
fn i66_theme_faults_are_failures() {
    let w = opened();
    let mut inputs = passing();
    inputs
        .theme
        .elements
        .remove(&crate::MandatoryElement::PlatformAttribution);
    if let Some(p) = inputs.theme.pairs.first_mut() {
        p.text = Rgb::hex(0xEE_EE_EE);
    }
    let r = w.report(&inputs);
    let checks: BTreeSet<CheckId> = r.failures().map(|f| f.check).collect();
    assert!(checks.contains(&CheckId::MandatoryElementMissing));
    assert!(checks.contains(&CheckId::ContrastFailure));
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

/// I-66: a fresh draft with clean facts shows only the roster warning.
#[test]
fn i66_fresh_draft_report_shows_the_roster_warning() {
    let w = opened();
    let r = w.report(&passing());
    let rows: Vec<(CheckId, Severity)> =
        r.results().iter().map(|c| (c.check, c.severity)).collect();
    assert_eq!(rows, vec![(CheckId::RosterShort, Severity::Warning)]);
    assert_eq!(r.revision(), w.head());
}

/// I-66, I-50, R-PG-01 AC: P-05 above the profile ceiling is a failure
/// that names both values as ADR-006 strings.
#[test]
fn i66_r_pg_01_cap_row_names_both_values() {
    let w = World::opened(policy(40_000_000, None));
    let mut facts = clean_facts();
    facts.profile.ceiling = Some(eur(30_000_000));
    let r = validate_at(&w.core, &w.creator, P, &facts, &passing());
    let row = r
        .results()
        .iter()
        .find(|c| c.check == CheckId::CapAboveCeiling)
        .unwrap();
    assert_eq!(
        row.detail,
        CheckDetail::Cap {
            p05: "400000.00".to_owned(),
            p58: "300000.00".to_owned()
        }
    );
    // A draft head with P-58 below P-05 gives the cap row only, not a
    // second PolicyInvalid row for the same I-50 refusal.
    let w = World::opened(policy(40_000_000, Some(39_999_999)));
    let r = validate_at(&w.core, &w.creator, P, &clean_facts(), &passing());
    let failures: Vec<CheckId> = r.failures().map(|f| f.check).collect();
    assert_eq!(failures, vec![CheckId::CapAboveCeiling]);
}

/// I-66, Q5, Q30, Q35: missing answers and absent probers fail closed.
#[test]
fn i66_missing_answers_fail_closed() {
    let w = opened();
    let mut inputs = passing();
    inputs.probes = ProbeSet::absent();
    inputs.unresolved_imports = 1;
    inputs.vault.exclusion_classes_known = None;
    inputs.vault.is_verified.remove(&TA);
    inputs.tenant_admins.remove(&TB);
    let r = w.report(&inputs);
    let failures: BTreeSet<CheckId> = r.failures().map(|f| f.check).collect();
    for c in [
        CheckId::ChannelUnreachable,
        CheckId::SendingDomainUnverified,
        CheckId::ImportUnresolved,
        CheckId::ExclusionClassUnknown,
        CheckId::BuilderUnverified,
        CheckId::TooFewTenantAdmins,
    ] {
        assert!(failures.contains(&c), "{}", c.name());
    }
    assert!(
        r.warnings()
            .any(|w| w.check == CheckId::InferenceUnreachable)
    );
}

/// I-66, Q6: the public report fails closed on a draft with no saved
/// field, no profile and a head policy that lacks P-23: wording counts as
/// pending and every content check fails.
#[test]
fn i66_public_validate_fails_closed_without_sources() {
    let w = opened();
    let facts = crate::validate::draft_facts(&w.core, &w.creator, P, None);
    let r = validate_at(&w.core, &w.creator, P, &facts, &passing());
    let failures: BTreeSet<CheckId> = r.failures().map(|f| f.check).collect();
    for c in [
        CheckId::LegalWordingPending,
        CheckId::FieldUnset,
        CheckId::CallPackageIncomplete,
        CheckId::GuideSectionMissing,
        CheckId::GuideBindingUnresolved,
        CheckId::FlowDownMissing,
    ] {
        assert!(failures.contains(&c), "{}", c.name());
    }
    // Q38 C (2026-11-06): the pre-check row is a warning, so it still
    // needs an acknowledgement, beside the failures above.
    assert!(r.shows_warning(&crate::check::WarningKey {
        check: CheckId::PrecheckUnavailable,
        subject: crate::check::CheckSubject::Draft,
    }));
}

/// SoD-01 to SoD-13 (R-CF-03): a refused or unchecked preview is a
/// failure naming the invitation and the rule only. A pending invitee is
/// a warning.
#[test]
fn i67_invitee_rows_follow_the_previews() {
    let mut w = opened();
    let mut inputs = passing();
    for (id, invitee) in [
        (1, Invitee::Account(M2)),
        (2, Invitee::Account(TB)),
        (
            3,
            Invitee::Pending {
                contact: TextRef::new(TextId::from_raw(5), ContentDigest::from_bytes([3; 32])),
            },
        ),
    ] {
        let cmd = CreatorCommand::Invite {
            programme: P,
            invitation: InvitationId::from_raw(id),
            role: Role::CommitteeMember,
            invitee,
            organisation: Some(OrganisationId::from_raw(id)),
            start: fstp_domain::time::Timestamp::from_micros(0),
            end: None,
        };
        w.run(&cmd, M1, &inputs).unwrap();
    }
    let targets: Vec<InvitationId> = preview_targets(&w.creator, P)
        .iter()
        .map(|t| t.invitation)
        .collect();
    assert_eq!(
        targets,
        vec![InvitationId::from_raw(1), InvitationId::from_raw(2)]
    );
    inputs.sod.outcomes.insert(
        InvitationId::from_raw(1),
        PreviewOutcome::Refused(RuleRef::Sod02),
    );
    let r = w.report(&inputs);
    let rows: Vec<(CheckId, CheckSubject, CheckDetail)> = r
        .results()
        .iter()
        .filter(|c| c.check == CheckId::InviteeRefused || c.check == CheckId::InviteeWithoutAccount)
        .map(|c| (c.check, c.subject.clone(), c.detail.clone()))
        .collect();
    assert_eq!(
        rows,
        vec![
            (
                CheckId::InviteeRefused,
                CheckSubject::Invitation(InvitationId::from_raw(1)),
                CheckDetail::Rule(RuleRef::Sod02)
            ),
            (
                CheckId::InviteeRefused,
                CheckSubject::Invitation(InvitationId::from_raw(2)),
                CheckDetail::NotChecked
            ),
            (
                CheckId::InviteeWithoutAccount,
                CheckSubject::Invitation(InvitationId::from_raw(3)),
                CheckDetail::None
            ),
        ]
    );
}

// ---------------------------------------------------------------------------
// The activation path
// ---------------------------------------------------------------------------

/// I-66, I-67, R-PG-03: M1 acknowledges the roster warning and requests,
/// and A2 activates. The entry records every probe and the approval.
#[test]
fn i66_i67_second_admin_activates_a_clean_draft() {
    let mut w = opened();
    let inputs = passing();
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    w.request(M1, &inputs).unwrap();
    let before = w.head();
    let cmd = CreatorCommand::ApproveActivation {
        programme: P,
        revision: before,
        decision: DecisionId::from_raw(99),
    };
    let d = decide_with(&w.core, &w.creator, &cmd, &ctx(TB), &inputs, &clean_facts()).unwrap();
    let probes = d
        .records
        .iter()
        .filter(|r| matches!(r, CreatorRecord::ProbeRecorded { .. }))
        .count();
    assert_eq!(probes, ProbeKind::ALL.len());
    let Some(CreatorRecord::ActivationApproved(a)) = d.records.last() else {
        panic!("no approval record: {:?}", d.records);
    };
    assert_eq!(a.approver(), TB);
    assert_eq!(a.revision(), before);
    assert_eq!(a.builders(), &[TA, M1].into_iter().collect::<BTreeSet<_>>());
    assert_eq!(a.decision(), DecisionId::from_raw(99));
    w.entry(d.records, Vec::new());
    assert_eq!(w.creator.draft(P).unwrap().active(), Some(before));
    assert_eq!(w.approve(TB, &inputs), Err(CreatorRefusal::AlreadyActive));
}

/// R-PG-03, T-AUTHZ-MATRIX, design section 15.0 ("Who requests
/// activation", 2026-11-06): only a programme manager on the draft
/// requests activation. A tenant admin, builder or not, is refused as an
/// actor. The actor comes before the draft's state, so an admin is
/// refused the same way once the programme is active.
#[test]
fn r_pg_03_only_a_programme_manager_requests_activation() {
    let mut w = opened();
    let inputs = passing();
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    for admin in [TA, TB] {
        assert_eq!(
            w.request(admin, &inputs),
            Err(CreatorRefusal::NotProgrammeManager),
            "{admin:?}"
        );
    }
    w.request(M1, &inputs).unwrap();
    w.approve(TB, &inputs).unwrap();
    for admin in [TA, TB] {
        assert_eq!(
            w.request(admin, &inputs),
            Err(CreatorRefusal::NotProgrammeManager),
            "{admin:?} once active"
        );
    }
    assert_eq!(w.request(M1, &inputs), Err(CreatorRefusal::AlreadyActive));
}

/// I-66: an unacknowledged warning blocks activation and names the check.
#[test]
fn i66_unacknowledged_warning_blocks() {
    let mut w = opened();
    let inputs = passing();
    w.request(M1, &inputs).unwrap();
    assert_eq!(
        w.approve(TB, &inputs),
        Err(CreatorRefusal::Uncleared(Uncleared::Unacknowledged(
            CheckId::RosterShort
        )))
    );
}

/// I-66, design 3.2 "Fresh probes": a probe that fails at approval blocks
/// activation, whatever the request saw.
#[test]
fn i66_probe_failing_at_approval_blocks() {
    let mut w = opened();
    let inputs = passing();
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    w.request(M1, &inputs).unwrap();
    let mut at_approval = passing();
    at_approval.probes = ProbeSet::passing().with(ProbeKind::Channel, ProbeOutcome::Fail);
    assert_eq!(
        w.approve(TB, &at_approval),
        Err(CreatorRefusal::Uncleared(Uncleared::Failure(
            CheckId::ChannelUnreachable
        )))
    );
}

/// I-66, reading R1: an edit voids the acknowledgement and the request.
#[test]
fn i66_edit_after_report_voids_acknowledgement_and_request() {
    let mut w = opened();
    let inputs = passing();
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    w.request(M1, &inputs).unwrap();
    let invite = CreatorCommand::Invite {
        programme: P,
        invitation: InvitationId::from_raw(1),
        role: Role::IrcMember,
        invitee: Invitee::Account(M2),
        organisation: None,
        start: fstp_domain::time::Timestamp::from_micros(0),
        end: None,
    };
    w.run(&invite, M1, &inputs).unwrap();
    let d = w.creator.draft(P).unwrap();
    assert!(!d.request_live());
    assert!(d.live_acks().is_empty());
    let mut inputs = passing();
    inputs
        .sod
        .outcomes
        .insert(InvitationId::from_raw(1), PreviewOutcome::Admitted);
    assert_eq!(w.approve(TB, &inputs), Err(CreatorRefusal::NoLiveRequest));
    w.request(M1, &inputs).unwrap();
    assert_eq!(
        w.approve(TB, &inputs),
        Err(CreatorRefusal::Uncleared(Uncleared::Unacknowledged(
            CheckId::RosterShort
        )))
    );
}

/// I-66: a command that names an old revision is refused.
#[test]
fn i66_stale_revision_is_refused() {
    let mut w = opened();
    let inputs = passing();
    let old = w.head();
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    let cmd = CreatorCommand::RequestActivation {
        programme: P,
        revision: old,
    };
    assert_eq!(w.run(&cmd, M1, &inputs), Err(CreatorRefusal::StaleRevision));
}

/// I-67, Q1: the opener, an acknowledging admin and a granting admin are
/// builders, and a programme manager is not an admin.
#[test]
fn i67_builders_never_approve() {
    let inputs = passing();
    let mut w = opened();
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    w.request(M1, &inputs).unwrap();
    assert_eq!(
        w.approve(TA, &inputs),
        Err(CreatorRefusal::ApproverIsBuilder)
    );
    assert_eq!(w.approve(M1, &inputs), Err(CreatorRefusal::NotTenantAdmin));

    let mut w = opened();
    w.acknowledge(TB, CheckId::RosterShort, &inputs).unwrap();
    w.request(M1, &inputs).unwrap();
    assert_eq!(
        w.approve(TB, &inputs),
        Err(CreatorRefusal::ApproverIsBuilder)
    );

    let mut w = opened();
    w.grant(TB, M2, 2);
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    w.request(M1, &inputs).unwrap();
    assert_eq!(
        w.approve(TB, &inputs),
        Err(CreatorRefusal::ApproverIsBuilder)
    );
}

/// I-67, Q2, T-SOD-SYBIL: an approver who shares a verified identity with
/// a builder, an unverified approver and a missing answer are refused.
#[test]
fn i67_second_person_needs_the_vault() {
    let base = passing();
    let mut w = opened();
    w.acknowledge(M1, CheckId::RosterShort, &base).unwrap();
    w.request(M1, &base).unwrap();
    let mut sybil = passing();
    sybil.vault.same_identity.insert(TB, true);
    assert_eq!(w.approve(TB, &sybil), Err(CreatorRefusal::SameIdentity));
    let mut unverified = passing();
    unverified.vault.is_verified.insert(TB, false);
    assert_eq!(
        w.approve(TB, &unverified),
        Err(CreatorRefusal::ApproverUnverified)
    );
    let mut missing = passing();
    missing.vault.same_identity.remove(&TB);
    assert_eq!(
        w.approve(TB, &missing),
        Err(CreatorRefusal::VaultAnswerMissing)
    );
    let q = vault_questions(&w.creator, P, Some(TB));
    assert_eq!(q.is_verified, [TA, TB, M1].into_iter().collect());
    assert_eq!(q.same_identity, Some((TB, [TA, M1].into_iter().collect())));
}

/// I-67, Q2: an unverified builder blocks activation.
#[test]
fn i67_unverified_builder_blocks() {
    let mut w = opened();
    let mut inputs = passing();
    inputs.vault.is_verified.insert(M1, false);
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    w.request(M1, &inputs).unwrap();
    assert_eq!(
        w.approve(TB, &inputs),
        Err(CreatorRefusal::Uncleared(Uncleared::Failure(
            CheckId::BuilderUnverified
        )))
    );
}

/// I-66: `clean` refuses acknowledgements read at another revision, and
/// `clear_activation` refuses a clean report that an edit made stale.
#[test]
fn i66_witnesses_bind_to_the_revision() {
    let mut w = opened();
    let inputs = passing();
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    w.request(M1, &inputs).unwrap();
    let report = w.report(&inputs);
    let acks = AckSet::live(&w.creator, P);
    let cleaned = clean(&report, &acks).unwrap();
    let invite = CreatorCommand::Invite {
        programme: P,
        invitation: InvitationId::from_raw(4),
        role: Role::CommitteeChair,
        invitee: Invitee::Account(M2),
        organisation: None,
        start: fstp_domain::time::Timestamp::from_micros(0),
        end: None,
    };
    w.run(&invite, M1, &inputs).unwrap();
    assert_eq!(
        clean(&report, &AckSet::live(&w.creator, P)),
        Err(Uncleared::Stale)
    );
    assert_eq!(
        clear_activation(
            &w.core,
            &w.creator,
            P,
            cleaned,
            &ctx(TB),
            &inputs,
            DecisionId::from_raw(1)
        ),
        Err(CreatorRefusal::StaleRevision)
    );
}

/// I-66, reading R5: only a warning the report shows can be acknowledged.
#[test]
fn i66_acknowledgement_names_a_shown_warning() {
    let mut w = opened();
    let inputs = passing();
    assert_eq!(
        w.acknowledge(M1, CheckId::InferenceUnreachable, &inputs),
        Err(CreatorRefusal::NotAWarning)
    );
    assert_eq!(
        w.acknowledge(M1, CheckId::FieldUnset, &inputs),
        Err(CreatorRefusal::NotAWarning)
    );
    assert_eq!(
        w.acknowledge(M2, CheckId::RosterShort, &inputs),
        Err(CreatorRefusal::NotProgrammeManager)
    );
}

/// I-66: the public decider fails closed on a draft with no saved field
/// and no profile, so it never activates.
#[test]
fn i66_public_decider_never_activates_without_sources() {
    let mut w = opened();
    let inputs = passing();
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    w.request(M1, &inputs).unwrap();
    let cmd = CreatorCommand::ApproveActivation {
        programme: P,
        revision: w.head(),
        decision: DecisionId::from_raw(1),
    };
    let got = decide_creator(&w.core, &w.creator, &cmd, &ctx(TB), &inputs);
    assert!(
        matches!(got, Err(CreatorRefusal::Uncleared(Uncleared::Failure(_)))),
        "{got:?}"
    );
}

/// R-PG-02, D1: an opening under a P-53 that names no shipped funder
/// profile refuses with the named gap, a second opening and an empty save
/// are refused, and a clone needs a source in the cell (I-19).
#[test]
fn r_pg_02_open_and_save_guards_refuse_with_a_named_reason() {
    let w = opened();
    let inputs = passing();
    let open = CreatorCommand::OpenDraft {
        programme: ProgrammeId::from_raw(8),
        version: PolicyVersionId::from_raw(8),
        profile: profile_ref(),
        name: None,
    };
    assert!(matches!(
        decide_creator(&w.core, &w.creator, &open, &ctx(TA), &inputs),
        Err(CreatorRefusal::Unavailable(_))
    ));
    let again = CreatorCommand::OpenDraft {
        programme: P,
        version: PolicyVersionId::from_raw(8),
        profile: profile_ref(),
        name: None,
    };
    assert_eq!(
        decide_creator(&w.core, &w.creator, &again, &ctx(TA), &inputs),
        Err(CreatorRefusal::DraftExists)
    );
    let save = CreatorCommand::SaveFields {
        programme: P,
        base: w.head(),
        fields: Vec::new(),
        clear: Vec::new(),
    };
    assert_eq!(
        decide_creator(&w.core, &w.creator, &save, &ctx(M1), &inputs),
        Err(CreatorRefusal::NothingToSave)
    );
    let start = CreatorCommand::ApplyStart {
        programme: P,
        base: w.head(),
        start: StartingPoint::Clone {
            source: ProgrammeId::from_raw(55),
        },
    };
    assert_eq!(
        decide_creator(&w.core, &w.creator, &start, &ctx(M1), &inputs),
        Err(CreatorRefusal::UnknownSource)
    );
}

/// Invitations: Receiving roles and tenant admin are not invitable, ids
/// are unique, and a withdrawn invitation cannot be withdrawn again.
#[test]
fn invitations_are_checked() {
    let mut w = opened();
    let inputs = passing();
    let invite = |id, role| CreatorCommand::Invite {
        programme: P,
        invitation: InvitationId::from_raw(id),
        role,
        invitee: Invitee::Account(M2),
        organisation: None,
        start: fstp_domain::time::Timestamp::from_micros(0),
        end: None,
    };
    assert_eq!(
        w.run(&invite(1, Role::Applicant), TA, &inputs),
        Err(CreatorRefusal::RoleNotInvitable)
    );
    assert_eq!(
        w.run(&invite(1, Role::TenantAdmin), TA, &inputs),
        Err(CreatorRefusal::RoleNotInvitable)
    );
    w.run(&invite(1, Role::CallDrafter), TA, &inputs).unwrap();
    assert_eq!(
        w.run(&invite(1, Role::CallDrafter), TA, &inputs),
        Err(CreatorRefusal::InvitationExists)
    );
    let withdraw = CreatorCommand::WithdrawInvitation {
        programme: P,
        invitation: InvitationId::from_raw(1),
    };
    w.run(&withdraw, M1, &inputs).unwrap();
    assert_eq!(
        w.run(&withdraw, M1, &inputs),
        Err(CreatorRefusal::UnknownInvitation)
    );
}

/// Design doc 11, Q3 (Daniel, 2026-11-15): an invitation carries the role
/// dates the grant reuses. An end that does not lie after the start is
/// refused, as a grant with such dates is (Cooling-off NOTE). A later end
/// and an open end are recorded with the start.
#[test]
fn q3_invitation_dates_are_recorded_and_an_end_before_the_start_is_refused() {
    use fstp_domain::time::Timestamp;
    let mut w = opened();
    let inputs = passing();
    let start = Timestamp::from_micros(1_794_009_600_000_000);
    let invite = |id, end| CreatorCommand::Invite {
        programme: P,
        invitation: InvitationId::from_raw(id),
        role: Role::FinanceApprover,
        invitee: Invitee::Account(M2),
        organisation: None,
        start,
        end,
    };
    for end in [start, Timestamp::from_micros(start.micros() - 1)] {
        assert_eq!(
            w.run(&invite(1, Some(end)), TA, &inputs),
            Err(CreatorRefusal::InvitationDates)
        );
    }
    let end = Timestamp::from_micros(start.micros() + 1);
    w.run(&invite(1, Some(end)), TA, &inputs).unwrap();
    w.run(&invite(2, None), M1, &inputs).unwrap();
    let d = w.creator.draft(P).unwrap();
    let one = d.invitations().get(&InvitationId::from_raw(1)).unwrap();
    assert_eq!((one.start, one.end), (start, Some(end)));
    let two = d.invitations().get(&InvitationId::from_raw(2)).unwrap();
    assert_eq!((two.start, two.end), (start, None));
}

// ---------------------------------------------------------------------------
// The fold
// ---------------------------------------------------------------------------

/// One entry bumps the revision once, and the fold refuses impossible
/// sequences.
#[test]
fn fold_bumps_once_per_entry_and_refuses_impossible_records() {
    let w = opened();
    assert_eq!(w.head().seq(), 2);
    let mut c = w.creator.clone();
    let opened = CreatorRecord::DraftOpened {
        programme: P,
        profile: profile_ref(),
        by: TA,
    };
    assert_eq!(
        c.apply(Seq::from_raw(9), &opened),
        Err(CreatorFoldError::DraftExists)
    );
    let stray = CreatorRecord::InvitationWithdrawn {
        programme: P,
        invitation: InvitationId::from_raw(3),
        by: M1,
    };
    assert_eq!(
        c.apply(Seq::from_raw(9), &stray),
        Err(CreatorFoldError::UnknownInvitation)
    );
    let elsewhere = CreatorRecord::InvitationWithdrawn {
        programme: ProgrammeId::from_raw(1),
        invitation: InvitationId::from_raw(3),
        by: M1,
    };
    assert_eq!(
        c.apply(Seq::from_raw(9), &elsewhere),
        Err(CreatorFoldError::UnknownDraft)
    );
    let probe = CreatorRecord::ProbeRecorded {
        programme: P,
        probe: ProbeKind::Channel,
        outcome: ProbeOutcome::Pass,
        at: NOW,
    };
    assert_eq!(
        c.apply(Seq::from_raw(1), &probe),
        Err(CreatorFoldError::OutOfOrder)
    );
    c.apply(Seq::from_raw(9), &probe).unwrap();
    c.apply(Seq::from_raw(9), &probe).unwrap();
    assert_eq!(c.head(P).unwrap().seq(), 3);
}

// ---------------------------------------------------------------------------
// Fold hooks: binding records, import resolutions, acceptances
// ---------------------------------------------------------------------------

impl World {
    /// Folds one core record into the creator alone, in a new entry. The
    /// creator never re-runs a core guard, so the core state stays as is.
    fn observe(&mut self, record: &Record) {
        self.seq = self.seq.saturating_add(1);
        self.creator
            .observe_core(Seq::from_raw(self.seq), record)
            .unwrap();
    }

    fn next_seq(&mut self) -> Seq {
        self.seq = self.seq.saturating_add(1);
        Seq::from_raw(self.seq)
    }
}

/// The later records of the binding `binding`, one per kind.
fn binding_records(binding: BindingId) -> Vec<Record> {
    vec![
        Record::BindingEnded(BindingEnded {
            binding,
            at: NOW,
            barred_through: 1,
            p12: CoolingOff(1),
        }),
        Record::BindingSuspended(BindingSuspended {
            binding,
            rule: RuleRef::Sod02,
            epoch: VaultEpoch::from_raw(1),
        }),
        Record::BindingVoided(BindingVoided {
            binding,
            rule: RuleRef::I04,
            epoch: VaultEpoch::from_raw(1),
        }),
        Record::BindingReinstated(BindingReinstated {
            binding,
            by: TA,
            reason: TextRef::new(TextId::from_raw(8), ContentDigest::from_bytes([8; 32])),
        }),
        Record::BindingEndScheduled { binding, at: NOW },
    ]
}

/// I-66, design 3.2 "Bound to a revision", reading R1: every later
/// record of a binding on the draft bumps the revision and voids the
/// acknowledgement and the request made before it.
#[test]
fn i66_binding_records_on_the_draft_void_acknowledgement_and_request() {
    for record in binding_records(BindingId::from_raw(1)) {
        let mut w = opened();
        let inputs = passing();
        w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
        w.request(M1, &inputs).unwrap();
        let before = w.head();
        w.observe(&record);
        let d = w.creator.draft(P).unwrap();
        assert_ne!(d.head(), before, "{record:?} left the revision");
        assert!(!d.request_live(), "{record:?} left the request live");
        assert!(d.live_acks().is_empty(), "{record:?} left the ack live");
    }
}

/// I-66: a binding record on a programme with no draft changes nothing.
#[test]
fn i66_binding_records_off_the_draft_change_nothing() {
    let mut w = opened();
    let before = w.creator.clone();
    for record in binding_records(BindingId::from_raw(77)) {
        w.observe(&record);
    }
    assert_eq!(w.creator, before);
}

/// I-67, Q1: the author of a reinstatement of a draft binding joins the
/// builder set, as a grantor does. The other binding records name no
/// author.
#[test]
fn i67_binding_reinstater_joins_the_builder_set() {
    let mut w = opened();
    w.observe(&Record::BindingReinstated(BindingReinstated {
        binding: BindingId::from_raw(1),
        by: TB,
        reason: TextRef::new(TextId::from_raw(8), ContentDigest::from_bytes([8; 32])),
    }));
    assert!(w.creator.draft(P).unwrap().builders().contains(&TB));
}

/// I-67, Q1 "any import resolution": a tenant admin who dismisses an
/// import proposal on the draft is a builder, so it cannot approve. The
/// dismissal is an edit, so it voids the acknowledgement and the request
/// too (reading R1).
#[test]
fn i67_import_dismissal_makes_the_resolver_a_builder() {
    let mut w = opened();
    let inputs = passing();
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    w.request(M1, &inputs).unwrap();
    let before = w.head();
    let seq = w.next_seq();
    w.creator.observe_import_resolution(seq, P, TB).unwrap();
    let d = w.creator.draft(P).unwrap();
    assert!(d.builders().contains(&TB));
    assert_ne!(d.head(), before);
    assert!(!d.request_live());
    assert!(d.live_acks().is_empty());
    assert_eq!(
        w.approve(TB, &inputs),
        Err(CreatorRefusal::ApproverIsBuilder)
    );
}

/// I-66, I-67 (Daniel, 2026-11-15, the I-66 generator gaps): the removal
/// of an imported document is a draft record. It voids the
/// acknowledgement and the activation request, and its author joins the
/// builder set. Only a programme manager at the head removes, and never
/// after activation.
#[test]
fn i66_import_removal_voids_acknowledgement_and_request() {
    let mut w = opened();
    let inputs = passing();
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    w.request(M1, &inputs).unwrap();
    let document = crate::ids::ImportDocumentId::from_raw(31);
    let removal = |w: &World, by, base| {
        crate::decide::decide_import_removal(&w.core, &w.creator, P, base, document, &ctx(by))
    };
    let stale = DraftRevision::new(1, Seq::from_raw(1));
    assert_eq!(removal(&w, M1, stale), Err(CreatorRefusal::StaleRevision));
    assert_eq!(
        removal(&w, TB, w.head()),
        Err(CreatorRefusal::NotProgrammeManager)
    );
    let d = removal(&w, M1, w.head()).unwrap();
    assert!(d.core.is_empty());
    assert_eq!(
        d.records,
        vec![CreatorRecord::ImportRemoved {
            programme: P,
            revision: w.head(),
            document,
            by: M1,
        }]
    );
    let before = w.head();
    w.entry(d.records, Vec::new());
    let draft = w.creator.draft(P).unwrap();
    assert_ne!(draft.head(), before);
    assert!(!draft.request_live(), "I-66: the removal voids the request");
    assert!(
        draft.live_acks().is_empty(),
        "I-66: and the acknowledgement"
    );
    assert!(draft.builders().contains(&M1));
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    w.request(M1, &inputs).unwrap();
    w.approve(TB, &inputs).unwrap();
    assert_eq!(
        removal(&w, M1, w.head()),
        Err(CreatorRefusal::AlreadyActive)
    );
}

/// The programme narrative as a manual edit with digest tag `tag`.
fn narrative_edit(text: &str, tag: u8) -> crate::model::FieldEdit {
    let field = fstp_programme::FieldId::ProgrammeNarrative;
    crate::model::FieldEdit {
        field,
        value: fstp_programme::decode_field_value(field, format!("\"{text}\"").as_bytes()).unwrap(),
        digest: crate::model::ValueDigest::new(ContentDigest::from_bytes([tag; 32])),
        provenance: crate::model::Provenance::Manual,
    }
}

/// I-66 (Daniel, 2026-11-15, the I-66 generator gaps): `EditNarrative`
/// edits narrative text the draft holds. A gap is refused, since a save
/// fills it, and so is a field that is no narrative, another provenance
/// and a stale revision. An edit records the new digest, voids the
/// acknowledgement and the request, and the value is held like a save's.
#[test]
fn i66_edit_narrative_edits_held_text_and_voids_the_clearance() {
    let mut w = opened();
    let inputs = passing();
    let edit = |w: &World, e: crate::model::FieldEdit| CreatorCommand::EditNarrative {
        programme: P,
        base: w.head(),
        edit: e,
    };
    let gap = edit(&w, narrative_edit("Synthetic narrative", 1));
    assert_eq!(
        w.run(&gap, M1, &inputs),
        Err(CreatorRefusal::NothingToSave),
        "a gap is filled by a save, not edited"
    );
    let save = CreatorCommand::SaveFields {
        programme: P,
        base: w.head(),
        fields: vec![narrative_edit("Synthetic narrative", 1)],
        clear: Vec::new(),
    };
    w.run(&save, M1, &inputs).unwrap();
    let mut not_manual = narrative_edit("Synthetic text", 2);
    not_manual.provenance = crate::model::Provenance::Template {
        template: TemplateId::from_raw(1),
        version: 1,
    };
    let refused = edit(&w, not_manual);
    assert_eq!(
        w.run(&refused, M1, &inputs),
        Err(CreatorRefusal::ProvenanceNotManual)
    );
    let p02 = crate::model::FieldEdit {
        field: fstp_programme::FieldId::P02,
        value: fstp_programme::decode_field_value(fstp_programme::FieldId::P02, b"\"75.00\"")
            .unwrap(),
        digest: crate::model::ValueDigest::new(ContentDigest::from_bytes([3; 32])),
        provenance: crate::model::Provenance::Manual,
    };
    let policy = edit(&w, p02);
    assert_eq!(
        w.run(&policy, M1, &inputs),
        Err(CreatorRefusal::NothingToSave),
        "P-02 is no narrative"
    );
    let stale = CreatorCommand::EditNarrative {
        programme: P,
        base: DraftRevision::new(1, Seq::from_raw(1)),
        edit: narrative_edit("Synthetic text", 4),
    };
    assert_eq!(
        w.run(&stale, M1, &inputs),
        Err(CreatorRefusal::StaleRevision)
    );
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    w.request(M1, &inputs).unwrap();
    let text = narrative_edit("Edited synthetic narrative", 5);
    let cmd = edit(&w, text.clone());
    w.run(&cmd, M1, &inputs).unwrap();
    let d = w.creator.draft(P).unwrap();
    assert_eq!(
        d.fields().get(&fstp_programme::FieldId::ProgrammeNarrative),
        Some(&(text.digest, crate::model::Provenance::Manual))
    );
    assert!(!d.request_live(), "I-66: the edit voids the request");
    assert!(d.live_acks().is_empty(), "I-66: and the acknowledgement");
    assert!(w.creator.hold_saved(P, std::slice::from_ref(&text)));
    assert_eq!(
        w.creator
            .held(P, fstp_programme::FieldId::ProgrammeNarrative, text.digest),
        Some(&text.value)
    );
}

/// The fuzz seeds of the narrative edit and the import removal decode, so
/// the targets start from valid forms.
#[test]
fn codec_fuzz_seeds_of_the_narrative_edit_and_the_import_removal_decode() {
    let command = include_str!("../fuzz/seeds/creator_command_decode/edit_narrative.json");
    assert!(matches!(
        crate::decode_command(command.as_bytes()),
        Ok(CreatorCommand::EditNarrative { .. })
    ));
    let edited = include_str!("../fuzz/seeds/creator_record_decode/narrative_edited.json");
    assert!(matches!(
        crate::decode_record(edited.as_bytes()),
        Ok(CreatorRecord::NarrativeEdited { .. })
    ));
    let removed = include_str!("../fuzz/seeds/creator_record_decode/import_removed.json");
    assert!(matches!(
        crate::decode_record(removed.as_bytes()),
        Ok(CreatorRecord::ImportRemoved { .. })
    ));
}

/// The codecs round-trip the narrative edit and the import removal.
#[test]
fn codec_round_trips_the_narrative_edit_and_the_import_removal() {
    let base = DraftRevision::new(3, Seq::from_raw(41));
    let text = narrative_edit("Synthetic narrative", 9);
    round_trip_command(&CreatorCommand::EditNarrative {
        programme: P,
        base,
        edit: text.clone(),
    });
    round_trip_record(&CreatorRecord::NarrativeEdited {
        programme: P,
        revision: base,
        field: text.field,
        digest: text.digest,
        by: M1,
    });
    round_trip_record(&CreatorRecord::ImportRemoved {
        programme: P,
        revision: base,
        document: crate::ids::ImportDocumentId::from_raw(12),
        by: M1,
    });
}

/// R-PG-05, Q17: a programme can be saved as a tenant-private template
/// after activation, and the fold admits the record. The saver does not
/// join the builder set after activation.
#[test]
fn r_pg_05_template_saved_after_activation_folds() {
    let mut w = opened();
    let inputs = passing();
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    w.request(M1, &inputs).unwrap();
    w.approve(TB, &inputs).unwrap();
    let active = w.creator.draft(P).unwrap().active();
    assert!(active.is_some());
    let builders = w.creator.draft(P).unwrap().builders().clone();
    let seq = w.next_seq();
    w.creator
        .apply(
            seq,
            &CreatorRecord::TemplateSaved {
                template: TemplateId::from_raw(4),
                programme: P,
                spec: ContentDigest::from_bytes([4; 32]),
                by: M2,
            },
        )
        .unwrap();
    let d = w.creator.draft(P).unwrap();
    assert_eq!(d.builders(), &builders);
    assert_eq!(d.active(), active);
    assert!(w.creator.template_taken(TemplateId::from_raw(4)));
}

/// I-66, R-PG-01: once an invitation by contact address is accepted, the
/// report previews its SoD guards instead of the warning
/// `InviteeWithoutAccount`, and the acceptance is an edit.
#[test]
fn i66_r_pg_01_accepted_invitation_gets_its_sod_preview() {
    let mut w = opened();
    let inputs = passing();
    let invitation = InvitationId::from_raw(3);
    let invite = CreatorCommand::Invite {
        programme: P,
        invitation,
        role: Role::IrcMember,
        invitee: Invitee::Pending {
            contact: TextRef::new(TextId::from_raw(5), ContentDigest::from_bytes([3; 32])),
        },
        organisation: None,
        start: fstp_domain::time::Timestamp::from_micros(0),
        end: None,
    };
    w.run(&invite, M1, &inputs).unwrap();
    assert!(preview_targets(&w.creator, P).is_empty());
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    let seq = w.next_seq();
    w.creator
        .observe_invitation_accepted(seq, P, invitation, M2)
        .unwrap();
    assert!(w.creator.draft(P).unwrap().live_acks().is_empty());
    let targets = preview_targets(&w.creator, P);
    assert_eq!(targets.len(), 1);
    assert_eq!(targets.first().map(|t| t.account), Some(M2));
    let rows: Vec<(CheckId, CheckDetail)> = w
        .report(&inputs)
        .results()
        .iter()
        .filter(|c| c.subject == CheckSubject::Invitation(invitation))
        .map(|c| (c.check, c.detail.clone()))
        .collect();
    assert_eq!(
        rows,
        vec![(CheckId::InviteeRefused, CheckDetail::NotChecked)]
    );
    let mut admitted = passing();
    admitted
        .sod
        .outcomes
        .insert(invitation, PreviewOutcome::Admitted);
    assert!(
        !w.report(&admitted)
            .results()
            .iter()
            .any(|c| c.subject == CheckSubject::Invitation(invitation))
    );
}

/// I-66: an acceptance names the invited account, a live invitation and
/// an existing draft, or the fold refuses it.
#[test]
fn i66_acceptance_refuses_the_wrong_account_or_invitation() {
    let mut w = opened();
    let inputs = passing();
    let invitation = InvitationId::from_raw(1);
    let invite = CreatorCommand::Invite {
        programme: P,
        invitation,
        role: Role::IrcMember,
        invitee: Invitee::Account(M2),
        organisation: None,
        start: fstp_domain::time::Timestamp::from_micros(0),
        end: None,
    };
    w.run(&invite, M1, &inputs).unwrap();
    let c = &w.creator;
    assert_eq!(
        c.check_invitation_acceptance(P, invitation, TB),
        Err(CreatorFoldError::InviteeMismatch)
    );
    assert_eq!(c.check_invitation_acceptance(P, invitation, M2), Ok(()));
    assert_eq!(
        c.check_invitation_acceptance(P, InvitationId::from_raw(2), M2),
        Err(CreatorFoldError::UnknownInvitation)
    );
    assert_eq!(
        c.check_invitation_acceptance(ProgrammeId::from_raw(1), invitation, M2),
        Err(CreatorFoldError::UnknownDraft)
    );
    let withdraw = CreatorCommand::WithdrawInvitation {
        programme: P,
        invitation,
    };
    w.run(&withdraw, TA, &inputs).unwrap();
    let seq = w.next_seq();
    assert_eq!(
        w.creator
            .observe_invitation_accepted(seq, P, invitation, M2),
        Err(CreatorFoldError::UnknownInvitation)
    );
}

/// I-70, design 8.8: the bound tables are readable, and each lower bound
/// lies below its upper bound.
#[test]
fn i70_linear_bounds_are_ordered() {
    for c in 0..=u8::MAX {
        let (lower, upper) = crate::theme::linear_bounds(c);
        assert!(lower < upper, "channel {c}");
    }
}

// ---------------------------------------------------------------------------
// The codecs
// ---------------------------------------------------------------------------

fn round_trip_record(r: &CreatorRecord) {
    let v = r.to_json();
    let text = v.to_canonical().unwrap();
    let back = crate::decode_record(text.as_bytes()).unwrap();
    assert_eq!(&back, r, "{text}");
}

fn round_trip_command(c: &CreatorCommand) {
    let text = c.to_json().to_canonical().unwrap();
    let back = crate::decode_command(text.as_bytes()).unwrap();
    assert_eq!(&back, c, "{text}");
}

/// The records of an activation round-trip through their JSON text.
#[test]
fn codec_round_trips_records_and_commands() {
    let mut w = opened();
    let inputs = passing();
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    w.request(M1, &inputs).unwrap();
    let cmd = CreatorCommand::ApproveActivation {
        programme: P,
        revision: w.head(),
        decision: DecisionId::from_raw(99),
    };
    let d = decide_with(&w.core, &w.creator, &cmd, &ctx(TB), &inputs, &clean_facts()).unwrap();
    let mut records = d.records;
    records.push(CreatorRecord::DraftOpened {
        programme: P,
        profile: profile_ref(),
        by: TA,
    });
    records.push(CreatorRecord::StartApplied {
        programme: P,
        revision: w.head(),
        start: StartingPoint::Template {
            template: TemplateId::from_raw(3),
            version: 2,
        },
        by: M1,
    });
    records.push(CreatorRecord::InvitationRecorded {
        programme: P,
        invitation: InvitationId::from_raw(1),
        role: Role::CommitteeMember,
        invitee: Invitee::Pending {
            contact: TextRef::new(TextId::from_raw(5), ContentDigest::from_bytes([0xAB; 32])),
        },
        organisation: Some(OrganisationId::from_raw(4)),
        start: fstp_domain::time::Timestamp::from_micros(1_794_009_600_000_000),
        end: Some(fstp_domain::time::Timestamp::from_micros(
            1_825_545_600_000_000,
        )),
        by: M1,
    });
    records.push(CreatorRecord::TemplateSaved {
        template: TemplateId::from_raw(3),
        programme: P,
        spec: ContentDigest::from_bytes([7; 32]),
        by: M1,
    });
    records.push(CreatorRecord::ProbeRecorded {
        programme: P,
        probe: ProbeKind::Inference,
        outcome: ProbeOutcome::Absent,
        at: Timestamp::from_micros(-5),
    });
    for r in &records {
        round_trip_record(r);
    }
    for c in [
        cmd,
        CreatorCommand::OpenDraft {
            programme: P,
            version: PolicyVersionId::from_raw(1),
            profile: profile_ref(),
            name: None,
        },
        CreatorCommand::ApplyStart {
            programme: P,
            base: w.head(),
            start: StartingPoint::Blank {
                profile: profile_ref(),
            },
        },
        CreatorCommand::AcknowledgeWarning {
            programme: P,
            revision: w.head(),
            warning: WarningKey {
                check: CheckId::ContrastFailure,
                subject: CheckSubject::Colour {
                    mode: crate::ThemeMode::Dark,
                    role: crate::TextRole::Link,
                },
            },
        },
        CreatorCommand::Invite {
            programme: P,
            invitation: InvitationId::from_raw(2),
            role: Role::IrcMember,
            invitee: Invitee::Account(M2),
            organisation: None,
            start: fstp_domain::time::Timestamp::from_micros(1_794_009_600_000_000),
            end: Some(fstp_domain::time::Timestamp::from_micros(
                1_825_545_600_000_000,
            )),
        },
        CreatorCommand::SaveAsTenantTemplate {
            programme: P,
            template: TemplateId::from_raw(1),
        },
    ] {
        round_trip_command(&c);
    }
}

/// The codec refuses unknown members, non-canonical numbers and unsorted
/// sets.
#[test]
fn codec_refuses_non_canonical_input() {
    for bad in [
        r#"{"kind":"RequestActivation","programme":"7","revision":{"seq":"1","entry":"1"},"x":1}"#,
        r#"{"kind":"RequestActivation","programme":"07","revision":{"seq":"1","entry":"1"}}"#,
        r#"{"kind":"RequestActivation","programme":7,"revision":{"seq":"1","entry":"1"}}"#,
        r#"{"kind":"RequestActivation","programme":"7"}"#,
        r#"{"kind":"Unknown"}"#,
        r#"{"kind":"SaveFields","programme":"7","base":{"seq":"1","entry":"1"},"fields":[{"field":"p05","value":null,"digest":"00","provenance":{"kind":"Manual"}}]}"#,
        "not json",
    ] {
        assert!(crate::decode_command(bad.as_bytes()).is_err(), "{bad}");
    }
    let unsorted = r#"{"kind":"ActivationApproved","programme":"7","revision":{"seq":"1","entry":"1"},"report":{"programme":"7","revision":{"seq":"1","entry":"1"},"rows":[]},"decision":"1","approver":"2","builders":["5","3"]}"#;
    assert!(crate::decode_record(unsorted.as_bytes()).is_err());
    let negative_zero =
        r#"{"kind":"ProbeRecorded","programme":"7","probe":"Channel","outcome":"Pass","at":"-0"}"#;
    assert!(crate::decode_record(negative_zero.as_bytes()).is_err());
}

/// `validate_total`: a decoded fuzz input folds and validates without a
/// panic.
#[test]
fn validate_draft_is_total_on_a_sample() {
    let text = r#"{"records":[{"seq":"1","record":{"kind":"DraftOpened","programme":"7","profile":"null","by":"161"}}],"inputs":{"unresolved_imports":"0","probes":{"Channel":"Pass"},"admitted":[],"refused":[],"verified":["161"],"unverified":[],"same_identity":[],"tenant_admins":["161"],"exclusion_classes_known":null,"proximity_lists_declared":true,"precheck":false,"score_tools":true}}"#;
    let input = crate::decode_draft(text.as_bytes()).unwrap();
    let reports = crate::validate_draft(&input);
    assert_eq!(reports.len(), 2);
    assert!(reports.iter().all(|r| r.failures().next().is_some()));
}

/// The JSON of a value is accepted by `FromJson` directly too.
#[test]
fn codec_from_json_matches_decode() {
    let r = CreatorRecord::InvitationWithdrawn {
        programme: P,
        invitation: InvitationId::from_raw(1),
        by: M1,
    };
    assert_eq!(CreatorRecord::from_json(&r.to_json()).unwrap(), r);
}

// ---------------------------------------------------------------------------
// The actor before the state (`07-test-plan/test-plan.md`, authorisation
// matrix row)
// ---------------------------------------------------------------------------

/// An account that holds no role in the cell.
const OUTSIDER: AccountId = AccountId::from_raw(0xD1);

/// Every draft command on `P`, at `revision`.
fn draft_commands(revision: DraftRevision) -> Vec<CreatorCommand> {
    vec![
        CreatorCommand::ApplyStart {
            programme: P,
            base: revision,
            start: StartingPoint::Clone {
                source: ProgrammeId::from_raw(55),
            },
        },
        CreatorCommand::SaveFields {
            programme: P,
            base: revision,
            fields: Vec::new(),
            clear: Vec::new(),
        },
        CreatorCommand::AcceptNarrative {
            programme: P,
            base: revision,
            field: fstp_programme::FieldId::P01,
        },
        CreatorCommand::Invite {
            programme: P,
            invitation: InvitationId::from_raw(1),
            role: Role::Applicant,
            invitee: Invitee::Account(M2),
            organisation: None,
            start: fstp_domain::time::Timestamp::from_micros(0),
            end: None,
        },
        CreatorCommand::WithdrawInvitation {
            programme: P,
            invitation: InvitationId::from_raw(9),
        },
        CreatorCommand::AcknowledgeWarning {
            programme: P,
            revision,
            warning: WarningKey {
                check: CheckId::FieldUnset,
                subject: CheckSubject::Draft,
            },
        },
        CreatorCommand::RequestActivation {
            programme: P,
            revision,
        },
        CreatorCommand::ApproveActivation {
            programme: P,
            revision,
            decision: DecisionId::from_raw(98),
        },
        CreatorCommand::SaveAsTenantTemplate {
            programme: P,
            template: TemplateId::from_raw(77),
        },
        CreatorCommand::EditNarrative {
            programme: P,
            base: revision,
            edit: narrative_edit("Synthetic narrative", 6),
        },
    ]
}

/// Whether `r` is an actor denial.
fn actor_denial(r: &Result<CreatorDecision, CreatorRefusal>) -> bool {
    matches!(
        r,
        Err(CreatorRefusal::NotProgrammeManager | CreatorRefusal::NotTenantAdmin)
    )
}

/// Test plan, authorisation matrix row, I-67, R-PG-02: an outsider's
/// creator command gets an actor denial before any input or I-66
/// refusal, at a stale revision, on an unknown programme and once the
/// programme is active. A permitted actor gets the state refusal instead.
#[test]
fn t_authz_i67_outsider_creator_command_is_an_actor_denial_in_every_state() {
    let mut w = opened();
    let inputs = passing();
    let stale = w.head();
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    let decide = |w: &World, cmd: &CreatorCommand, a| {
        decide_creator(&w.core, &w.creator, cmd, &ctx(a), &inputs)
    };
    for cmd in draft_commands(stale) {
        let r = decide(&w, &cmd, OUTSIDER);
        assert!(actor_denial(&r), "stale {cmd:?}: {r:?}");
    }
    let mut unknown = opened();
    unknown.creator = CreatorState::genesis();
    for cmd in draft_commands(stale) {
        let r = decide(&unknown, &cmd, OUTSIDER);
        assert!(actor_denial(&r), "unknown {cmd:?}: {r:?}");
    }
    w.request(M1, &inputs).unwrap();
    w.approve(TB, &inputs).unwrap();
    let head = w.head();
    for cmd in draft_commands(head) {
        let r = decide(&w, &cmd, OUTSIDER);
        assert!(actor_denial(&r), "active {cmd:?}: {r:?}");
    }
    let r = decide(&w, &draft_commands(head)[1], M1);
    assert_eq!(r, Err(CreatorRefusal::AlreadyActive));
    let r = decide(&w, &draft_commands(head)[7], TA);
    assert_eq!(r, Err(CreatorRefusal::ApproverIsBuilder));
}

// ---------------------------------------------------------------------------
// ADR-022: the tenant admin override of I-67 (Daniel, 2026-11-15)
// ---------------------------------------------------------------------------

/// A synthetic stored override reason.
fn override_reason() -> TextRef {
    TextRef::new(
        TextId::from_raw(4242),
        ContentDigest::from_bytes([0x52; 32]),
    )
}

/// I-67 as amended by ADR-022, R-PG-03: A1, the opener and so a builder,
/// is refused the normal approval and activates through the override.
/// The entry records every probe and `ActivationOverridden` by A1 with the
/// reason, the builder set holding A1, and the decision time.
#[test]
fn i67_adr022_builder_admin_activates_through_the_override_with_its_reason() {
    let mut w = opened();
    let inputs = passing();
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    w.request(M1, &inputs).unwrap();
    assert_eq!(
        w.approve(TA, &inputs),
        Err(CreatorRefusal::ApproverIsBuilder),
        "the normal path still refuses a builder"
    );
    let before = w.head();
    let cmd = CreatorCommand::OverrideActivation {
        programme: P,
        revision: before,
        decision: DecisionId::from_raw(98),
        reason: override_reason(),
    };
    let d = decide_with(&w.core, &w.creator, &cmd, &ctx(TA), &inputs, &clean_facts()).unwrap();
    assert!(d.core.is_empty(), "the engine composes the activation");
    let probes = d
        .records
        .iter()
        .filter(|r| matches!(r, CreatorRecord::ProbeRecorded { .. }))
        .count();
    assert_eq!(probes, ProbeKind::ALL.len());
    let Some(CreatorRecord::ActivationOverridden(o)) = d.records.last() else {
        panic!("no override record: {:?}", d.records);
    };
    assert_eq!(o.by(), TA);
    assert_eq!(o.reason(), override_reason());
    assert_eq!(o.revision(), before);
    assert!(o.builders().contains(&TA));
    assert_eq!(o.decision(), DecisionId::from_raw(98));
    assert_eq!(o.at(), ctx(TA).now);
    w.entry(d.records, Vec::new());
    assert_eq!(w.creator.draft(P).unwrap().active(), Some(before));
    assert_eq!(
        w.override_activation(TA, &inputs),
        Err(CreatorRefusal::AlreadyActive)
    );
}

/// I-67 still holds for every builder but a tenant admin (ADR-022): M1,
/// the programme manager who built the draft, is refused the override.
#[test]
fn i67_adr022_non_admin_builder_override_is_refused() {
    let mut w = opened();
    let inputs = passing();
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    w.request(M1, &inputs).unwrap();
    assert_eq!(
        w.override_activation(M1, &inputs),
        Err(CreatorRefusal::NotTenantAdmin)
    );
    assert_eq!(w.creator.draft(P).unwrap().active(), None);
}

/// ADR-022, interim reading 1: A2, a tenant admin outside the builder
/// set, takes the normal approval and is refused the override.
#[test]
fn i67_adr022_non_builder_admin_override_is_refused() {
    let mut w = opened();
    let inputs = passing();
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    w.request(M1, &inputs).unwrap();
    assert_eq!(
        w.override_activation(TB, &inputs),
        Err(CreatorRefusal::NotABuilder)
    );
}

/// ADR-022: the override lifts only the second-person rule. I-66 holds
/// (an unacknowledged warning and a failing probe refuse it), a request
/// must be live, and the vault must verify the overriding admin.
#[test]
fn i66_adr022_override_keeps_i66_the_request_and_a_verified_admin() {
    let mut w = opened();
    let inputs = passing();
    assert_eq!(
        w.override_activation(TA, &inputs),
        Err(CreatorRefusal::NoLiveRequest)
    );
    w.request(M1, &inputs).unwrap();
    assert_eq!(
        w.override_activation(TA, &inputs),
        Err(CreatorRefusal::Uncleared(Uncleared::Unacknowledged(
            CheckId::RosterShort
        )))
    );
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    w.request(M1, &inputs).unwrap();
    let mut failing = passing();
    failing.probes = ProbeSet::passing().with(ProbeKind::Channel, ProbeOutcome::Fail);
    assert_eq!(
        w.override_activation(TA, &failing),
        Err(CreatorRefusal::Uncleared(Uncleared::Failure(
            CheckId::ChannelUnreachable
        )))
    );
    let mut unverified = passing();
    unverified.vault.is_verified.insert(TA, false);
    assert_eq!(
        w.override_activation(TA, &unverified),
        Err(CreatorRefusal::ApproverUnverified)
    );
    assert_eq!(w.creator.draft(P).unwrap().active(), None);
}

/// ADR-022, ADR-007: the override command and its record survive the
/// creator codec, the reason as a text reference only.
#[test]
fn adr022_override_command_and_record_round_trip() {
    let cmd = CreatorCommand::OverrideActivation {
        programme: P,
        revision: DraftRevision::new(3, Seq::from_raw(9)),
        decision: DecisionId::from_raw(98),
        reason: override_reason(),
    };
    let back = CreatorCommand::from_json(&cmd.to_json()).unwrap();
    assert_eq!(back, cmd);
    assert!(cmd.high_risk(), "I-78: the override is high-risk");
    let mut w = opened();
    let inputs = passing();
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    w.request(M1, &inputs).unwrap();
    let cmd = CreatorCommand::OverrideActivation {
        programme: P,
        revision: w.head(),
        decision: DecisionId::from_raw(98),
        reason: override_reason(),
    };
    let d = decide_with(&w.core, &w.creator, &cmd, &ctx(TA), &inputs, &clean_facts()).unwrap();
    let rec = d.records.last().unwrap().clone();
    let back = CreatorRecord::from_json(&rec.to_json()).unwrap();
    assert_eq!(back, rec);
}

/// R-PG-01, design doc 11 section 15: an `OpenDraft` with a name survives
/// the codec. One without a name writes no `name` member, so an opening
/// stored before the name keeps its form.
#[test]
fn r_pg_01_open_draft_name_round_trips_and_is_left_out_when_unset() {
    let value = fstp_programme::decode_field_value(
        fstp_programme::FieldId::ProgrammeName,
        b"\"Synthetic name\"",
    )
    .unwrap();
    let named = CreatorCommand::OpenDraft {
        programme: P,
        version: PolicyVersionId::from_raw(8),
        profile: profile_ref(),
        name: Some(crate::model::FieldEdit {
            field: fstp_programme::FieldId::ProgrammeName,
            value,
            digest: crate::model::ValueDigest::new(ContentDigest::from_bytes([5; 32])),
            provenance: crate::model::Provenance::Manual,
        }),
    };
    assert_eq!(CreatorCommand::from_json(&named.to_json()).unwrap(), named);
    let plain = CreatorCommand::OpenDraft {
        programme: P,
        version: PolicyVersionId::from_raw(8),
        profile: profile_ref(),
        name: None,
    };
    let v = plain.to_json();
    assert!(v.as_object().unwrap().get("name").is_none());
    assert_eq!(CreatorCommand::from_json(&v).unwrap(), plain);
}

/// I-66 (Daniel, 2026-11-15 night): `SaveFields` clears a field
/// explicitly. The cleared field holds no value any more, so the draft
/// holds no value of it (a gap, which the report shows as `FieldUnset`), and the
/// clear is an edit: it voids
/// the acknowledgement and the activation request. The record names the
/// cleared fields, and a save without a clear records none.
#[test]
fn i66_save_fields_clear_makes_a_gap_and_voids_the_clearance() {
    let field = fstp_programme::FieldId::ProgrammeNarrative;
    let mut w = opened();
    let inputs = passing();
    let save = CreatorCommand::SaveFields {
        programme: P,
        base: w.head(),
        fields: vec![narrative_edit("Synthetic narrative", 1)],
        clear: Vec::new(),
    };
    w.run(&save, M1, &inputs).unwrap();
    assert!(w.creator.draft(P).unwrap().set_fields().contains(&field));
    w.acknowledge(M1, CheckId::RosterShort, &inputs).unwrap();
    w.request(M1, &inputs).unwrap();

    let clear = CreatorCommand::SaveFields {
        programme: P,
        base: w.head(),
        fields: Vec::new(),
        clear: vec![field],
    };
    let d = decide_with(
        &w.core,
        &w.creator,
        &clear,
        &ctx(M1),
        &inputs,
        &clean_facts(),
    )
    .unwrap();
    assert!(
        d.core.is_empty(),
        "a clear composes no policy: {:?}",
        d.core
    );
    assert!(matches!(
        d.records.as_slice(),
        [CreatorRecord::FieldsSaved { fields, cleared, .. }]
            if fields.is_empty() && cleared == &vec![field]
    ));
    w.run(&clear, M1, &inputs).unwrap();
    let draft = w.creator.draft(P).unwrap();
    assert!(!draft.set_fields().contains(&field), "the field is a gap");
    assert!(!draft.fields().contains_key(&field));
    assert!(!draft.request_live(), "the clear voids the request");
    assert!(
        draft.live_acks().is_empty(),
        "the clear voids the acknowledgement"
    );
}

/// I-66: a clear names only fields that hold a value, never P-53, never a
/// field the same save sets, and in strictly ascending order. Each other
/// clear is refused as an invalid save.
#[test]
fn i66_save_fields_clear_is_refused_when_it_clears_nothing() {
    use fstp_programme::FieldId;
    let mut w = opened();
    let inputs = passing();
    let save = CreatorCommand::SaveFields {
        programme: P,
        base: w.head(),
        fields: vec![narrative_edit("Synthetic narrative", 1)],
        clear: Vec::new(),
    };
    w.run(&save, M1, &inputs).unwrap();
    let clear = |w: &World, fields: Vec<crate::model::FieldEdit>, clear: Vec<FieldId>| {
        CreatorCommand::SaveFields {
            programme: P,
            base: w.head(),
            fields,
            clear,
        }
    };
    for (what, cmd) in [
        (
            "an unset field",
            clear(&w, Vec::new(), vec![FieldId::Minors]),
        ),
        ("P-53", clear(&w, Vec::new(), vec![FieldId::P53])),
        (
            "a field the save sets",
            clear(
                &w,
                vec![narrative_edit("Other narrative", 2)],
                vec![FieldId::ProgrammeNarrative],
            ),
        ),
        (
            "a repeated field",
            clear(
                &w,
                Vec::new(),
                vec![FieldId::ProgrammeNarrative, FieldId::ProgrammeNarrative],
            ),
        ),
    ] {
        assert_eq!(
            w.run(&cmd, M1, &inputs),
            Err(CreatorRefusal::NothingToSave),
            "{what}"
        );
    }
}

/// The codec of a clear: a save without one encodes as before clears
/// existed, with no `clear` member, and a record with no `cleared`
/// member decodes to none. A clear round-trips, and an empty or unsorted
/// set is refused, so each value has one encoding.
#[test]
fn save_fields_clear_codec_keeps_old_encodings() {
    use fstp_programme::FieldId;
    let old = r#"{"kind":"FieldsSaved","programme":"7","revision":{"seq":"1","entry":"1"},"fields":[],"by":"177"}"#;
    let r = crate::decode_record(old.as_bytes()).unwrap();
    assert!(matches!(&r, CreatorRecord::FieldsSaved { cleared, .. } if cleared.is_empty()));
    let back = r.to_json().to_canonical().unwrap();
    assert!(!back.contains("cleared"), "{back}");

    let mut a = FieldId::Minors;
    let mut b = FieldId::ProgrammeNarrative;
    if b < a {
        std::mem::swap(&mut a, &mut b);
    }
    let cmd = CreatorCommand::SaveFields {
        programme: P,
        base: DraftRevision::new(1, Seq::from_raw(1)),
        fields: Vec::new(),
        clear: vec![a, b],
    };
    let text = cmd.to_json().to_canonical().unwrap();
    assert_eq!(crate::decode_command(text.as_bytes()).unwrap(), cmd);
    let none = CreatorCommand::SaveFields {
        programme: P,
        base: DraftRevision::new(1, Seq::from_raw(1)),
        fields: vec![narrative_edit("Synthetic narrative", 1)],
        clear: Vec::new(),
    };
    assert!(!none.to_json().to_canonical().unwrap().contains("clear"));

    let (ka, kb) = (a.key(), b.key());
    for bad in [
        r#"{"kind":"SaveFields","programme":"7","base":{"seq":"1","entry":"1"},"fields":[],"clear":[]}"#.to_owned(),
        format!(
            r#"{{"kind":"SaveFields","programme":"7","base":{{"seq":"1","entry":"1"}},"fields":[],"clear":["{kb}","{ka}"]}}"#
        ),
    ] {
        assert!(crate::decode_command(bad.as_bytes()).is_err(), "{bad}");
    }
}
