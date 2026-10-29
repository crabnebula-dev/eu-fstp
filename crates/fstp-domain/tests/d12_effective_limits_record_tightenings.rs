//! I-51 and P-05 and P-13 NOTE 7: each published call keeps a record of its effective limits, the publication snapshot plus every later tightening (M4 design section 3.4, D12, O-52).
//!
//! `SPEC/02-domain/policy-parameters.md` NOTE 7 (decided 2026-10-25,
//! O-52): a change after publication that tightens P-05 or P-13 produces a
//! numbered corrigendum, and each published call keeps a record of its
//! effective limits, from which the corrigenda are generated. Q37 C,
//! interim pending Daniel: the record is built in M4 (D12).
//!
//! Readings of these tests, the strictest the text allows where it is
//! clear:
//!
//! - The record holds the publication snapshot and one numbered
//!   tightening per policy edit that lowers the effective P-05 or adds a
//!   P-13 class, numbered from 1 in edit order. Each tightening names the
//!   edit's version and the effective values after it.
//! - An edit that tightens neither limit appends nothing, a loosening
//!   included.
//! - While the live values only tighten, the record's current values are
//!   the values that enforcement reads, `effective_p05` and
//!   `effective_p13`.
//! - An unpublished call has no record.
//!
//! Open point, not tested here: a loosening after a tightening. NOTE 7
//! makes enforcement read the stricter of the snapshot and the live value,
//! while the record's latest corrigendum names the tightened value. The
//! two then differ, so I-51 needs Daniel's reading there.
//!
//! Each story runs production `queries`, `decide` and `apply` from genesis
//! with a fixed synthetic vault: every account verified with its own
//! identity, every recipient within every cap, and no conflict.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU8, NonZeroU16, NonZeroU32};

use fstp_domain::command::{Actor, Command, Ctx, Via};
use fstp_domain::id::{
    AccountId, BindingId, CallId, ClassId, CommandId, ContentDigest, CriterionId, DecisionId,
    KnockOutCriterionId, LlmConfigId, PolicyVersionId, ProgrammeId, TextId, TextRef,
};
use fstp_domain::oracle::{Answer, Answers, Query};
use fstp_domain::policy::activation::ReportDigest;
use fstp_domain::policy::{
    AgentContentAccess, EffectiveScoreRule, ExclusionClasses, FrozenValues, FunderProfileRef,
    InferenceBinding, IrcExemptions, KnockOutCriteria, KnockOutCriterion, LicenceSet, LiveValues,
    McpBindingActions, ModelRef, OpaqueValue, ParamId, PolicyVersion, ProximityLists, ReadAccess,
    ReviewerAnonymity, SpdxId, TieBreakRule, VotingRules,
};
use fstp_domain::programme::effective_limits;
use fstp_domain::record::Record;
use fstp_domain::refusal::Refusal;
use fstp_domain::roles::{CoolingOff, Role};
use fstp_domain::scoring::{Criteria, Criterion};
use fstp_domain::state::State;
use fstp_domain::time::{Days, Timestamp, ZoneName};
use fstp_ledger::Seq;
use fstp_money::{Amount, AmountRange, Currency, NonNegAmount, Percent};

const P1: ProgrammeId = ProgrammeId::from_raw(1);
const CALL: CallId = CallId::from_raw(1);
const OPENER: AccountId = AccountId::from_raw(1);
const APPROVER: AccountId = AccountId::from_raw(2);
const DRAFTER: AccountId = AccountId::from_raw(3);
const MANAGER: AccountId = AccountId::from_raw(4);
const K1: ClassId = ClassId::from_raw(1);
const K2: ClassId = ClassId::from_raw(2);

fn eur(minor: i64) -> NonNegAmount {
    Amount::from_minor(minor, Currency::Eur)
        .and_then(NonNegAmount::new)
        .unwrap()
}

fn text_ref(n: u128) -> TextRef {
    let mut d = [0u8; 32];
    let (head, _) = d.split_at_mut(16);
    head.copy_from_slice(&n.to_be_bytes());
    TextRef::new(TextId::from_raw(n), ContentDigest::from_bytes(d))
}

fn opaque(s: &str) -> OpaqueValue {
    OpaqueValue::from_value(&fstp_json::Value::String(s.to_owned())).unwrap()
}

/// The frozen parameters without a typed field.
const FROZEN_OPAQUE: [ParamId; 17] = [
    ParamId::P08,
    ParamId::P23,
    ParamId::P25,
    ParamId::P28,
    ParamId::P29,
    ParamId::P30,
    ParamId::P34,
    ParamId::P44,
    ParamId::P55,
    ParamId::P59,
    ParamId::P60,
    ParamId::P61,
    ParamId::P62,
    ParamId::P63,
    ParamId::P64,
    ParamId::P65,
    ParamId::P66,
];

/// The live programme parameters without a typed field.
const LIVE_OPAQUE: [ParamId; 27] = [
    ParamId::P06,
    ParamId::P18,
    ParamId::P19,
    ParamId::P22,
    ParamId::P27,
    ParamId::P31,
    ParamId::P32,
    ParamId::P33,
    ParamId::P35,
    ParamId::P36,
    ParamId::P37,
    ParamId::P40,
    ParamId::P41,
    ParamId::P42,
    ParamId::P43,
    ParamId::P45,
    ParamId::P46,
    ParamId::P47,
    ParamId::P48,
    ParamId::P49,
    ParamId::P50,
    ParamId::P51,
    ParamId::P52,
    ParamId::P54,
    ParamId::P57,
    ParamId::P67,
    ParamId::P76,
];

/// A complete, valid first policy version of P1: P-05 400000.00 EUR, P-13 {K1}.
fn first_version() -> PolicyVersion {
    let two = NonZeroU8::new(2).unwrap();
    let criterion = |id: u128, w: u16| Criterion {
        id: CriterionId::from_raw(id),
        weight: NonZeroU16::new(w).unwrap(),
    };
    PolicyVersion {
        id: PolicyVersionId::from_raw(1),
        programme: P1,
        parent: None,
        currency: Currency::Eur,
        frozen: FrozenValues {
            p01: Criteria::new(
                NonZeroU8::new(4).unwrap(),
                vec![criterion(1, 30), criterion(2, 40), criterion(3, 30)],
            )
            .unwrap(),
            p02: Percent::from_bp(7_500).unwrap(),
            p03: two,
            p04: AmountRange::new(eur(500_000), eur(10_000_000)).unwrap(),
            p07: Days::new(28),
            p09: KnockOutCriteria(vec![KnockOutCriterion {
                id: KnockOutCriterionId::from_raw(1),
                text: text_ref(1_001),
            }]),
            p10: ReadAccess::AssignedReviewersOnly,
            p11: ReviewerAnonymity::Anonymous,
            p14: IrcExemptions(opaque("synthetic P-14")),
            p15: two,
            p16: VotingRules(opaque("synthetic P-16")),
            p17: TieBreakRule(opaque("synthetic P-17")),
            p21: InferenceBinding {
                provider: opaque("synthetic provider"),
                primary: ModelRef("synthetic-model-a".to_owned()),
                fallbacks: Vec::new(),
            },
            p24: EffectiveScoreRule::HigherOfOriginalAndRevised,
            p26: LicenceSet([SpdxId("MIT".to_owned())].into_iter().collect()),
            p39: two,
            p53: FunderProfileRef(opaque("synthetic funder profile")),
            p75: AgentContentAccess::Off,
            p77: McpBindingActions::DraftOnly,
            opaque: FROZEN_OPAQUE
                .iter()
                .map(|p| (*p, opaque(&format!("synthetic {}", p.spec_id()))))
                .collect(),
        },
        live: LiveValues {
            p05: eur(40_000_000),
            p12: CoolingOff(1),
            p13: ExclusionClasses([K1].into_iter().collect()),
            p38: ProximityLists(BTreeMap::new()),
            p56: Some(eur(200_000_000)),
            p58: Some(eur(50_000_000)),
            opaque: LIVE_OPAQUE
                .iter()
                .map(|p| (*p, opaque(&format!("synthetic {}", p.spec_id()))))
                .collect(),
        },
    }
}

/// The production projection with a clock, over the fixed synthetic vault.
struct World {
    state: State,
    now: i64,
    next_version: u128,
}

impl World {
    fn run(&mut self, actor: AccountId, admin: bool, cmd: Command) -> Result<Vec<Record>, Refusal> {
        self.now = self.now.saturating_add(1);
        let ctx = Ctx {
            now: Timestamp::from_micros(self.now),
            actor: Actor::Account(actor),
            command: CommandId::from_bytes(*b"test:d12:limits!"),
            via: Via::Web,
            tenant_admin: admin,
            second_tenant_admin: None,
            binds_tenant_admin: false,
        };
        let mut answers = Answers::new();
        for q in fstp_domain::queries(&self.state, &cmd, &ctx)? {
            let holds = matches!(
                q,
                Query::IsVerified { .. }
                    | Query::WithinRecipientCap { .. }
                    | Query::AllRecipientsWithinCap { .. }
            );
            let accounts = matches!(q, Query::ChangedSince { .. }).then(BTreeSet::new);
            answers.insert(
                q,
                Answer {
                    holds,
                    accounts,
                    epoch: fstp_domain::id::VaultEpoch::GENESIS,
                    digest: ContentDigest::from_bytes([0; 32]),
                },
            );
        }
        let records = fstp_domain::decide(&self.state, &cmd, &ctx, &answers)?;
        for r in &records {
            fstp_domain::apply(&mut self.state, Seq::from_raw(1), ctx.now, r).unwrap();
        }
        Ok(records)
    }

    fn must(&mut self, actor: AccountId, admin: bool, cmd: Command) -> Vec<Record> {
        let kind = cmd.kind();
        self.run(actor, admin, cmd)
            .unwrap_or_else(|r| panic!("{kind:?} by {actor:?} refused: {r}"))
    }

    /// An `EditPolicy` of the head by the manager, changed by `change`.
    /// Returns the new version's id.
    fn edit(&mut self, change: impl FnOnce(&mut PolicyVersion)) -> PolicyVersionId {
        let head = fstp_domain::policy::head(&self.state, P1).unwrap().clone();
        let id = PolicyVersionId::from_raw(self.next_version);
        self.next_version = self.next_version.saturating_add(1);
        let mut v = head.clone();
        v.id = id;
        v.parent = Some(head.id);
        change(&mut v);
        self.must(
            MANAGER,
            false,
            Command::EditPolicy {
                base: head.id,
                version: Box::new(v),
            },
        );
        id
    }

    fn grant(&mut self, binding: u128, account: AccountId, role: Role) {
        self.must(
            OPENER,
            true,
            Command::GrantRole {
                binding: BindingId::from_raw(binding),
                account,
                programme: P1,
                role,
                start: Timestamp::from_micros(self.now.saturating_add(1)),
                second_admin: None,
                confidentiality: Some(text_ref(binding.saturating_add(500))),
                organisation: None,
                end: None,
            },
        );
    }
}

/// P1 created, activated, with a call drafter and a programme manager, and
/// call 1 drafted and approved. With `publish`, the call is published too.
fn world(publish: bool) -> World {
    let mut w = World {
        state: State::genesis(),
        now: 1_000,
        next_version: 2,
    };
    w.must(
        OPENER,
        true,
        Command::CreateProgramme {
            policy: Box::new(first_version()),
        },
    );
    w.must(
        APPROVER,
        true,
        Command::ActivateProgramme {
            programme: P1,
            decision: DecisionId::from_raw(77_001),
            report: ReportDigest::from_bytes([5; 32]),
            revision: 1,
            creator_builders: BTreeSet::new(),
        },
    );
    w.grant(11, DRAFTER, Role::CallDrafter);
    w.grant(12, MANAGER, Role::ProgrammeManager);
    w.must(
        DRAFTER,
        false,
        Command::DraftCall {
            call: CALL,
            programme: P1,
            opens: Timestamp::from_micros(1_000_000_000),
            deadline: Timestamp::from_micros(2_000_000_000),
            deadline_zone: ZoneName::new("Europe/Brussels").unwrap(),
            budget: eur(100_000_000),
            text: text_ref(10_001),
        },
    );
    w.must(
        MANAGER,
        false,
        Command::ApproveCallPublication {
            call: CALL,
            decision: DecisionId::from_raw(1),
        },
    );
    if publish {
        w.must(
            MANAGER,
            false,
            Command::PublishCall {
                call: CALL,
                config: LlmConfigId::from_raw(1),
                config_model: ModelRef("synthetic-model-a".to_owned()),
            },
        );
    }
    w
}

fn classes(c: &[ClassId]) -> ExclusionClasses {
    ExclusionClasses(c.iter().copied().collect())
}

fn nz(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).unwrap()
}

/// D12, NOTE 7: a published call's record starts with its publication
/// snapshot of P-05 and P-13 and no tightening, and its current values
/// are the ones enforcement reads.
#[test]
fn d12_publication_records_the_snapshot() {
    let w = world(true);
    let limits = effective_limits(&w.state, CALL).unwrap_or_else(|| panic!("no record"));
    assert_eq!(limits.publication().p05, eur(40_000_000));
    assert_eq!(limits.publication().p13, classes(&[K1]));
    assert!(limits.tightenings().is_empty());
    assert_eq!(
        limits.p05(),
        fstp_domain::policy::effective_p05(&w.state, CALL).unwrap()
    );
    assert_eq!(
        limits.p13(),
        &fstp_domain::policy::effective_p13(&w.state, CALL).unwrap()
    );
}

/// D12: an unpublished call has no effective-limits record.
#[test]
fn d12_unpublished_call_has_no_record() {
    let w = world(false);
    assert!(effective_limits(&w.state, CALL).is_none());
}

/// D12, NOTE 7, O-52, I-51: a lower P-05 and an added P-13 class after
/// publication each append a numbered tightening that names its version
/// and the effective values after it. The record's current values stay
/// equal to the values enforcement reads.
#[test]
fn d12_tightenings_are_numbered_in_edit_order() {
    let mut w = world(true);
    let lower = w.edit(|v| v.live.p05 = eur(30_000_000));
    let added = w.edit(|v| {
        v.live.p13.0.insert(K2);
    });
    let limits = effective_limits(&w.state, CALL).unwrap_or_else(|| panic!("no record"));
    let got: Vec<(NonZeroU32, PolicyVersionId, NonNegAmount, ExclusionClasses)> = limits
        .tightenings()
        .iter()
        .map(|t| (t.corrigendum, t.version, t.p05, t.p13.clone()))
        .collect();
    assert_eq!(
        got,
        vec![
            (nz(1), lower, eur(30_000_000), classes(&[K1])),
            (nz(2), added, eur(30_000_000), classes(&[K1, K2])),
        ]
    );
    assert_eq!(
        limits.publication().p05,
        eur(40_000_000),
        "the snapshot never changes"
    );
    assert_eq!(
        limits.p05(),
        fstp_domain::policy::effective_p05(&w.state, CALL).unwrap()
    );
    assert_eq!(
        limits.p13(),
        &fstp_domain::policy::effective_p13(&w.state, CALL).unwrap()
    );
    assert_eq!(limits.p05(), eur(30_000_000));
}

/// D12, NOTE 7: an edit that tightens neither limit appends nothing: a
/// higher live P-05, which enforcement does not follow, and a frozen-value
/// edit, which applies to the next call.
#[test]
fn d12_other_edits_append_no_tightening() {
    let mut w = world(true);
    w.edit(|v| v.live.p05 = eur(45_000_000));
    w.edit(|v| {
        v.frozen
            .opaque
            .insert(ParamId::P08, opaque("synthetic P-08 edit"));
    });
    let limits = effective_limits(&w.state, CALL).unwrap_or_else(|| panic!("no record"));
    assert!(
        limits.tightenings().is_empty(),
        "{:?}",
        limits.tightenings()
    );
    assert_eq!(
        limits.p05(),
        eur(40_000_000),
        "NOTE 7: the stricter snapshot holds"
    );
    assert_eq!(
        limits.p05(),
        fstp_domain::policy::effective_p05(&w.state, CALL).unwrap()
    );
}

/// The record's entries as plain tuples.
fn entries(w: &World) -> Vec<(NonZeroU32, PolicyVersionId, NonNegAmount, ExclusionClasses)> {
    effective_limits(&w.state, CALL)
        .unwrap_or_else(|| panic!("no record"))
        .tightenings()
        .iter()
        .map(|t| (t.corrigendum, t.version, t.p05, t.p13.clone()))
        .collect()
}

/// Asserts that the record's current values are the ones enforcement reads.
fn record_equals_enforcement(w: &World) {
    let limits = effective_limits(&w.state, CALL).unwrap_or_else(|| panic!("no record"));
    assert_eq!(
        limits.p05(),
        fstp_domain::policy::effective_p05(&w.state, CALL).unwrap(),
        "I-51: the record's P-05 is the enforced P-05"
    );
    assert_eq!(
        limits.p13(),
        &fstp_domain::policy::effective_p13(&w.state, CALL).unwrap(),
        "I-51: the record's P-13 is the enforced P-13"
    );
}

/// I-51, D12, NOTE 7 (interim, pending Daniel): a live P-05 lowered after
/// publication and then raised above the snapshot appends a second entry
/// at the snapshot value, which NOTE 7 enforcement reads again.
#[test]
fn i51_d12_p05_loosening_after_a_tightening_appends_an_entry() {
    let mut w = world(true);
    let lower = w.edit(|v| v.live.p05 = eur(30_000_000));
    let raised = w.edit(|v| v.live.p05 = eur(45_000_000));
    assert_eq!(
        entries(&w),
        vec![
            (nz(1), lower, eur(30_000_000), classes(&[K1])),
            (nz(2), raised, eur(40_000_000), classes(&[K1])),
        ]
    );
    record_equals_enforcement(&w);
}

/// I-51, D12, NOTE 7 (interim, pending Daniel): a P-13 class added after
/// publication and later removed appends a second entry without it. A
/// removal of a snapshot class changes nothing enforced and appends
/// nothing.
#[test]
fn i51_d12_p13_removal_of_an_added_class_appends_an_entry() {
    let mut w = world(true);
    let added = w.edit(|v| {
        v.live.p13.0.insert(K2);
    });
    let removed = w.edit(|v| {
        v.live.p13.0.remove(&K2);
    });
    w.edit(|v| {
        v.live.p13.0.remove(&K1);
    });
    assert_eq!(
        entries(&w),
        vec![
            (nz(1), added, eur(40_000_000), classes(&[K1, K2])),
            (nz(2), removed, eur(40_000_000), classes(&[K1])),
        ]
    );
    record_equals_enforcement(&w);
}
