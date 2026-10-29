//! Review reproducer (lane m4w1b, I-51, D12, NOTE 7): after a tightening and a later loosening, the effective-limits record and enforcement differ.
//!
//! The record's current P-05 is the latest corrigendum's value. NOTE 7
//! enforcement reads the stricter of the snapshot and the live value. A
//! tightening followed by a loosening of the live P-05 raises the enforced
//! cap and appends no corrigendum, so the Guide read with its corrigenda
//! no longer equals the effective limits, which D12 exists to keep (I-51).
//! The setup is copied from `d12_effective_limits_record_tightenings.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)]

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

/// I-51, D12, NOTE 7: the record's current P-05 equals the P-05 that
/// enforcement reads after a tightening and a later loosening.
#[test]
fn review_i51_record_equals_enforcement_after_tighten_then_loosen() {
    let mut w = world(true);
    w.edit(|v| v.live.p05 = eur(30_000_000));
    w.edit(|v| v.live.p05 = eur(45_000_000));
    let limits = effective_limits(&w.state, CALL).unwrap_or_else(|| panic!("no record"));
    let enforced = fstp_domain::policy::effective_p05(&w.state, CALL).unwrap();
    assert_eq!(
        limits.p05(),
        enforced,
        "I-51: the Guide with corrigenda {:?} names {:?}, but enforcement reads {enforced:?}",
        limits.tightenings(),
        limits.p05()
    );
}
