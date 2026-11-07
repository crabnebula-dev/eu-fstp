//! The scenario seeds of the review and applicant specs (`e2e/review`,
//! `e2e/applicant`), built from genesis through production commands.
//!
//! A seed starts from an empty ledger with the synthetic SuperSAFE
//! programme: the `fstp-programme` fixture, compiled under the Horizon
//! Europe profile, with its P-09 wording stored as public texts first, as
//! the creator does (ADR-007). It then runs every command through one of
//! two production paths:
//!
//! - **the API core**, `ApiCore::dispatch` with the actor's session, for
//!   every operation the registry routes and whose texts or projections a
//!   page reads later: the workspace, the submission, scores, ranking
//!   summaries, stage 2 questions and "no questions";
//! - **the engine**, `FakeEngine::environment`, for the commands no page
//!   route reaches in M4: the programme, its activation, role grants,
//!   calls, drafts, plans, assignments, declarations, the knock-out,
//!   admission, the stage 1 close and the cut-off rounds of change D5.
//!
//! Both paths run the domain's guards, so a seed that breaks a rule fails
//! with the refusal. Every persona gets a one-time enrolment link, as the
//! M3 invitation pages take it.
//!
//! Interim readings, pending Daniel and the lead:
//!
//! - The `irc_review` stage records its cut-off round through the engine.
//!   The API core's journal does not know a round recorded so, and
//!   `committee.round` fails closed on it. The committee journeys open,
//!   cast and record their rounds through the API core.
//! - P-01 has no criterion wording in the domain, so the pages label the
//!   criteria by number.

use std::collections::BTreeMap;

use fstp_api_core::decode::{Method as ApiMethod, decode_route};
use fstp_api_core::port::{LoginMethod, TextClass, TextOwner, TextStore};
use fstp_api_core::{Credential, OpResult, RequestHead};
use fstp_api_testkit::fake::fixture::World;
use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Command as Core, DeclarationSubject};
use fstp_domain::decision::Vote;
use fstp_domain::id::{
    AccountId, AssignmentId, BindingId, CallId, CommandId, ContentDigest, DecisionId, LlmConfigId,
    MilestoneId, OrganisationId, PlanVersionId, PolicyVersionId, ProgrammeId, ProposalId, TextId,
    TextRef,
};
use fstp_domain::policy::ModelRef;
use fstp_domain::proposal::{Milestone, PlanOrigin, Task};
use fstp_domain::roles::Role;
use fstp_domain::time::{Timestamp, ZoneName};
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, IRC, L1, L2, L3, L4, O1, O2, O3, R1, R2, R3, R4, assign, declare, tag,
};
use fstp_domain_testkit::r#gen::roster::{
    self, ADMIN, ADMIN_2, Flags, STAFF_DRAFTER, STAFF_PM, Step, add_staff, staff_bindings,
};
use fstp_domain_testkit::mc::life_model::{CHAIR, IRC2, admit, knock_out};
use fstp_domain_testkit::vault::GroundTruth;
use fstp_http::{Request, Response, StatusCode};
use fstp_json::{Array, Object, Value};
use fstp_ledger::MemStore;
use fstp_money::{Amount, Currency, NonNegAmount, PosAmount};

use crate::auth::AuthState;
use crate::control::email;
use crate::wire::{self, dec, obj};
use crate::{Inner, Site, SiteInfo};

/// The SuperSAFE programme of every seed.
const PROGRAMME: ProgrammeId = ProgrammeId::from_raw(1);
/// Its first policy version.
const VERSION: PolicyVersionId = PolicyVersionId::from_raw(1);
/// The call every seed's proposals are in.
const CALL: CallId = CallId::from_raw(1);
/// The later call of NOTE 7, published in the `irc_review` stage.
const FUTURE_CALL: CallId = CallId::from_raw(2);

/// One second, in microseconds.
const SECOND: i64 = 1_000_000;
/// One day, in microseconds.
const DAY: i64 = 86_400 * SECOND;
/// 2026-09-01T08:00:00Z: the programme and its people.
const T_SETUP: i64 = 1_788_249_600 * SECOND;
/// 2026-09-15T00:00:00Z: the call opens.
const CALL_OPENS: i64 = 1_789_430_400 * SECOND;
/// 2026-10-29T11:00:00Z, noon in Brussels: the call deadline.
const DEADLINE: i64 = 1_793_271_600 * SECOND;
/// 2026-10-01T09:00:00Z: the drafts.
const T_DRAFT: i64 = 1_790_845_200 * SECOND;
/// 2026-10-20T09:00:00Z: the submissions.
const T_SUBMIT: i64 = 1_792_486_800 * SECOND;
/// 2026-10-29T13:00:00Z: the evaluation, after the deadline.
const T_EVAL: i64 = 1_793_278_800 * SECOND;
/// 2026-10-30T09:00:00Z: the cell clock once a seed is done.
const T_NOW: i64 = 1_793_350_800 * SECOND;

/// The title of the call every seed's proposals are in.
const CALL_TITLE: &str = "SuperSAFE open call 2026";

/// The P-21 primary model of the SuperSAFE fixture, which a publication pins.
const PRIMARY_MODEL: &str = "placeholder-model";

/// A Judging persona of the review specs (design section 2.1).
struct Persona {
    key: &'static str,
    account: AccountId,
    role: Role,
    organisation: Option<OrganisationId>,
    label: &'static str,
}

/// The cast of the review specs. R1 and R4 share organisation O1 (SoD-10).
const PERSONAS: [Persona; 8] = [
    Persona {
        key: "c1",
        account: COORDINATOR,
        role: Role::FstpCoordinator,
        organisation: None,
        label: "Coordinator C1",
    },
    Persona {
        key: "r1",
        account: R1,
        role: Role::CommitteeMember,
        organisation: Some(O1),
        label: "Committee member R1",
    },
    Persona {
        key: "r2",
        account: R2,
        role: Role::CommitteeMember,
        organisation: Some(O2),
        label: "Committee member R2",
    },
    Persona {
        key: "r3",
        account: R3,
        role: Role::CommitteeMember,
        organisation: Some(O3),
        label: "Committee member R3",
    },
    Persona {
        key: "r4",
        account: R4,
        role: Role::CommitteeMember,
        organisation: Some(O1),
        label: "Committee member R4",
    },
    Persona {
        key: "h1",
        account: CHAIR,
        role: Role::CommitteeChair,
        organisation: Some(O2),
        label: "Committee chair H1",
    },
    Persona {
        key: "i1",
        account: IRC,
        role: Role::IrcMember,
        organisation: None,
        label: "IRC member I1",
    },
    Persona {
        key: "i2",
        account: IRC2,
        role: Role::IrcMember,
        organisation: None,
        label: "IRC member I2",
    },
];

/// The programme manager M1 of every seed (design section 2.1): its key,
/// account and label. Interim, pending Daniel (design section 15.0,
/// 2026-10-31): the demo lists M1 beside the Judging personas, so a
/// person can sign in as the programme manager and reach the creator.
/// The seed grants the role with the staff bindings (`programme`), so M1
/// is not in [`PERSONAS`], whose grants that loop makes.
const PROGRAMME_MANAGER: (&str, AccountId, &str) = ("m1", STAFF_PM, "Programme manager M1");

/// The label of the persona with `key`, such as `Committee member R1`.
fn label_of_key(key: &str) -> &'static str {
    if key == PROGRAMME_MANAGER.0 {
        return PROGRAMME_MANAGER.2;
    }
    PERSONAS
        .iter()
        .find(|p| p.key == key)
        .map_or("", |p| p.label)
}

/// One seeded proposal: its key, id, lead, minor flag and texts.
#[derive(Clone, Copy)]
struct Seeded {
    key: &'static str,
    proposal: ProposalId,
    lead: AccountId,
    minor: bool,
    title: &'static str,
    summary: &'static str,
    /// The requested amount, in cents (ADR-006).
    cents: i64,
}

/// The fifth lead, of proposal u.
const L5: AccountId = AccountId::from_raw(305);

/// The proposals of the review specs (design section 2.1, plus u).
const PROPOSALS: [Seeded; 5] = [
    Seeded {
        key: "x",
        proposal: ProposalId::from_raw(1001),
        lead: L1,
        minor: false,
        title: "Synthetic open sensor kit",
        summary: "A kit of open hardware sensors for air quality readings.",
        cents: 6_000_000,
    },
    Seeded {
        key: "z",
        proposal: ProposalId::from_raw(1002),
        lead: L2,
        minor: false,
        title: "Synthetic closed protocol bridge",
        summary: "A bridge between two proprietary chat protocols.",
        cents: 4_000_000,
    },
    Seeded {
        key: "w",
        proposal: ProposalId::from_raw(1003),
        lead: L3,
        minor: false,
        title: "Synthetic mesh router firmware",
        summary: "Free firmware for community mesh routers.",
        cents: 8_000_000,
    },
    Seeded {
        key: "v",
        proposal: ProposalId::from_raw(1004),
        lead: L4,
        minor: true,
        title: "Synthetic school data vault",
        summary: "A local data store for a school robotics club.",
        cents: 1_500_000,
    },
    Seeded {
        key: "u",
        proposal: ProposalId::from_raw(1005),
        lead: L5,
        minor: false,
        title: "Synthetic offline map tiles",
        summary: "Offline map tiles for disaster response volunteers.",
        cents: 3_000_000,
    },
];

/// The stages of `POST /test/scenario/review` (`e2e/review/contract.ts`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReviewAt {
    Submitted,
    Stage1,
    Stage1Scored,
    Stage2,
    Ranked,
    RankedTie,
    IrcReview,
}

impl ReviewAt {
    fn parse(s: &str) -> Option<ReviewAt> {
        Some(match s {
            "submitted" => ReviewAt::Submitted,
            "stage1" => ReviewAt::Stage1,
            "stage1_scored" => ReviewAt::Stage1Scored,
            "stage2" => ReviewAt::Stage2,
            "ranked" => ReviewAt::Ranked,
            "ranked_tie" => ReviewAt::RankedTie,
            "irc_review" => ReviewAt::IrcReview,
            _ => return None,
        })
    }
}

/// A fresh P-11 handle: random bytes, so no two assignments share one and
/// none names its account (R-AN-01).
fn fresh_handle() -> Result<fstp_domain::id::Handle, String> {
    Ok(fstp_domain::id::Handle::from_bytes(wire::random::<16>()?))
}

/// The plan version of proposal `p`.
fn plan_of(p: ProposalId) -> PlanVersionId {
    PlanVersionId::from_raw(p.raw().saturating_add(5_000))
}

/// The id of the reviewer assignment of `who` on `p`.
fn assignment_of(p: ProposalId, who: AccountId, kind: AssignmentKind) -> AssignmentId {
    let k = u128::from(kind != AssignmentKind::Reviewer);
    AssignmentId::from_raw(
        70_000_000u128
            .saturating_add(p.raw().saturating_mul(10_000))
            .saturating_add(who.raw().saturating_mul(10))
            .saturating_add(k),
    )
}

/// The canary in the content of x (R-CF-02).
const CONTENT_CANARY: &str = "SYNTHETIC-CONTENT-CANARY-7f3a";

/// The deliberation canaries: the round's rationale and tie-break (R-IR-03).
const RATIONALE_CANARY: &str = "SYNTHETIC-DELIBERATION-RATIONALE-91c2";
const TIE_BREAK_CANARY: &str = "SYNTHETIC-DELIBERATION-TIEBREAK-4d8e";

/// The narrative of `s`. The content canary is in x's only.
fn narrative(s: &Seeded) -> String {
    let canary = if s.key == "x" {
        format!(" {CONTENT_CANARY}.")
    } else {
        String::new()
    };
    format!(
        "{} The work plan has three tasks over twelve months.{canary}",
        s.summary
    )
}

/// A domain text reference to `text` stored under `id`.
fn text_ref(id: u128, text: &str) -> TextRef {
    TextRef::new(
        TextId::from_raw(id),
        ContentDigest::from_bytes(fstp_crypto::sha256(text.as_bytes())),
    )
}

/// An EUR amount of `cents`.
fn eur(cents: i64) -> Result<Amount, String> {
    Amount::from_minor(cents, Currency::Eur).map_err(|e| format!("amount: {e:?}"))
}

/// The seeding run over one fresh cell state.
struct Seeder<'a> {
    inner: &'a Inner,
    now: i64,
    command: u32,
    cookies: BTreeMap<AccountId, Vec<u8>>,
}

impl Seeder<'_> {
    /// The next instant: one second later.
    fn tick(&mut self) -> Timestamp {
        self.now = self.now.saturating_add(SECOND);
        Timestamp::from_micros(self.now)
    }

    /// The instant the next step runs at, for a grant that starts with it
    /// (no backdating, design 2.6).
    fn next(&self) -> Timestamp {
        Timestamp::from_micros(self.now.saturating_add(SECOND))
    }

    /// Moves the seed's clock to `t`, if it is later.
    fn at(&mut self, t: i64) {
        if t > self.now {
            self.now = t;
        }
    }

    /// Runs `step` on the engine at the next instant.
    fn step(&mut self, step: &Step) -> Result<(), String> {
        let now = self.tick();
        self.command = self.command.saturating_add(1);
        let mut id = *b"fstp:e2e:seed\0\0\0";
        let n = self.command.to_be_bytes();
        for (slot, b) in id.iter_mut().skip(12).zip(n.iter()) {
            *slot = *b;
        }
        let ctx = step.ctx(now, CommandId::from_bytes(id));
        self.inner
            .ports
            .engine
            .setup_step(&step.cmd, ctx)
            .map(|_| ())
            .map_err(|e| format!("seed step {:?} by {:?}: {e}", step.cmd.kind(), step.actor))
    }

    /// Runs a command by `account` on the engine.
    fn by(&mut self, account: AccountId, cmd: Core) -> Result<(), String> {
        self.step(&Step::by(account, Flags::NONE, cmd))
    }

    /// Calls the API as `account`, with its session, at the next instant.
    async fn api(
        &mut self,
        account: AccountId,
        method: ApiMethod,
        path: &str,
        body: &Value,
    ) -> Result<Value, String> {
        let now = self.tick();
        self.inner.ports.clock.set(now);
        let cookie = match self.cookies.get(&account) {
            Some(c) => c.clone(),
            None => {
                let c = self
                    .inner
                    .ports
                    .sessions
                    .login(account, LoginMethod::Passkey)
                    .cookie;
                self.cookies.insert(account, c.clone());
                c
            }
        };
        let bytes = match body {
            Value::Null => Vec::new(),
            v => v.to_compact().into_bytes(),
        };
        let op = decode_route(method, path, &bytes).map_err(|e| format!("{path}: {e}"))?;
        match self
            .inner
            .core
            .dispatch(Credential::SessionCookie(cookie), &RequestHead::new(), op)
            .await
        {
            Ok(OpResult::Done { body, .. }) => Ok(fstp_json::ToJson::to_json(&body)),
            Ok(other) => Err(format!(
                "{path}: {}",
                fstp_json::ToJson::to_json(&other).to_compact()
            )),
            Err(e) => Err(format!(
                "{path}: {}",
                fstp_json::ToJson::to_json(&e).to_compact()
            )),
        }
    }

    /// Stores `text` as a public text of the programme and returns its
    /// domain reference.
    async fn public_text(&mut self, text: &str) -> Result<TextRef, String> {
        let r = self
            .inner
            .ports
            .texts
            .put(
                TextClass::Public,
                TextOwner::Programme(PROGRAMME),
                text.as_bytes(),
            )
            .await
            .map_err(|e| format!("text: {e:?}"))?;
        Ok(text_ref(r.0, text))
    }

    /// Stores `text` as a confidential text of `p` and returns its
    /// domain reference.
    async fn private_text(&mut self, p: ProposalId, text: &str) -> Result<TextRef, String> {
        let r = self
            .inner
            .ports
            .texts
            .put(
                TextClass::Confidential,
                TextOwner::Proposal(p),
                text.as_bytes(),
            )
            .await
            .map_err(|e| format!("text: {e:?}"))?;
        Ok(text_ref(r.0, text))
    }
}

/// The SuperSAFE policy of the seeds: the compiled fixture, with its P-09
/// wording stored as public texts first (ADR-007).
async fn supersafe(seed: &mut Seeder<'_>) -> Result<fstp_domain::policy::PolicyVersion, String> {
    let fixture = fstp_programme::supersafe_fixture().map_err(|e| format!("fixture: {e:?}"))?;
    let compiled = fstp_programme::compile(
        &fixture.spec,
        &fstp_programme::FunderProfile::horizon_europe(),
        fstp_programme::CompileIds::new(PROGRAMME, VERSION, None),
    )
    .map_err(|e| format!("compile: {e}"))?;
    let mut policy = compiled.policy;
    let wording: BTreeMap<u128, String> = match &fixture.spec.evaluation.p09_knock_outs {
        fstp_programme::Field::Set(k) => k
            .items()
            .iter()
            .map(|c| {
                let text = match &c.text {
                    fstp_programme::Narrative::Inline(s) => s.clone(),
                    fstp_programme::Narrative::Stored(_) => String::new(),
                };
                (c.id.raw(), text)
            })
            .collect(),
        fstp_programme::Field::Unset => return Err("the fixture sets no P-09".to_owned()),
    };
    for k in &mut policy.frozen.p09.0 {
        let text = wording
            .get(&k.id.raw())
            .cloned()
            .ok_or("a P-09 criterion has no wording")?;
        k.text = seed.public_text(&text).await?;
    }
    Ok(policy)
}

/// The vault of the review seeds: staff, personas and leads with their
/// own verified identities, and every lead but v's attested adult.
fn review_truth() -> GroundTruth {
    let mut t = GroundTruth::new();
    add_staff(&mut t);
    for p in &PERSONAS {
        t.set_identity(p.account, tag(p.account));
        t.verify(p.account);
    }
    t.set_identity(GUARDIAN, tag(GUARDIAN));
    t.verify(GUARDIAN);
    t.attest_adult(GUARDIAN, roster::LEAD_ADULT_FROM);
    for s in &PROPOSALS {
        t.set_identity(s.lead, tag(s.lead));
        t.verify(s.lead);
        if !s.minor {
            t.attest_adult(s.lead, roster::LEAD_ADULT_FROM);
        }
    }
    t
}

/// The programme, its activation, staff and Judging grants, and the two
/// calls, the first published with its deadline at `deadline`.
async fn programme(seed: &mut Seeder<'_>, deadline: i64) -> Result<(), String> {
    seed.at(T_SETUP);
    let policy = supersafe(seed).await?;
    seed.step(&Step::by(
        ADMIN,
        Flags::ADMIN,
        Core::CreateProgramme {
            policy: Box::new(policy),
        },
    ))?;
    seed.step(&fstp_domain_testkit::activation::activation_step(PROGRAMME))?;
    let [pm, drafter] = staff_bindings(PROGRAMME);
    seed.step(&roster::grant(
        pm,
        STAFF_PM,
        PROGRAMME,
        Role::ProgrammeManager,
        seed.next(),
    ))?;
    seed.step(&roster::grant(
        drafter,
        STAFF_DRAFTER,
        PROGRAMME,
        Role::CallDrafter,
        seed.next(),
    ))?;
    for (i, p) in (0u128..).zip(PERSONAS.iter()) {
        let mut step = roster::grant(
            BindingId::from_raw(2_000u128.saturating_add(i)),
            p.account,
            PROGRAMME,
            p.role,
            seed.next(),
        );
        if let Core::GrantRole { organisation, .. } = &mut step.cmd {
            *organisation = p.organisation;
        }
        seed.step(&step)?;
    }
    let zone = ZoneName::new("Europe/Brussels").ok_or("zone")?;
    for c in [CALL, FUTURE_CALL] {
        let title = if c == CALL {
            CALL_TITLE
        } else {
            "SuperSAFE open call 2027"
        };
        let text = seed.public_text(title).await?;
        let (opens, deadline) = if c == CALL {
            (CALL_OPENS, deadline)
        } else {
            (
                deadline.saturating_add(30 * DAY),
                deadline.saturating_add(120 * DAY),
            )
        };
        seed.by(
            STAFF_DRAFTER,
            Core::DraftCall {
                call: c,
                programme: PROGRAMME,
                opens: Timestamp::from_micros(opens),
                deadline: Timestamp::from_micros(deadline),
                deadline_zone: zone.clone(),
                budget: NonNegAmount::new(eur(40_000_000)?).map_err(|e| format!("{e:?}"))?,
                text,
            },
        )?;
        seed.by(
            STAFF_PM,
            Core::ApproveCallPublication {
                call: c,
                decision: DecisionId::from_raw(c.raw().saturating_add(100)),
            },
        )?;
    }
    seed.by(STAFF_PM, publish(CALL))?;
    Ok(())
}

/// The publication of `c`, pinned to the P-21 primary model.
fn publish(c: CallId) -> Core {
    Core::PublishCall {
        call: c,
        config: LlmConfigId::from_raw(1),
        config_model: ModelRef(PRIMARY_MODEL.to_owned()),
    }
}

/// Drafts, plans, workspaces and submissions of `which`, each through
/// production: the draft and plan on the engine, the workspace and the
/// submission through the API, as the lead.
async fn submit(seed: &mut Seeder<'_>, which: &[Seeded]) -> Result<(), String> {
    seed.at(T_DRAFT);
    for (i, s) in (0u128..).zip(which.iter()) {
        seed.step(&roster::draft(
            s.lead,
            s.proposal,
            CALL,
            BindingId::from_raw(4_000u128.saturating_add(i)),
            s.minor,
        ))?;
        if s.minor {
            // A minor lead's draft gets its guardian (state-machine NOTE 14).
            seed.step(&roster::add_member(
                s.lead,
                s.proposal,
                GUARDIAN,
                BindingId::from_raw(4_500u128.saturating_add(i)),
                true,
            ))?;
        }
        let milestone = Milestone {
            id: MilestoneId::from_raw(s.proposal.raw().saturating_add(6_000)),
            amount: PosAmount::new(eur(s.cents)?).map_err(|e| format!("{e:?}"))?,
            start: Timestamp::from_micros(DEADLINE.saturating_add(40 * DAY)),
            due: Timestamp::from_micros(DEADLINE.saturating_add(300 * DAY)),
            activity: None,
            deliverables: Vec::new(),
        };
        let content = narrative(s);
        seed.by(
            s.lead,
            Core::RecordPlanVersion {
                plan: plan_of(s.proposal),
                proposal: s.proposal,
                origin: PlanOrigin::Submitted,
                supersedes: None,
                tasks: vec![Task {
                    milestones: vec![milestone],
                }],
                content: ContentDigest::from_bytes(fstp_crypto::sha256(content.as_bytes())),
            },
        )?;
        let id = s.proposal.raw().to_string();
        seed.api(
            s.lead,
            ApiMethod::Put,
            &format!("/proposals/{id}/workspace"),
            &obj(vec![
                ("narrative", content.into()),
                ("summary", s.summary.into()),
                ("title", s.title.into()),
            ]),
        )
        .await?;
    }
    seed.at(T_SUBMIT);
    for s in which {
        let id = s.proposal.raw().to_string();
        seed.api(
            s.lead,
            ApiMethod::Post,
            &format!("/proposals/{id}/submission"),
            &obj(vec![
                (
                    "ethics",
                    obj(vec![
                        ("issues_declared", false.into()),
                        ("text", "No ethics issue.".into()),
                    ]),
                ),
                ("notice", wire::int(1)),
                ("plan", dec(plan_of(s.proposal).raw())),
            ]),
        )
        .await?;
    }
    Ok(())
}

/// The coordinator's declaration, a passed knock-out, the reviewer
/// assignments of `reviewers`, the no-conflict declarations of
/// `declared` and the admission of `s` to stage 1. Admission needs at
/// least P-03 declared, conflict-free reviewers (R-EV-02).
fn admit_with(
    seed: &mut Seeder<'_>,
    s: &Seeded,
    reviewers: &[AccountId],
    declared: &[AccountId],
) -> Result<(), String> {
    seed.at(T_EVAL);
    seed.step(&declare(
        COORDINATOR,
        DeclarationSubject::Proposal(s.proposal),
        false,
        false,
    ))?;
    seed.step(&knock_out(s.proposal, true))?;
    for r in reviewers {
        let a = assignment_of(s.proposal, *r, AssignmentKind::Reviewer);
        seed.step(&assign(
            COORDINATOR,
            a,
            s.proposal,
            *r,
            AssignmentKind::Reviewer,
            Some(fresh_handle()?),
        ))?;
    }
    for r in declared {
        let a = assignment_of(s.proposal, *r, AssignmentKind::Reviewer);
        seed.step(&declare(
            *r,
            DeclarationSubject::Assignment(a),
            false,
            false,
        ))?;
    }
    seed.step(&admit(s.proposal))
}

/// Each reviewer of `reviewers` scores `s` with `values` through the API.
/// Those in `undeclared` first declare no conflict.
async fn score_all(
    seed: &mut Seeder<'_>,
    s: &Seeded,
    reviewers: &[AccountId],
    values: &[u8],
    undeclared: &[AccountId],
) -> Result<(), String> {
    for r in reviewers {
        let a = assignment_of(s.proposal, *r, AssignmentKind::Reviewer);
        if undeclared.contains(r) {
            seed.step(&declare(
                *r,
                DeclarationSubject::Assignment(a),
                false,
                false,
            ))?;
        }
        seed.api(
            *r,
            ApiMethod::Post,
            &format!("/assignments/{}/scores", a.raw()),
            &obj(vec![
                ("plan", dec(plan_of(s.proposal).raw())),
                ("stage", "One".into()),
                (
                    "values",
                    Value::Array(values.iter().map(|v| wire::int(i64::from(*v))).collect()),
                ),
            ]),
        )
        .await?;
    }
    Ok(())
}

/// Takes `s` from STAGE1 to RANKED: the close, a ranking summary by the
/// first reviewer, and "no questions" by every reviewer through the API.
async fn rank(seed: &mut Seeder<'_>, s: &Seeded, reviewers: &[AccountId]) -> Result<(), String> {
    seed.by(
        COORDINATOR,
        Core::CloseStage1 {
            proposal: s.proposal,
        },
    )?;
    let Some(first) = reviewers.first() else {
        return Err("no reviewer".to_owned());
    };
    let a = assignment_of(s.proposal, *first, AssignmentKind::Reviewer);
    seed.api(
        *first,
        ApiMethod::Post,
        &format!("/assignments/{}/ranking-summary", a.raw()),
        &obj(vec![
            ("neutral_summary", s.summary.into()),
            ("rationale", "Clear plan within the call scope.".into()),
            ("title", s.title.into()),
        ]),
    )
    .await?;
    for r in reviewers {
        let a = assignment_of(s.proposal, *r, AssignmentKind::Reviewer);
        seed.api(
            *r,
            ApiMethod::Post,
            &format!("/assignments/{}/no-questions", a.raw()),
            &Value::Null,
        )
        .await?;
    }
    Ok(())
}

/// The proposal of key `k`.
fn proposal(k: &str) -> Result<Seeded, String> {
    PROPOSALS
        .iter()
        .find(|s| s.key == k)
        .copied()
        .ok_or_else(|| format!("no proposal {k}"))
}

/// What a review seed holds per proposal: its assignments.
#[derive(Default)]
struct Held {
    reviewers: BTreeMap<&'static str, BTreeMap<&'static str, AssignmentId>>,
    irc: BTreeMap<&'static str, BTreeMap<&'static str, AssignmentId>>,
    future_call: bool,
    deliberation: Vec<&'static str>,
}

impl Held {
    fn note(&mut self, key: &'static str, reviewers: &[AccountId], kind: AssignmentKind) {
        let s = match proposal(key) {
            Ok(s) => s,
            Err(_) => return,
        };
        let map = match kind {
            AssignmentKind::Irc => &mut self.irc,
            _ => &mut self.reviewers,
        };
        let entry = map.entry(key).or_default();
        for r in reviewers {
            if let Some(p) = PERSONAS.iter().find(|p| p.account == *r) {
                entry.insert(p.key, assignment_of(s.proposal, *r, kind));
            }
        }
    }
}

/// Seeds `stage` (`e2e/review/contract.ts` `ReviewStage`).
async fn seed_review(
    seed: &mut Seeder<'_>,
    stage: ReviewAt,
) -> Result<(Vec<Seeded>, Held), String> {
    let mut held = Held::default();
    programme(seed, DEADLINE).await?;
    let x = proposal("x")?;
    let z = proposal("z")?;
    let w = proposal("w")?;
    let v = proposal("v")?;
    let u = proposal("u")?;
    let both = [R1, R2];
    match stage {
        ReviewAt::Submitted => {
            submit(seed, &[x, z, w, v]).await?;
        }
        ReviewAt::Stage1 | ReviewAt::Stage1Scored => {
            submit(seed, &[x, z, w, v]).await?;
            // R3 and R4 declare at admission, which needs P-03 declared
            // reviewers (R-EV-02), so R1 and R2 still have to declare.
            let four = [R1, R2, R3, R4];
            let early = [R3, R4];
            admit_with(seed, &x, &four, &early)?;
            admit_with(seed, &w, &four, &early)?;
            held.note("x", &four, AssignmentKind::Reviewer);
            held.note("w", &four, AssignmentKind::Reviewer);
            if stage == ReviewAt::Stage1Scored {
                score_all(seed, &x, &four, &[5, 5, 5], &both).await?;
                score_all(seed, &w, &four, &[3, 3, 3], &both).await?;
            }
        }
        ReviewAt::Stage2 => {
            submit(seed, &[x, z, w, v]).await?;
            admit_with(seed, &x, &both, &both)?;
            held.note("x", &both, AssignmentKind::Reviewer);
            score_all(seed, &x, &both, &[5, 5, 5], &[]).await?;
            seed.by(
                COORDINATOR,
                Core::CloseStage1 {
                    proposal: x.proposal,
                },
            )?;
        }
        ReviewAt::Ranked | ReviewAt::RankedTie => {
            let ranked: Vec<(Seeded, [u8; 3])> = if stage == ReviewAt::Ranked {
                vec![(x, [5, 5, 5]), (v, [5, 4, 5]), (w, [4, 4, 4])]
            } else {
                vec![(x, [4, 4, 4]), (w, [4, 4, 4])]
            };
            let all: Vec<Seeded> = ranked.iter().map(|(s, _)| *s).collect();
            submit(seed, &all).await?;
            for (s, values) in &ranked {
                let mut reviewers = vec![R1, R2];
                if s.key == "w" && stage == ReviewAt::Ranked {
                    reviewers.push(R4);
                }
                admit_with(seed, s, &reviewers, &both)?;
                held.note(s.key, &reviewers, AssignmentKind::Reviewer);
                if s.key == "w" && stage == ReviewAt::Ranked {
                    // R4 declares a conflict on w, so R4 is recused (Q16).
                    let a = assignment_of(s.proposal, R4, AssignmentKind::Reviewer);
                    seed.step(&declare(R4, DeclarationSubject::Assignment(a), true, false))?;
                }
                score_all(seed, s, &both, values, &[]).await?;
                rank(seed, s, &both).await?;
            }
        }
        ReviewAt::IrcReview => {
            let ranked = [(x, [5u8, 5, 5]), (v, [5, 4, 5]), (u, [4, 4, 5])];
            let all: Vec<Seeded> = ranked.iter().map(|(s, _)| *s).collect();
            submit(seed, &all).await?;
            for (s, values) in &ranked {
                admit_with(seed, s, &both, &both)?;
                held.note(s.key, &both, AssignmentKind::Reviewer);
                score_all(seed, s, &both, values, &[]).await?;
                rank(seed, s, &both).await?;
            }
            let round = DecisionId::from_raw(9_301);
            let rationale = seed.private_text(x.proposal, RATIONALE_CANARY).await?;
            let tie_break = seed.private_text(x.proposal, TIE_BREAK_CANARY).await?;
            held.deliberation = vec![RATIONALE_CANARY, TIE_BREAK_CANARY];
            seed.by(
                R1,
                Core::OpenCutOffRound {
                    round,
                    call: CALL,
                    order: ranked.iter().map(|(s, _)| s.proposal).collect(),
                    nominated: 3,
                    rationale,
                    tie_breaks: Some(tie_break),
                },
            )?;
            for m in [R1, R2, R3] {
                seed.by(
                    m,
                    Core::CastBallot {
                        round,
                        vote: Vote::For,
                    },
                )?;
            }
            seed.by(R1, Core::RecordCutOff { round })?;
            for (s, _) in &ranked {
                for i in [IRC, IRC2] {
                    let a = assignment_of(s.proposal, i, AssignmentKind::Irc);
                    seed.step(&assign(
                        COORDINATOR,
                        a,
                        s.proposal,
                        i,
                        AssignmentKind::Irc,
                        Some(fresh_handle()?),
                    ))?;
                }
                held.note(s.key, &[IRC, IRC2], AssignmentKind::Irc);
            }
            seed.by(STAFF_PM, publish(FUTURE_CALL))?;
            held.future_call = true;
            return Ok((all, held));
        }
    }
    let seeded = match stage {
        ReviewAt::Ranked => vec![x, v, w],
        ReviewAt::RankedTie => vec![x, w],
        _ => vec![x, z, w, v],
    };
    Ok((seeded, held))
}

/// The JSON of one seeded proposal.
fn proposal_json(inner: &Inner, s: &Seeded, held: &Held) -> Value {
    let state = fstp_domain::view::proposal_state(&inner.ports.engine.state().core, s.proposal)
        .map_or("UNKNOWN", |t| t.spec_name());
    let ids = |m: Option<&BTreeMap<&'static str, AssignmentId>>| {
        let mut o = Object::new();
        for (k, a) in m.into_iter().flatten() {
            let _ = o.insert(*k, dec(a.raw()));
        }
        Value::Object(o)
    };
    obj(vec![
        ("id", dec(s.proposal.raw())),
        ("state", state.into()),
        ("title", s.title.into()),
        ("neutral_summary", s.summary.into()),
        ("assignments", ids(held.reviewers.get(s.key))),
        ("irc_assignments", ids(held.irc.get(s.key))),
    ])
}

/// A fresh seed state: the cell state, each persona's key, enrolment link
/// and login email, and the identity canaries of the leads.
type FreshSeed = (Inner, Vec<Person>, Vec<String>);

/// A persona's key, its one-time enrolment link and its login email.
type Person = (&'static str, String, String);

/// A fresh state for a seed: an empty ledger over the review vault, every
/// persona and lead with a login email and a display handle.
fn fresh_review(info: &SiteInfo) -> Result<FreshSeed, String> {
    let world = World {
        store: MemStore::new(),
        truth: review_truth(),
        start: Timestamp::from_micros(T_SETUP),
        admins: [ADMIN, ADMIN_2].into_iter().collect(),
    };
    let mut auth = AuthState::new(info);
    let mut people = Vec::new();
    for p in &PERSONAS {
        let mail = email(p.key)?;
        auth.person(&mail, p.account);
        let url = auth.invite(p.account)?;
        people.push((p.key, url, mail));
    }
    let (pm_key, pm, _) = PROGRAMME_MANAGER;
    let mail = email(pm_key)?;
    auth.person(&mail, pm);
    let url = auth.invite(pm)?;
    people.push((pm_key, url, mail));
    let mut canaries = Vec::new();
    let mut leads = Vec::new();
    for s in &PROPOSALS {
        let mail = email(&format!("lead-{}", s.key))?;
        auth.person(&mail, s.lead);
        canaries.push(mail);
        leads.push(s.lead);
    }
    let inner = Inner::new(info, &world, auth, PRIMARY_MODEL)?;
    for p in &PERSONAS {
        inner.ports.accounts.name(p.account, p.label);
    }
    inner
        .ports
        .accounts
        .name(PROGRAMME_MANAGER.1, PROGRAMME_MANAGER.2);
    for (s, lead) in PROPOSALS.iter().zip(leads) {
        let name = format!("Synthetic applicant {} Lead-Person", s.key.to_uppercase());
        inner.ports.accounts.name(lead, &name);
        canaries.push(name);
    }
    Ok((inner, people, canaries))
}

/// The label of a review persona or of the programme manager, such as
/// `Committee member R1`.
pub(crate) fn persona_label(account: AccountId) -> Option<&'static str> {
    if account == PROGRAMME_MANAGER.1 {
        return Some(PROGRAMME_MANAGER.2);
    }
    PERSONAS
        .iter()
        .find(|p| p.account == account)
        .map(|p| p.label)
}

/// A fresh cell seeded at review `stage`, for the demo page.
pub(crate) async fn demo_review(site: &Site, name: &str) -> Result<(), String> {
    let stage = ReviewAt::parse(name).ok_or_else(|| "stage".to_owned())?;
    let (inner, _) = build_review(&site.info, stage).await?;
    inner.set_scene(name);
    site.replace(inner);
    Ok(())
}

/// A fresh cell seeded at applicant state `at`, for the demo page.
pub(crate) async fn demo_applicant(site: &Site, name: &str) -> Result<(), String> {
    let at = At::parse(name).ok_or_else(|| "at".to_owned())?;
    let (inner, _) = build_applicant(&site.info, at).await?;
    inner.set_scene(name);
    site.replace(inner);
    Ok(())
}

/// `POST /test/scenario/review {stage}`.
pub(crate) async fn review(site: &Site, req: &Request) -> Response {
    let Some(body) = wire::body(req) else {
        return wire::bad("body");
    };
    let name = wire::str_member(&body, "stage")
        .unwrap_or_default()
        .to_owned();
    let Some(stage) = ReviewAt::parse(&name) else {
        return wire::bad("stage");
    };
    match build_review(&site.info, stage).await {
        Ok((inner, v)) => {
            inner.set_scene(&name);
            site.replace(inner);
            wire::json(StatusCode::OK, &v)
        }
        Err(e) => wire::refuse(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn build_review(info: &SiteInfo, stage: ReviewAt) -> Result<(Inner, Value), String> {
    let (inner, people, canaries) = fresh_review(info)?;
    let mut seed = Seeder {
        inner: &inner,
        now: T_SETUP,
        command: 0,
        cookies: BTreeMap::new(),
    };
    let (seeded, held) = seed_review(&mut seed, stage).await?;
    inner
        .ports
        .clock
        .set(Timestamp::from_micros(T_NOW.max(seed.now)));
    let mut people_o = Object::new();
    for (key, url, _) in &people {
        let label = label_of_key(key);
        let _ = people_o.insert(
            *key,
            obj(vec![
                ("invite_url", url.as_str().into()),
                ("label", label.into()),
            ]),
        );
    }
    let mut proposals = Object::new();
    for s in &seeded {
        let _ = proposals.insert(s.key, proposal_json(&inner, s, &held));
    }
    let criteria: Vec<Value> = (1u128..=3)
        .map(|i| obj(vec![("id", dec(i)), ("max", wire::int(5))]))
        .collect();
    let strings = |v: &[String]| -> Value {
        Value::Array(v.iter().map(|s| Value::from(s.as_str())).collect::<Array>())
    };
    let deliberation: Vec<String> = held.deliberation.iter().map(|s| (*s).to_owned()).collect();
    let v = obj(vec![
        ("programme", dec(PROGRAMME.raw())),
        ("call", dec(CALL.raw())),
        ("future_call", held.future_call.into()),
        ("criteria", Value::Array(criteria.into_iter().collect())),
        (
            "knock_out",
            Value::Array((1u128..=3).map(dec).collect::<Array>()),
        ),
        ("people", Value::Object(people_o)),
        ("proposals", Value::Object(proposals)),
        ("identity_canaries", strings(&canaries)),
        ("deliberation_canaries", strings(&deliberation)),
        ("content_canary", CONTENT_CANARY.into()),
    ]);
    Ok((inner, v))
}

// ---------------------------------------------------------------------------
// The applicant seeds (`e2e/applicant/support.ts` `ScenarioAt`)
// ---------------------------------------------------------------------------

/// Where `POST /test/scenario/applicant {at}` leaves the seeded proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum At {
    OpenCall,
    Stage2,
    IrcReviewMinor,
    Negotiation,
    NotSelected,
    DeferredAfterConcern,
    Ineligible,
}

impl At {
    fn parse(s: &str) -> Option<At> {
        Some(match s {
            "OPEN_CALL" => At::OpenCall,
            "STAGE2" => At::Stage2,
            "IRC_REVIEW_MINOR" => At::IrcReviewMinor,
            "NEGOTIATION" => At::Negotiation,
            "NOT_SELECTED" => At::NotSelected,
            "DEFERRED_AFTER_CONCERN" => At::DeferredAfterConcern,
            "INELIGIBLE" => At::Ineligible,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            At::OpenCall => "OPEN_CALL",
            At::Stage2 => "STAGE2",
            At::IrcReviewMinor => "IRC_REVIEW_MINOR",
            At::Negotiation => "NEGOTIATION",
            At::NotSelected => "NOT_SELECTED",
            At::DeferredAfterConcern => "DEFERRED_AFTER_CONCERN",
            At::Ineligible => "INELIGIBLE",
        }
    }
}

/// The guardian of v's minor lead (state-machine NOTE 14).
const GUARDIAN: AccountId = AccountId::from_raw(401);

/// The deadline of the `OPEN_CALL` seed: 30 minutes after the cell
/// clock's start, so a spec can pass it within one session (P-72).
const OPEN_DEADLINE: i64 = T_NOW + 30 * 60 * SECOND;

/// `t` as an RFC 3339 instant in UTC, to the second.
fn rfc3339(t: i64) -> String {
    let secs = t.div_euclid(SECOND);
    let day = fstp_api_core_day(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!(
        "{day}T{:02}:{:02}:{:02}Z",
        rem.div_euclid(3_600),
        rem.rem_euclid(3_600).div_euclid(60),
        rem.rem_euclid(60)
    )
}

/// The civil date of `days` since 1970-01-01, `YYYY-MM-DD`, on integers.
fn fstp_api_core_day(days: i64) -> String {
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.saturating_sub(era.saturating_mul(146_097));
    let yoe = doe
        .saturating_sub(doe.div_euclid(1_460))
        .saturating_add(doe.div_euclid(36_524))
        .saturating_sub(doe.div_euclid(146_096))
        .div_euclid(365);
    let doy = doe.saturating_sub(
        yoe.saturating_mul(365)
            .saturating_add(yoe.div_euclid(4))
            .saturating_sub(yoe.div_euclid(100)),
    );
    let mp = doy.saturating_mul(5).saturating_add(2).div_euclid(153);
    let d = doy
        .saturating_sub(mp.saturating_mul(153).saturating_add(2).div_euclid(5))
        .saturating_add(1);
    let m = if mp < 10 {
        mp.saturating_add(3)
    } else {
        mp.saturating_sub(9)
    };
    let y = yoe
        .saturating_add(era.saturating_mul(400))
        .saturating_add(i64::from(m <= 2));
    format!("{y:04}-{m:02}-{d:02}")
}

/// Takes the proposals of `ranked` from submission to RANKED, each with
/// R1 and R2 and their scores, then opens, votes and records one cut-off
/// round that nominates all of them, and assigns I1 and I2 to each IRC
/// case. Returns the IRC assignments by proposal.
async fn to_irc(
    seed: &mut Seeder<'_>,
    ranked: &[(Seeded, [u8; 3])],
    held: &mut Held,
) -> Result<(), String> {
    let both = [R1, R2];
    for (s, values) in ranked {
        admit_with(seed, s, &both, &both)?;
        held.note(s.key, &both, AssignmentKind::Reviewer);
        score_all(seed, s, &both, values, &[]).await?;
        rank(seed, s, &both).await?;
    }
    let first = ranked
        .first()
        .map(|(s, _)| s.proposal)
        .ok_or("no proposal")?;
    let round = DecisionId::from_raw(9_301);
    let rationale = seed.private_text(first, RATIONALE_CANARY).await?;
    let tie_break = seed.private_text(first, TIE_BREAK_CANARY).await?;
    held.deliberation = vec![RATIONALE_CANARY, TIE_BREAK_CANARY];
    seed.by(
        R1,
        Core::OpenCutOffRound {
            round,
            call: CALL,
            order: ranked.iter().map(|(s, _)| s.proposal).collect(),
            nominated: u32::try_from(ranked.len()).map_err(|e| e.to_string())?,
            rationale,
            tie_breaks: Some(tie_break),
        },
    )?;
    for m in [R1, R2, R3] {
        seed.by(
            m,
            Core::CastBallot {
                round,
                vote: Vote::For,
            },
        )?;
    }
    seed.by(R1, Core::RecordCutOff { round })?;
    for (s, _) in ranked {
        for i in [IRC, IRC2] {
            let a = assignment_of(s.proposal, i, AssignmentKind::Irc);
            seed.step(&assign(
                COORDINATOR,
                a,
                s.proposal,
                i,
                AssignmentKind::Irc,
                Some(fresh_handle()?),
            ))?;
            seed.step(&declare(i, DeclarationSubject::Assignment(a), false, false))?;
        }
        held.note(s.key, &[IRC, IRC2], AssignmentKind::Irc);
    }
    Ok(())
}

/// Every IRC member of `s` records `verdict` through the API.
async fn irc_verdicts(seed: &mut Seeder<'_>, s: &Seeded, concern: bool) -> Result<(), String> {
    let members: &[AccountId] = if concern { &[IRC] } else { &[IRC, IRC2] };
    for i in members {
        let a = assignment_of(s.proposal, *i, AssignmentKind::Irc);
        let verdict = if concern {
            obj(vec![
                (
                    "concern",
                    "Synthetic concern: the plan is not frugal enough.".into(),
                ),
                ("type", "Concern".into()),
            ])
        } else {
            obj(vec![("type", "Validate".into())])
        };
        seed.api(
            *i,
            ApiMethod::Post,
            &format!("/irc-assignments/{}/review", a.raw()),
            &obj(vec![("verdict", verdict)]),
        )
        .await?;
    }
    Ok(())
}

/// Seeds `at` and returns the seeded proposal, if any, and its questions.
async fn seed_applicant(
    seed: &mut Seeder<'_>,
    at: At,
) -> Result<(Option<Seeded>, Vec<String>, Held), String> {
    let mut held = Held::default();
    let deadline = if at == At::OpenCall {
        OPEN_DEADLINE
    } else {
        DEADLINE
    };
    programme(seed, deadline).await?;
    let x = proposal("x")?;
    let v = proposal("v")?;
    let both = [R1, R2];
    let mut handles = Vec::new();
    let seeded = match at {
        At::OpenCall => None,
        At::Ineligible => {
            submit(seed, &[x]).await?;
            seed.at(T_EVAL);
            seed.step(&declare(
                COORDINATOR,
                DeclarationSubject::Proposal(x.proposal),
                false,
                false,
            ))?;
            seed.step(&knock_out(x.proposal, false))?;
            Some(x)
        }
        At::NotSelected => {
            submit(seed, &[x]).await?;
            admit_with(seed, &x, &both, &both)?;
            score_all(seed, &x, &both, &[3, 3, 3], &[]).await?;
            seed.by(
                COORDINATOR,
                Core::CloseStage1 {
                    proposal: x.proposal,
                },
            )?;
            Some(x)
        }
        At::Stage2 => {
            submit(seed, &[x]).await?;
            admit_with(seed, &x, &both, &both)?;
            score_all(seed, &x, &both, &[5, 5, 5], &[]).await?;
            seed.by(
                COORDINATOR,
                Core::CloseStage1 {
                    proposal: x.proposal,
                },
            )?;
            for (r, q) in [
                (R1, "Synthetic question: which sensors are in the kit?"),
                (R2, "Synthetic question: who maintains the firmware?"),
            ] {
                let a = assignment_of(x.proposal, r, AssignmentKind::Reviewer);
                seed.api(
                    r,
                    ApiMethod::Post,
                    &format!("/assignments/{}/questions", a.raw()),
                    &obj(vec![("text", q.into())]),
                )
                .await?;
                let state = seed.inner.ports.engine.state();
                if let Some(h) = state.core.review().get(a).and_then(|x| x.handle) {
                    let b = h.bytes();
                    let head: Vec<u8> = b.iter().take(4).copied().collect();
                    handles.push(format!("R-{}", wire::hex(&head)));
                }
            }
            Some(x)
        }
        At::Negotiation => {
            submit(seed, &[x]).await?;
            to_irc(seed, &[(x, [5, 5, 5])], &mut held).await?;
            irc_verdicts(seed, &x, false).await?;
            Some(x)
        }
        At::DeferredAfterConcern => {
            submit(seed, &[x]).await?;
            to_irc(seed, &[(x, [5, 5, 5])], &mut held).await?;
            seed.by(STAFF_PM, publish(FUTURE_CALL))?;
            irc_verdicts(seed, &x, true).await?;
            Some(x)
        }
        At::IrcReviewMinor => {
            seed.at(T_DRAFT);
            submit(seed, &[v]).await?;
            to_irc(seed, &[(v, [5, 4, 5])], &mut held).await?;
            irc_verdicts(seed, &v, false).await?;
            Some(v)
        }
    };
    Ok((seeded, handles, held))
}

/// `POST /test/scenario/applicant {at}`.
pub(crate) async fn applicant(site: &Site, req: &Request) -> Response {
    let Some(body) = wire::body(req) else {
        return wire::bad("body");
    };
    let name = wire::str_member(&body, "at").unwrap_or_default().to_owned();
    let Some(at) = At::parse(&name) else {
        return wire::bad("at");
    };
    match build_applicant(&site.info, at).await {
        Ok((inner, v)) => {
            inner.set_scene(&name);
            site.replace(inner);
            wire::json(StatusCode::OK, &v)
        }
        Err(e) => wire::refuse(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn build_applicant(info: &SiteInfo, at: At) -> Result<(Inner, Value), String> {
    let (inner, people, _canaries) = fresh_review(info)?;
    let mut seed = Seeder {
        inner: &inner,
        now: T_SETUP,
        command: 0,
        cookies: BTreeMap::new(),
    };
    let (seeded, handles, _held) = seed_applicant(&mut seed, at).await?;
    inner
        .ports
        .clock
        .set(Timestamp::from_micros(T_NOW.max(seed.now)));
    let deadline = if at == At::OpenCall {
        OPEN_DEADLINE
    } else {
        DEADLINE
    };
    let until = deadline
        .saturating_sub(inner.ports.clock.read().micros())
        .max(1);
    let call = obj(vec![
        ("id", dec(CALL.raw())),
        ("title", CALL_TITLE.into()),
        ("deadline", rfc3339(deadline).into()),
        ("time_zone", "Europe/Brussels".into()),
        (
            "amounts",
            Value::Array(
                ["400000.00", "5000.00", "100000.00"]
                    .iter()
                    .map(|a| Value::from(*a))
                    .collect::<Array>(),
            ),
        ),
        ("until_deadline_micros", wire::int(until)),
    ]);
    let mut auth = lock_auth(&inner);
    let person = |auth: &mut AuthState, account: AccountId, tag: &str| -> Result<Value, String> {
        let mail = email(tag)?;
        auth.person(&mail, account);
        let url = auth.invite(account)?;
        Ok(obj(vec![("email", mail.into()), ("enrol_url", url.into())]))
    };
    let (proposal_v, title_v, lead_v) = match &seeded {
        Some(s) => (
            dec(s.proposal.raw()),
            Value::from(s.title),
            person(&mut auth, s.lead, &format!("lead-{}-self", s.key))?,
        ),
        None => (Value::Null, Value::Null, Value::Null),
    };
    let guardian_v = if at == At::IrcReviewMinor {
        person(&mut auth, GUARDIAN, "guardian")?
    } else {
        Value::Null
    };
    let stage2_v = if at == At::Stage2 {
        let mut hidden = Vec::new();
        for p in PERSONAS.iter().filter(|p| matches!(p.key, "r1" | "r2")) {
            hidden.push(Value::from(p.label));
            hidden.push(dec(p.account.raw()));
            if let Some((_, _, mail)) = people.iter().find(|(k, _, _)| *k == p.key) {
                hidden.push(Value::from(mail.as_str()));
            }
        }
        obj(vec![
            (
                "handles",
                Value::Array(
                    handles
                        .iter()
                        .map(|h| Value::from(h.as_str()))
                        .collect::<Array>(),
                ),
            ),
            (
                "hidden",
                Value::Array(hidden.into_iter().collect::<Array>()),
            ),
        ])
    } else {
        Value::Null
    };
    drop(auth);
    let v = obj(vec![
        ("at", at.name().into()),
        ("call", call),
        ("proposal", proposal_v),
        ("title", title_v),
        ("lead", lead_v),
        ("guardian", guardian_v),
        ("stage2", stage2_v),
    ]);
    Ok((inner, v))
}

/// The M3 records of `inner`, locked.
fn lock_auth(inner: &Inner) -> std::sync::MutexGuard<'_, AuthState> {
    inner
        .auth
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use fstp_rt::future::block_on;

    fn info() -> SiteInfo {
        SiteInfo {
            name: "a",
            host: "a.fstp.localhost".to_owned(),
            origin: "http://a.fstp.localhost:8640".to_owned(),
            control: "http://127.0.0.1:8641".to_owned(),
            assets: fstp_web_assets::AssetSet::from_files("main.js", &[("main.js", b"export {};")])
                .unwrap(),
            auth_assets: std::sync::Arc::new(crate::assets::AuthAssets::empty()),
            demo_signin: false,
        }
    }

    fn state_of(v: &Value, key: &str) -> String {
        v.get("proposals")
            .and_then(|p| p.get(key))
            .and_then(|p| p.get("state"))
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("no state of {key} in {}", v.to_compact()))
            .to_owned()
    }

    /// R-EV-02, R-EV-08, R-IR-01 and NOTE 7 (design sections 2.2 J5 to J8):
    /// every review seed builds from genesis through production commands
    /// and leaves its proposals in the states the review specs read.
    #[test]
    fn r_ev_02_review_seeds_reach_their_states() {
        let want: [(ReviewAt, &[(&str, &str)]); 7] = [
            (
                ReviewAt::Submitted,
                &[("x", "SUBMITTED"), ("z", "SUBMITTED")],
            ),
            (ReviewAt::Stage1, &[("x", "STAGE1"), ("w", "STAGE1")]),
            (ReviewAt::Stage1Scored, &[("x", "STAGE1"), ("w", "STAGE1")]),
            (ReviewAt::Stage2, &[("x", "STAGE2")]),
            (
                ReviewAt::Ranked,
                &[("x", "RANKED"), ("v", "RANKED"), ("w", "RANKED")],
            ),
            (ReviewAt::RankedTie, &[("x", "RANKED"), ("w", "RANKED")]),
            (
                ReviewAt::IrcReview,
                &[
                    ("x", "IRC_REVIEW"),
                    ("v", "IRC_REVIEW"),
                    ("u", "IRC_REVIEW"),
                ],
            ),
        ];
        for (stage, states) in want {
            let (_, v) =
                block_on(build_review(&info(), stage)).unwrap_or_else(|e| panic!("{stage:?}: {e}"));
            for (key, tag) in states {
                assert_eq!(state_of(&v, key), *tag, "{stage:?}: {key}");
            }
        }
    }

    /// R-EV-02 (design sections 2.2 J1 and J6, 15.0 of 2026-10-31): every
    /// review seed invites the programme manager M1 under its label, and
    /// the demo page's line for each person says what they can do in the
    /// scene. In stage1, R1 has two review assignments to declare first.
    #[test]
    fn r_ev_02_review_seed_lists_m1_and_says_what_each_person_can_do() {
        let (inner, v) = block_on(build_review(&info(), ReviewAt::Stage1)).unwrap();
        let m1 = v.get("people").and_then(|p| p.get("m1")).unwrap();
        assert_eq!(
            m1.get("label").and_then(Value::as_str),
            Some("Programme manager M1")
        );
        let invited: Vec<AccountId> = lock_auth(&inner)
            .open_invites()
            .into_iter()
            .map(|(a, _)| a)
            .collect();
        assert!(invited.contains(&STAFF_PM), "M1 has a sign-in link");
        assert_eq!(persona_label(STAFF_PM), Some("Programme manager M1"));
        // Under strict D2e the seeded programme is activated through the
        // creator, so it holds a draft and both creator pages read it.
        let pm = crate::demo::what_they_can_do(&inner, STAFF_PM);
        assert_eq!(
            pm,
            "Programme manager: the programme set-up and people pages of the programme, and its call boards."
        );
        let r1 = crate::demo::what_they_can_do(&inner, R1);
        assert!(
            r1.contains("2 review assignments to work on, 2 to declare first"),
            "{r1}"
        );
        let i1 = crate::demo::what_they_can_do(&inner, IRC);
        assert_eq!(i1, "IRC member: no IRC case in this scene.");
    }

    /// R-EV-02, R-IR-02 (design section 15.0 of 2026-10-31; review
    /// findings U1 to U4): the demo line of each person promises only
    /// pages that open. Finished review assignments and decided IRC
    /// cases are counted as finished, the chair line names no cut-off
    /// round, and the programme manager is sent to the creator pages only
    /// when the programme holds a draft. Under strict D2e every seeded
    /// programme holds one.
    #[test]
    fn r_ev_02_demo_lines_promise_only_pages_that_open() {
        let (ranked, _) = block_on(build_review(&info(), ReviewAt::Ranked)).unwrap();
        let r1 = crate::demo::what_they_can_do(&ranked, R1);
        assert!(
            r1.starts_with("Committee member: no review assignment open in this scene ("),
            "{r1}"
        );
        assert!(!r1.contains("to work on"), "{r1}");
        let h1 = crate::demo::what_they_can_do(&ranked, CHAIR);
        assert!(!h1.contains("cut-off"), "{h1}");
        let pm = crate::demo::what_they_can_do(&ranked, STAFF_PM);
        assert!(
            ranked
                .ports
                .engine
                .state()
                .creator
                .draft(PROGRAMME)
                .is_some()
                && pm.contains("set-up"),
            "{pm}"
        );
        let (irc, _) = block_on(build_review(&info(), ReviewAt::IrcReview)).unwrap();
        let i1 = crate::demo::what_they_can_do(&irc, IRC);
        assert!(i1.contains(" to work on, "), "{i1}");
        let (neg, _) = block_on(build_applicant(&info(), At::Negotiation)).unwrap();
        let i1 = crate::demo::what_they_can_do(&neg, IRC);
        assert!(
            i1.starts_with("IRC member: no IRC case open in this scene ("),
            "{i1}"
        );
        let r1 = crate::demo::what_they_can_do(&neg, R1);
        assert!(!r1.contains("to work on"), "{r1}");
    }

    /// R-SB-02, R-EV-04, R-IR-02, R-NG-06 and I-18 (design section 2.2 J4):
    /// every applicant seed builds from genesis through production
    /// commands, and the seeded proposal is in the state its name says.
    #[test]
    fn r_sb_02_applicant_seeds_reach_their_states() {
        let want = [
            (At::Stage2, "STAGE2"),
            (At::IrcReviewMinor, "IRC_REVIEW"),
            (At::Negotiation, "NEGOTIATION"),
            (At::NotSelected, "NOT_SELECTED"),
            (At::DeferredAfterConcern, "DEFERRED"),
            (At::Ineligible, "INELIGIBLE"),
        ];
        for (at, tag) in want {
            let (inner, v) =
                block_on(build_applicant(&info(), at)).unwrap_or_else(|e| panic!("{at:?}: {e}"));
            let p = v
                .get("proposal")
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or_else(|| panic!("{at:?}: no proposal"));
            let state = fstp_domain::view::proposal_state(
                &inner.ports.engine.state().core,
                ProposalId::from_raw(p),
            );
            assert_eq!(state.map(|t| t.spec_name()), Some(tag), "{at:?}");
        }
        let (_, open) = block_on(build_applicant(&info(), At::OpenCall)).unwrap();
        assert!(open.get("proposal").is_some_and(Value::is_null));
    }

    /// The seeded proposal of an applicant scene.
    fn seeded_proposal(v: &Value) -> ProposalId {
        let p = v
            .get("proposal")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or_else(|| panic!("no proposal in {}", v.to_compact()));
        ProposalId::from_raw(p)
    }

    /// The lead of the seeded proposal `p`.
    fn lead_of(inner: &Inner, p: ProposalId) -> AccountId {
        inner
            .ports
            .engine
            .state()
            .core
            .roster()
            .bindings()
            .map(|(_, b)| *b)
            .find(|b| b.role == Role::Applicant && b.proposal() == Some(p))
            .map(|b| b.account)
            .unwrap_or_else(|| panic!("no lead of {p:?}"))
    }

    /// A seeding run over `inner`, resumed at the cell clock.
    fn seeder(inner: &Inner) -> Seeder<'_> {
        Seeder {
            inner,
            now: inner.ports.clock.read().micros(),
            command: 1_000,
            cookies: BTreeMap::new(),
        }
    }

    /// R-EV-05, NOTE 1 (design section 2.2 J4): in stage 2 the lead
    /// submits a revised plan through one call. The page form records the
    /// plan version of origin "stage 2 revision" and submits it as the
    /// revision in one ledger entry: both records carry the same command
    /// id, and nothing else is in that entry. The reply names the plan and
    /// its total, and the proposal stays in STAGE2.
    #[test]
    fn r_ev_05_stage2_revision_is_one_entry() {
        use fstp_api_core::port::AsyncEngine;
        use fstp_domain::record::Record as CoreRecord;
        let (inner, v) = block_on(build_applicant(&info(), At::Stage2)).unwrap();
        let p = seeded_proposal(&v);
        let lead = lead_of(&inner, p);
        let milestone = obj(vec![
            ("amount", "1800.00".into()),
            ("start", "2027-03-01".into()),
            ("due", "2027-06-30".into()),
        ]);
        let task = obj(vec![(
            "milestones",
            Value::Array(vec![milestone].into_iter().collect::<Array>()),
        )]);
        let form = obj(vec![
            ("description", "A synthetic revised work plan.".into()),
            (
                "tasks",
                Value::Array(vec![task].into_iter().collect::<Array>()),
            ),
        ]);
        let mut seed = seeder(&inner);
        let reply = block_on(seed.api(
            lead,
            ApiMethod::Post,
            &format!("/proposals/{}/stage2/revision", p.raw()),
            &form,
        ))
        .unwrap_or_else(|e| panic!("the revision: {e}"));
        assert_eq!(
            reply.get("total").and_then(Value::as_str),
            Some("1800.00"),
            "{}",
            reply.to_compact()
        );
        let plan = reply
            .get("plan")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u128>().ok())
            .map(PlanVersionId::from_raw)
            .unwrap_or_else(|| panic!("no plan in {}", reply.to_compact()));
        let ledger = inner.ports.engine.ledger().unwrap();
        let core = |r: &fstp_engine::Record| match r {
            fstp_engine::Record::Core(c) => Some(c.clone()),
            _ => None,
        };
        let submitted = ledger
            .iter()
            .find(|e| {
                matches!(core(&e.record), Some(CoreRecord::RevisionSubmitted { plan: x, proposal })
                    if x == plan && proposal == p)
            })
            .unwrap_or_else(|| panic!("no RevisionSubmitted of {plan:?}"));
        let entry: Vec<_> = ledger
            .iter()
            .filter(|e| e.command == submitted.command)
            .collect();
        assert_eq!(entry.len(), 2, "one entry of two records: {entry:?}");
        assert!(
            matches!(core(&entry[0].record), Some(CoreRecord::PlanVersionRecorded(r))
                if r.plan == plan && r.proposal == p && r.origin == PlanOrigin::Stage2Revision),
            "the plan comes first: {entry:?}"
        );
        assert_eq!(entry[1].seq, submitted.seq);
        let state = fstp_domain::view::proposal_state(&inner.ports.engine.state().core, p);
        assert_eq!(state.map(|t| t.spec_name()), Some("STAGE2"));
    }

    /// I-18, R-NG-01 NOTE and state-machine NOTE 14: the guardian of a
    /// minor-flagged proposal in IRC_REVIEW starts the consent on the
    /// vault origin. The reply is the vault's write page on
    /// `id.<cell host>`, with a ticket in the fragment and no query. The
    /// vault starts a guardian consent verification of that proposal. The
    /// lead cannot start it, and the proposal waits in IRC_REVIEW.
    #[test]
    fn i18_guardian_consent_runs_on_the_vault_origin_and_the_proposal_waits() {
        use fstp_api_core::port::VerificationPurpose;
        let (inner, v) = block_on(build_applicant(&info(), At::IrcReviewMinor)).unwrap();
        let p = seeded_proposal(&v);
        let lead = lead_of(&inner, p);
        let mut seed = seeder(&inner);
        let path = format!("/proposals/{}/guardian/consent", p.raw());
        let refused = block_on(seed.api(lead, ApiMethod::Post, &path, &obj(vec![])));
        assert!(refused.is_err(), "the lead starts no consent: {refused:?}");
        let reply = block_on(seed.api(GUARDIAN, ApiMethod::Post, &path, &obj(vec![])))
            .unwrap_or_else(|e| panic!("the guardian: {e}"));
        let to = reply
            .get("redirect")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("no redirect in {}", reply.to_compact()));
        let ticket = to
            .strip_prefix("http://id.a.fstp.localhost:8640/w#")
            .unwrap_or_else(|| panic!("not the vault write page: {to}"));
        assert!(
            !ticket.is_empty() && !ticket.contains(['?', '#', '/']),
            "{to}"
        );
        assert_eq!(
            inner.ports.vault.verifications(),
            vec![(VerificationPurpose::GuardianConsent(p), GUARDIAN)]
        );
        let state = fstp_domain::view::proposal_state(&inner.ports.engine.state().core, p);
        assert_eq!(state.map(|t| t.spec_name()), Some("IRC_REVIEW"));
    }
}
