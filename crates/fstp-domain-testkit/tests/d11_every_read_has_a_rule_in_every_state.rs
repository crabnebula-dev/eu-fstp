//! R-AC-01, P-10 and R-CF-02: every content read has a rule in every one of the 16 states, and P-75 governs reviewers' reads through MCP (M4 design section 3.4, D11 and D6).
//!
//! D11, Q39 interim reading, pending Daniel: the M2 audit left 1,436 RANKED
//! reads unjudged. Now the review reference judges every read, in every
//! state, for every reader, and production must agree. The applicant team
//! reads in every state. RANKED, DEFERRED, GRANTED, IN_EXECUTION and the
//! terminal states admit the applicant team only. The readers are the
//! lead, the FSTP coordinator, three committee members, two IRC members,
//! the programme manager and an account with no binding.
//!
//! The reads are checked in every state of two exhaustive models:
//! M-LIFECYCLE, which reaches every state up to NEGOTIATION with a havoc
//! vault bit, and M-CONFORMANCE, which reaches all sixteen states. Each
//! run keeps the models' own witnesses, so every state is visited.
//!
//! D6, TH-62, `SPEC/03-architecture/mcp-server.md` Confidentiality: P-75
//! is typed and frozen. Through MCP, a read is refused unless P-75 is on,
//! except for the applicant team, which reads its own proposal through MCP
//! as through the web (I-84). Test-author choice: the refusal is
//! `RuleRef::Param(ParamId::P75)` with `RefusalReason::NotThroughMcp`, as
//! P-77 names its refusal.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::{Command, Via};
use fstp_domain::id::{AccountId, CommandId, PolicyVersionId, ProposalId};
use fstp_domain::oracle::Answers;
use fstp_domain::policy::AgentContentAccess;
use fstp_domain::record::Record;
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::rules::{ParamId, StateTag};
use fstp_domain_testkit::r#gen::money::{LC, PC};
use fstp_domain_testkit::r#gen::policy::next_version;
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, IRC, L1, PR1, R1, R2, R3, ReviewWorld, STRANGER, read,
};
use fstp_domain_testkit::r#gen::roster::{Backend, Flags, P1, STAFF_PM, Step};
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::conformance::{
    ConfState, ConformanceModel, M_CONFORMANCE_STATES, conformance_properties,
};
use fstp_domain_testkit::mc::life_model::{
    IRC2, LifeModel, LifeState, LifeWorld, Story, life_judges, story_setup,
};
use fstp_domain_testkit::mc::lifecycle_model::{
    M_LIFECYCLE_STATES, lifecycle_config, reachability_properties,
};
use fstp_domain_testkit::reference::sod::Verdict;
use fstp_mc::Property;

/// The readers besides the lead.
const READERS: [AccountId; 8] = [COORDINATOR, R1, R2, R3, IRC, IRC2, STAFF_PM, STRANGER];

/// D11: in `rev`, the review reference judges the read of `proposal` by
/// `lead` and every reader of [`READERS`], and production agrees.
fn reads_judged(rev: &ReviewWorld, proposal: ProposalId, lead: AccountId) -> Result<(), String> {
    let state = rev.view.proposals.get(&proposal).map(|l| l.state);
    for reader in READERS.into_iter().chain([lead]) {
        let step = read(reader, proposal);
        let verdict = rev.verdict(&step);
        let production = rev
            .production_outcome(&step)
            .ok_or("D11 runs on production")?;
        match (&verdict, &production) {
            (Verdict::Unjudged, _) => {
                return Err(format!(
                    "D11: the read by {reader:?} in {state:?} has no rule"
                ));
            }
            (Verdict::Accept, Ok(_)) | (Verdict::Refuse(_), Err(_)) => {}
            _ => {
                return Err(format!(
                    "D11: the read by {reader:?} in {state:?}: the reference gives {verdict:?}, \
                     production {production:?}"
                ));
            }
        }
    }
    Ok(())
}

/// D11, R-AC-01, R-CF-02, Q39: on M-LIFECYCLE, every read of PR1 in every
/// state up to NEGOTIATION is judged by the reference, and production
/// agrees, the havoc vault bit included.
#[test]
fn d11_every_read_has_a_rule_up_to_negotiation() {
    let model = LifeModel::new(lifecycle_config(), Backend::Production)
        .unwrap_or_else(|e| panic!("M-LIFECYCLE start from genesis: {e}"));
    let mut properties = reachability_properties::<LifeModel>();
    properties.push(Property::always_with(
        "D11: every read has a rule",
        |s: &LifeState| reads_judged(&s.world.rev, PR1, L1),
    ));
    if let Err(e) = check_exhaustive(&model, &properties, M_LIFECYCLE_STATES) {
        panic!("{e}");
    }
}

/// D11, R-AC-01, R-CF-02, Q39: on M-CONFORMANCE, every read of PC in every
/// one of the sixteen states is judged by the reference, and production
/// agrees.
#[test]
fn d11_every_read_has_a_rule_in_every_state() {
    let model = ConformanceModel::new(true)
        .unwrap_or_else(|e| panic!("M-CONFORMANCE start from genesis: {e}"));
    let mut properties = conformance_properties::<ConformanceModel>();
    properties.push(Property::always_with(
        "D11: every read has a rule",
        |s: &ConfState| reads_judged(&s.world.life.rev, PC, LC),
    ));
    if let Err(e) = check_exhaustive(&model, &properties, M_CONFORMANCE_STATES) {
        panic!("{e}");
    }
}

// ---------------------------------------------------------------------------
// D6: P-75 through MCP
// ---------------------------------------------------------------------------

/// PR1 in STAGE1 with R1 and R2 assigned and declared, under P-75 `p75`.
fn stage1(p75: AgentContentAccess) -> Story {
    let setup = story_setup(vec![(L1, PR1, false)], life_judges());
    let mut steps = setup.draft_steps().unwrap_or_else(|e| panic!("{e}"));
    for s in &mut steps {
        if let Command::CreateProgramme { policy } = &mut s.cmd {
            policy.frozen.p75 = p75;
        }
    }
    let mut s = Story {
        world: LifeWorld::from_steps(Backend::Production, setup.truth(), &steps)
            .unwrap_or_else(|e| panic!("story from genesis: {e}")),
    };
    s.to_stage1(L1, PR1, &[R1, R2])
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Stage1));
    s
}

/// The production outcome of a read of PR1 by `reader` through `via`.
fn read_via(s: &Story, reader: AccountId, via: Via) -> Result<Vec<Record>, Refusal> {
    let w = &s.world.rev.sod;
    let step = read(reader, PR1);
    let mut ctx = step.ctx(w.now, CommandId::from_bytes(*b"test:d6:p75:read"));
    ctx.via = via;
    let queries = fstp_domain::queries(&w.state, &step.cmd, &ctx)?;
    let mut answers = Answers::new();
    for q in queries {
        let a = w.truth.answer(&q);
        answers.insert(q, a);
    }
    fstp_domain::decide(&w.state, &step.cmd, &ctx, &answers)
}

/// The P-75 refusal through MCP (test-author choice).
fn p75_refusal() -> Refusal {
    Refusal::new(RuleRef::Param(ParamId::P75), RefusalReason::NotThroughMcp)
}

/// D6, TH-62: with P-75 off, an assigned reviewer's read through MCP is
/// refused for P-75, while the same read through the web is accepted.
#[test]
fn d6_p75_off_refuses_reviewer_reads_through_mcp() {
    let s = stage1(AgentContentAccess::Off);
    assert!(
        read_via(&s, R1, Via::Web).is_ok(),
        "R-AC-01: the assigned reviewer reads"
    );
    assert_eq!(read_via(&s, R1, Via::Mcp), Err(p75_refusal()));
}

/// D6: with P-75 on, the assigned reviewer's read through MCP is accepted
/// and records exactly what the web read records (I-84).
#[test]
fn d6_p75_on_admits_reviewer_reads_through_mcp() {
    let s = stage1(AgentContentAccess::On);
    let web = read_via(&s, R1, Via::Web).unwrap_or_else(|r| panic!("{r}"));
    let mcp = read_via(&s, R1, Via::Mcp).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(mcp, web);
}

/// D6, I-84, `mcp-server.md` Confidentiality: P-75 governs reviewers'
/// agents only. With P-75 off, the lead reads their own proposal through
/// MCP exactly as through the web.
#[test]
fn d6_applicant_team_reads_through_mcp_with_p75_off() {
    let s = stage1(AgentContentAccess::Off);
    let web = read_via(&s, L1, Via::Web).unwrap_or_else(|r| panic!("{r}"));
    let mcp = read_via(&s, L1, Via::Mcp).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(mcp, web);
}

/// D6, I-12: P-75 is frozen with the call. A head edit to "on" after the
/// call's publication leaves the reviewer's MCP read of a proposal in that
/// call refused.
#[test]
fn d6_p75_is_read_from_the_frozen_call_policy() {
    let mut s = stage1(AgentContentAccess::Off);
    let head = fstp_domain::policy::head(&s.world.rev.sod.state, P1)
        .unwrap_or_else(|| panic!("no head"))
        .clone();
    let next = PolicyVersionId::from_raw(head.id.raw().saturating_add(1_000));
    let mut v = next_version(&head, next);
    v.frozen.p75 = AgentContentAccess::On;
    s.run(&Step::by(
        STAFF_PM,
        Flags::NONE,
        Command::EditPolicy {
            base: head.id,
            version: Box::new(v),
        },
    ))
    .unwrap_or_else(|e| panic!("the programme manager edits the head: {e}"));
    assert_eq!(
        fstp_domain::policy::head(&s.world.rev.sod.state, P1).map(|h| h.frozen.p75),
        Some(AgentContentAccess::On)
    );
    assert_eq!(read_via(&s, R1, Via::Mcp), Err(p75_refusal()));
}
