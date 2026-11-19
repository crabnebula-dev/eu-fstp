//! R-EV-03 and I-08 through the API interface (M4 design sections 2.1
//! and 8.2, `r_ev_03_exactly_75_percent_does_not_pass_through_the_interface`).
//!
//! The SuperSAFE run uses the 0 to 5 scale of P-01. The Y edge runs in a
//! second programme with the scale changed to 0 to 4, so the SuperSAFE
//! fixture stays as the spec has it (design section 2.1).
//!
//! - P1 stands for the SuperSAFE programme: P-01 weights 30, 40 and 30 on
//!   a scale of 0 to 5.
//! - P2 is the second programme: P-01 weights 30, 40 and 30 on a scale of
//!   0 to 4, P-02 75.00% and P-03 2. Its call 2 is published, and the
//!   committee members R1 and R2 of two organisations judge in it.
//! - Y and X are submitted in call 2, pass the knock-out and are admitted
//!   to stage 1, all from genesis through production commands.
//!
//! Through `ApiCore::dispatch`, each reviewer scores 3 on every criterion
//! of Y, which gives exactly 75.00%. X gets one 4, which gives 80.00%.
//! The coordinator closes stage 1 of both through the route. Y does not
//! pass P-02 and becomes NOT_SELECTED, while X reaches STAGE2.
//!
//! Every account and text is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::num::NonZeroU8;

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::port::{LoginMethod, api_core};
use fstp_api_core::{ApiCore, Credential, OpResult, RequestHead};
use fstp_api_testkit::fake::fixture::World;
use fstp_api_testkit::fake::{FakePorts, FakeVault, port_seams};
use fstp_domain::StateTag;
use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::DeclarationSubject;
use fstp_domain::id::{AccountId, CallId, CommandId, ProposalId};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::policy::criteria;
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, DraftSpec, L1, L2, R1, R2, ReviewSetup, attest_adult_leads, declare,
    judge_binding, plan_of, review_truth,
};
use fstp_domain_testkit::r#gen::roster::{ADMIN, ADMIN_2, K1, P1, P2, SodSetup, Step, T0, call};
use fstp_domain_testkit::mc::life_model::{
    T_EVAL, admit, assign_declared, assignment_of, knock_out, life_judges,
};
use fstp_engine::Engine;
use fstp_json::{Array, Number, ToJson, Value};
use fstp_ledger::MemStore;
use fstp_money::Percent;
use fstp_rt::future::block_on;

/// The published call of the second programme.
const CALL_Y: CallId = call(2);
/// The proposal that scores exactly 75.00%.
const Y: ProposalId = ProposalId::from_raw(21);
/// The control proposal that scores 80.00%.
const X: ProposalId = ProposalId::from_raw(22);

/// The setup: P1 and P2 with one published call each, the life models'
/// judges, and Y and X submitted in call 2.
fn setup() -> ReviewSetup {
    ReviewSetup {
        base: SodSetup {
            programmes: vec![P1, P2],
            p12: 0,
            p13: [K1].into_iter().collect(),
            calls: vec![(P1, call(1)), (P2, CALL_Y)],
            published: vec![call(1), CALL_Y],
        },
        p38: std::collections::BTreeMap::new(),
        p10: fstp_domain::policy::ReadAccess::AssignedReviewersOnly,
        judges: life_judges(),
        drafts: [(L1, Y), (L2, X)]
            .into_iter()
            .map(|(lead, proposal)| DraftSpec {
                lead,
                proposal,
                call: CALL_Y,
                team: Vec::new(),
                minor: false,
                submit: true,
            })
            .collect(),
    }
}

/// The steps from genesis to Y and X submitted, with the policies of P1
/// and P2 and every judge granted in P2.
fn genesis() -> Vec<Step> {
    let s = setup();
    let mut steps = s.steps().unwrap();
    let judges = (0..s.judges.len()).map(judge_binding).collect::<Vec<_>>();
    for step in &mut steps {
        match &mut step.cmd {
            fstp_domain::Command::CreateProgramme { policy } => {
                let scale = if policy.programme == P2 { 4 } else { 5 };
                policy.frozen.p01 = criteria(scale, [30, 40, 30]).unwrap();
                policy.frozen.p02 = Percent::from_bp(7_500).unwrap();
                policy.frozen.p03 = NonZeroU8::new(2).unwrap();
            }
            fstp_domain::Command::GrantRole {
                binding, programme, ..
            } if judges.contains(binding) => *programme = P2,
            _ => {}
        }
    }
    steps
}

/// The steps after the deadline: both proposals reviewed by
/// R1 and R2 with no conflict, declared on by the coordinator, past the knock-out and admitted.
fn evaluation() -> Vec<Step> {
    let mut steps = Vec::new();
    for p in [Y, X] {
        for r in [R1, R2] {
            steps.extend(assign_declared(r, p, CALL_Y, AssignmentKind::Reviewer));
        }
        steps.push(declare(
            COORDINATOR,
            DeclarationSubject::Proposal(p),
            false,
            false,
        ));
        steps.push(knock_out(p, true));
        steps.push(admit(p));
    }
    steps
}

/// The world: the ledger from genesis, the vault facts, and the cell
/// clock an hour after the evaluation steps.
fn world() -> World {
    let s = setup();
    let mut truth = review_truth(s.accounts());
    attest_adult_leads(&mut truth, s.drafts.iter().map(|d| (d.lead, d.minor)));
    let vault = FakeVault::new(truth.clone());
    let mut engine = Engine::open(MemStore::new(), vault.oracle()).unwrap();
    let mut n = 0u32;
    let mut run = |engine: &mut _, step: Step, at: Timestamp| {
        n += 1;
        let mut b = *b"r_ev_03:world:\0\0";
        let k = u16::try_from(n).unwrap().to_be_bytes();
        b[14] = k[0];
        b[15] = k[1];
        let ctx = step.ctx(at, CommandId::from_bytes(b));
        fstp_domain_testkit::activation::run_core(engine, &step.cmd, ctx)
            .unwrap_or_else(|e| panic!("world step {n} {:?}: {e}", step.cmd.kind()));
    };
    for step in genesis() {
        run(&mut engine, step, T0);
    }
    let mut at = T_EVAL;
    for step in evaluation() {
        run(&mut engine, step, at);
        at = Timestamp::from_micros(at.micros() + 1_000_000);
    }
    let (store, _, _) = engine.into_parts();
    World {
        store,
        truth,
        start: Timestamp::from_micros(T_EVAL.micros() + 3_600_000_000),
        admins: [ADMIN, ADMIN_2].into_iter().collect(),
    }
}

/// The cell: fake ports and their API core.
struct Cell {
    ports: FakePorts,
    core: ApiCore,
}

impl Cell {
    fn new() -> Cell {
        let ports = FakePorts::new(&world(), port_seams().unwrap()).unwrap();
        Cell {
            core: api_core(ports.clone()),
            ports,
        }
    }

    /// Sends `method path body` through a passkey web session of `who`.
    fn web(&self, who: AccountId, method: Method, path: &str, body: &Value) -> OpResult {
        let login = self.ports.sessions.login(who, LoginMethod::Passkey);
        let bytes = match body {
            Value::Null => Vec::new(),
            v => v.to_compact().into_bytes(),
        };
        let op = decode_route(method, path, &bytes).unwrap_or_else(|e| panic!("{path}: {e:?}"));
        block_on(self.core.dispatch(
            Credential::SessionCookie(login.cookie),
            &RequestHead::new(),
            op,
        ))
        .unwrap_or_else(|e| panic!("{path}: {}", e.to_json().to_compact()))
    }

    /// The proposal state of `p` in the engine head.
    fn state(&self, p: ProposalId) -> Option<StateTag> {
        fstp_domain::view::proposal_state(&self.ports.engine.state().core, p)
    }
}

/// A score body for the stage 1 plan of `p`.
fn score_body(p: ProposalId, values: [u64; 3]) -> Value {
    let mut o = fstp_json::Object::new();
    let _ = o.insert("plan", Value::String(plan_of(p).raw().to_string()));
    let _ = o.insert("stage", Value::String("One".to_owned()));
    let _ = o.insert(
        "values",
        Value::Array(
            values
                .into_iter()
                .map(|v| Value::Number(Number::from(v)))
                .collect::<Array>(),
        ),
    );
    Value::Object(o)
}

fn done(r: &OpResult, what: &str) {
    assert!(
        matches!(r, OpResult::Done { .. }),
        "{what}: {}",
        r.to_json().to_compact()
    );
}

/// R-EV-03 AC, I-08, M4 design section 8.2: with P-01 weights 30, 40 and
/// 30, the 0 to 4 scale of the second programme and every score 3, Y's
/// weighted score is exactly 75.00%, and Y does not pass a P-02 of 75%
/// when the coordinator closes stage 1 through the interface. X, one
/// point higher, passes, so the close is not vacuous.
#[test]
fn r_ev_03_exactly_75_percent_does_not_pass_through_the_interface() {
    let c = Cell::new();
    assert_eq!(c.state(Y), Some(StateTag::Stage1));
    assert_eq!(c.state(X), Some(StateTag::Stage1));
    let scores = [
        (Y, R1, [3, 3, 3]),
        (Y, R2, [3, 3, 3]),
        (X, R1, [3, 3, 3]),
        (X, R2, [3, 4, 3]),
    ];
    for (p, r, values) in scores {
        let a = assignment_of(r, p, CALL_Y, AssignmentKind::Reviewer);
        let path = format!("/assignments/{}/scores", a.raw());
        let got = c.web(r, Method::Post, &path, &score_body(p, values));
        done(&got, &format!("{r:?} scores {p:?}"));
    }
    for p in [Y, X] {
        let path = format!("/proposals/{}/stage1-close", p.raw());
        let got = c.web(COORDINATOR, Method::Post, &path, &Value::Null);
        done(&got, &format!("the close of {p:?}"));
    }
    assert_eq!(
        c.state(Y),
        Some(StateTag::NotSelected),
        "R-EV-03: exactly 75.00% does not pass a P-02 of 75%"
    );
    assert_eq!(c.state(X), Some(StateTag::Stage2), "80.00% passes");
}
