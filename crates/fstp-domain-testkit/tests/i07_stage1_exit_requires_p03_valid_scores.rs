//! I-07 machine: no proposal leaves stage 1 by score without P-03 valid scores (design 6.2).
//!
//! Two proposals, PR1 and PR2, are submitted from genesis under the base
//! P-01 (weights 30, 40 and 30 on a scale of 0 to 4), P-02 75.00 and
//! P-03 = 2. Commands: `Assign`, `DeclareConflict` on assignments and by
//! the coordinator, `RecordKnockOut`, `AdmitToStage1`, `RecordScore` and
//! `CorrectScore`. `CloseStage1` comes from the coordinator, a committee
//! member and the System. `Unassign` and `Withdraw` run from every state.
//! Vault relations between reviewers and leads are processed in the same step.
//! Score vectors favour the exact 75.00% of R-EV-03.
//!
//! The model is the lifecycle reference running alone. Every command is
//! compared with it in both directions, and an accepted lifecycle command
//! must hold the records the reference expects. After every step the
//! system's ledger must replay to its state and extend the previous ledger
//! (I-23). The lifecycle view of the system's own ledger must show I-07,
//! I-08 and sealed scores for every exit from STAGE1 by score, including
//! after withdrawals from STAGE1.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, DeclarationSubject, SystemCause};
use fstp_domain::id::{AccountId, ProposalId};
use fstp_domain::record::Record;
use fstp_domain::scoring::{ScoreKey, Stage};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, L1, L2, PR1, PR2, R1, R2, R3, declare, plan_of, run_records, submit, tag,
    unassign, withdraw,
};
use fstp_domain_testkit::r#gen::roster::{Backend, Step, T0, call};
use fstp_domain_testkit::harness::prop::ledger_step;
use fstp_domain_testkit::mc::life_model::{
    LifeSetup, LifeWorld, T_EVAL, admit, assign_declared, assignment_of, close, correct, knock_out,
    life_judges, score, story_setup,
};
use fstp_domain_testkit::reference::lifecycle::{
    LifeVerdict, LifeView, check_batch, check_i07, check_i08, check_sealed,
};
use fstp_domain_testkit::scenario::Scenario;
use fstp_domain_testkit::vault::Relation;
use fstp_engine::Record as EngineRecord;
use fstp_ledger::Entry;
use fstp_prop::{Config, Gen, StateMachine, check_machine_with, run_machine};

const PROPOSALS: [(AccountId, ProposalId); 2] = [(L1, PR1), (L2, PR2)];
const REVIEWERS: [AccountId; 3] = [R1, R2, R3];

fn vectors() -> [Vec<u8>; 4] {
    [vec![3, 3, 3], vec![4, 4, 4], vec![0, 0, 0], vec![4, 3, 2]]
}

fn setup() -> LifeSetup {
    let mut s = story_setup(
        PROPOSALS.iter().map(|(l, p)| (*l, *p, false)).collect(),
        life_judges(),
    );
    s.scale_max = 4;
    s.weights = vec![30, 40, 30];
    s.p02_bp = 7_500;
    s
}

/// The steps from genesis to both proposals submitted, all at T0.
fn genesis_steps() -> Vec<Step> {
    let mut steps = setup().draft_steps().unwrap();
    for (l, p) in PROPOSALS {
        steps.push(submit(l, p, plan_of(p), false));
    }
    steps
}

#[derive(Clone, Debug)]
enum Cmd {
    /// A core command at `T_EVAL`.
    Core(Box<Step>),
    /// The vault relates the reviewer to the lead, and the reaction runs.
    Relate(AccountId, AccountId),
}

#[derive(Clone, Debug)]
struct Model {
    world: Option<LifeWorld>,
    broken: Option<String>,
}

enum Driver {
    Scenario {
        scenario: Box<Scenario>,
        previous: Vec<Entry<EngineRecord>>,
    },
    World(Box<LifeWorld>),
}

struct Sut {
    driver: Option<Driver>,
    broken: Option<String>,
}

#[derive(Debug)]
enum Output {
    /// The records of an accepted command, or its refusal.
    Done(Result<Vec<Record>, String>),
    /// A harness failure.
    Broken(String),
}

struct Machine {
    backend: Backend,
}

fn key(r: AccountId, p: ProposalId) -> ScoreKey {
    ScoreKey {
        assignment: assignment_of(r, p, call(1), AssignmentKind::Reviewer),
        stage: Stage::One,
        plan: plan_of(p),
    }
}

fn model_step(world: &LifeWorld, cmd: &Cmd) -> Result<Option<LifeWorld>, String> {
    match cmd {
        Cmd::Core(step) => Ok(world.step(step)?.map(|(w, _)| w)),
        Cmd::Relate(r, lead) => {
            let mut w = world.clone();
            w.rev
                .sod
                .truth
                .relate(tag(*r), tag(*lead), Relation::CoWorker);
            w.sync()?;
            Ok(Some(w))
        }
    }
}

fn scenario_records(entries: &[Entry<EngineRecord>]) -> Vec<(Record, Timestamp)> {
    entries
        .iter()
        .filter_map(|e| match &e.record {
            EngineRecord::Core(r) => Some((r.clone(), Timestamp::from_micros(e.at))),
            EngineRecord::Finding(_) | EngineRecord::Creator(_) | EngineRecord::Import(_) => None,
        })
        .collect()
}

fn lifecycle_invariants(view: &LifeView) -> Result<(), String> {
    check_i07(view)?;
    check_i08(view)?;
    check_sealed(view)
}

fn run_scenario(scenario: &mut Scenario, cmd: &Cmd) -> Output {
    match cmd {
        Cmd::Core(step) => match run_records(scenario, step, T_EVAL) {
            Ok(Ok(records)) => Output::Done(Ok(records)),
            Ok(Err(r)) => Output::Done(Err(r.to_string())),
            Err(e) => Output::Broken(e),
        },
        Cmd::Relate(r, lead) => {
            let ctx = scenario.ctx(T_EVAL, Actor::System(SystemCause::Vault));
            let (r, lead) = (*r, *lead);
            match scenario.change_vault(|t| t.relate(tag(r), tag(lead), Relation::CoWorker), ctx) {
                Ok(_) => Output::Done(Ok(Vec::new())),
                Err(e) => Output::Broken(format!("the vault reaction failed: {e:?}")),
            }
        }
    }
}

fn build_sut(backend: Backend) -> Result<Driver, String> {
    match backend {
        Backend::Production => {
            let mut s = Scenario::new(setup().truth()).map_err(|e| format!("{e:?}"))?;
            for step in genesis_steps() {
                if let Err(r) = run_records(&mut s, &step, T0)? {
                    return Err(format!("setup step {:?} refused: {r}", step.cmd.kind()));
                }
            }
            let previous = s.entries().map_err(|e| format!("{e:?}"))?;
            Ok(Driver::Scenario {
                scenario: Box::new(s),
                previous,
            })
        }
        Backend::Reference => {
            let mut w =
                LifeWorld::from_steps(Backend::Reference, setup().truth(), &genesis_steps())?;
            w.set_now(T_EVAL);
            Ok(Driver::World(Box::new(w)))
        }
    }
}

impl StateMachine for Machine {
    type Model = Model;
    type Sut = Sut;
    type Command = Cmd;
    type Output = Output;

    fn init_model(&self) -> Model {
        match LifeWorld::from_steps(Backend::Reference, setup().truth(), &genesis_steps()) {
            Ok(mut w) => {
                w.set_now(T_EVAL);
                Model {
                    world: Some(w),
                    broken: None,
                }
            }
            Err(e) => Model {
                world: None,
                broken: Some(format!("the reference setup failed: {e}")),
            },
        }
    }

    fn init_sut(&self) -> Sut {
        match build_sut(self.backend) {
            Ok(d) => Sut {
                driver: Some(d),
                broken: None,
            },
            Err(e) => Sut {
                driver: None,
                broken: Some(e),
            },
        }
    }

    fn command(&self, g: &mut Gen, model: &Model) -> Cmd {
        let (lead, p) = *g.pick(&PROPOSALS);
        let r = *g.pick(&REVIEWERS);
        let vs = vectors();
        let v = g.pick(&vs).clone();
        let asg = assignment_of(r, p, call(1), AssignmentKind::Reviewer);
        let life = model.world.as_ref().map(|w| &w.life);
        let held = life.and_then(|l| l.assignments.get(&asg)).copied();
        let cleared = life.is_some_and(|l| {
            l.cleared.contains(&(COORDINATOR, p)) || l.facts.contains(&(COORDINATOR, p))
        });
        let mut pick = g.weighted(&[3, 3, 2, 2, 3, 7, 2, 4, 1, 1, 1]);
        // Review commands that the L-REV reference leaves to production are
        // not drawn, so the reference model and the system stay in step.
        let applicable = match pick {
            0 => held.is_none(),
            1 => held.is_some_and(|a| !a.declared && !a.released),
            2 => !cleared,
            8 => held.is_some_and(|a| !a.released),
            _ => true,
        };
        if !applicable {
            pick = 7;
        }
        let step = match pick {
            0 => assign_declared(r, p, call(1), AssignmentKind::Reviewer).swap_remove(0),
            1 => declare(
                r,
                DeclarationSubject::Assignment(asg),
                g.weighted(&[5, 1]) == 1,
                false,
            ),
            2 => declare(COORDINATOR, DeclarationSubject::Proposal(p), false, false),
            3 => knock_out(p, g.weighted(&[4, 1]) == 0),
            4 => admit(p),
            5 => score(r, key(r, p), &v),
            6 => correct(r, key(r, p), &v),
            7 => {
                let actor = match g.weighted(&[6, 1, 1]) {
                    0 => Actor::Account(COORDINATOR),
                    1 => Actor::Account(R1),
                    _ => Actor::System(SystemCause::Timeline),
                };
                close(actor, p)
            }
            8 => unassign(COORDINATOR, asg),
            9 => withdraw(lead, p),
            _ => return Cmd::Relate(r, lead),
        };
        Cmd::Core(Box::new(step))
    }

    fn run(&self, sut: &mut Sut, cmd: &Cmd) -> Output {
        if let Some(b) = &sut.broken {
            return Output::Broken(b.clone());
        }
        match sut.driver.as_mut() {
            None => Output::Broken("no driver".to_owned()),
            Some(Driver::World(w)) => match model_step(w, cmd) {
                Ok(Some(next)) => {
                    **w = next;
                    Output::Done(Ok(Vec::new()))
                }
                Ok(None) => Output::Done(Err("refused".to_owned())),
                Err(e) => Output::Broken(e),
            },
            Some(Driver::Scenario { scenario, previous }) => {
                match scenario.entries() {
                    Ok(e) => *previous = e,
                    Err(e) => return Output::Broken(format!("{e:?}")),
                }
                run_scenario(scenario, cmd)
            }
        }
    }

    fn next_state(&self, model: &mut Model, cmd: &Cmd) {
        let Some(w) = &model.world else {
            return;
        };
        match model_step(w, cmd) {
            Ok(Some(next)) => model.world = Some(next),
            Ok(None) => {}
            Err(e) => model.broken = Some(e),
        }
    }

    fn postcondition(&self, model: &Model, cmd: &Cmd, output: &Output) -> Result<(), String> {
        if let Some(b) = &model.broken {
            return Err(format!("the reference model broke: {b}"));
        }
        let world = model.world.as_ref().ok_or("no reference world")?;
        let accepted = model_step(world, cmd)?.is_some();
        let done = match output {
            Output::Broken(e) => return Err(format!("harness: {e}")),
            Output::Done(d) => d,
        };
        let context = format!("{cmd:?}");
        match (accepted, done) {
            (true, Ok(records)) => {
                if let Cmd::Core(step) = cmd
                    && self.backend == Backend::Production
                    && let LifeVerdict::Accept(exp) | LifeVerdict::Either(exp) =
                        world.life_verdict(step)
                {
                    check_batch(&context, &exp, records)?;
                }
                Ok(())
            }
            (false, Err(_)) => Ok(()),
            (true, Err(r)) => Err(format!(
                "{context}: over-denial, the reference accepts, the system refuses with {r}"
            )),
            (false, Ok(records)) => Err(format!(
                "{context}: over-permission, the reference refuses, the system accepts with {records:?}"
            )),
        }
    }

    fn invariant(&self, model: &Model, sut: &Sut) -> Result<(), String> {
        if let Some(b) = &model.broken {
            return Err(format!("the reference model broke: {b}"));
        }
        if let Some(b) = &sut.broken {
            return Err(format!("the system setup failed: {b}"));
        }
        match &sut.driver {
            None => Err("no driver".to_owned()),
            Some(Driver::World(w)) => lifecycle_invariants(&w.life),
            Some(Driver::Scenario { scenario, previous }) => {
                let current = scenario.entries().map_err(|e| format!("{e:?}"))?;
                ledger_step(previous, &current, scenario.state())?;
                let records = scenario_records(&current);
                let view = LifeView::of(records.iter().map(|(r, t)| (r, *t)))?;
                lifecycle_invariants(&view)
            }
        }
    }

    fn max_commands(&self) -> usize {
        40
    }
}

/// I-07, R-EV-02, NOTE 3: stage 1 exits by score need P-03 valid scores,
/// over random assignments, declarations, scores, corrections, releases,
/// conflicts, closes and withdrawals.
#[test]
fn i07_stage1_exit_requires_p03_valid_scores() {
    let machine = Machine {
        backend: Backend::Production,
    };
    check_machine_with(
        "i07_stage1_exit_requires_p03_valid_scores",
        Config::default().with_cases(48),
        &machine,
    );
}

/// I-07: the same machine with the references as its own system passes.
#[test]
fn i07_stage1_machine_agrees_with_its_reference() {
    let machine = Machine {
        backend: Backend::Reference,
    };
    let outcome = run_machine(
        "i07_stage1_machine_agrees_with_its_reference",
        Config::default().with_cases(48),
        &machine,
    );
    if let Some(f) = outcome.failure() {
        panic!("the reference-backed machine failed: {}", f.message);
    }
}
