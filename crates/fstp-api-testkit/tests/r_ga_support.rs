//! Shared setup of the Guide publication tests (R-GA-01, I-51, I-52, I-53;
//! M4 design section 3.10). Each test binary that needs it includes this
//! file as a module. On its own it holds no test.
//!
//! The world is the Guide world of `fstp_api_testkit::mc::public_model`:
//! programme P1 on the compiled SuperSAFE policy, with call 1 published
//! and call 2 approved. Here the engine decides with a creator
//! environment that supplies the Guide facts of a publication: the
//! shipped Horizon Europe template, the compiled spec, a synthetic data
//! protection summary and SHA-256 through `fstp-crypto`. So the
//! publication of call 1 stores its Guide in the same entry. Every value
//! is synthetic.

#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use fstp_creator::{CreatorCommand, CreatorInputs};
use fstp_domain::command::{Ctx, Via};
use fstp_domain::id::{CallId, CommandId, PolicyVersionId};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{K1, P1, SodSetup, Step, T0, sod_truth};
use fstp_domain_testkit::vault::SyntheticVault;
use fstp_engine::compose::GuideFacts;
use fstp_engine::{CreatorDecider, CreatorEnvironment, Engine, EngineState, NoEnvironment, Record};
use fstp_guide::{HORIZON_EUROPE, ProfileSource, ShippedProfiles, Template};
use fstp_ledger::{MemStore, Seq};
use fstp_programme::Compiled;

/// The published call of the world.
pub(crate) const GUIDE_CALL: CallId = CallId::from_raw(1);
/// The approved call of the world that is not published.
pub(crate) const UNPUBLISHED_CALL: CallId = CallId::from_raw(2);
/// The synthetic data protection summary. Not a privacy notice.
pub(crate) const SUMMARY: &str =
    "Synthetic data protection summary for tests. It is not a privacy notice.";
/// The synthetic privacy statement address.
pub(crate) const PRIVACY: &str = "https://privacy.fstp.example/statement";
/// The synthetic platform address.
pub(crate) const PLATFORM: &str = "https://a.fstp.example/";

/// The shipped Horizon Europe template.
pub(crate) fn shipped_template() -> Template {
    let profile = ShippedProfiles
        .profile(HORIZON_EUROPE)
        .unwrap_or_else(|e| panic!("profile: {e:?}"));
    fstp_guide::parse_template(profile.guide_template().as_bytes())
        .unwrap_or_else(|e| panic!("template: {e}"))
}

/// The compiled SuperSAFE fixture, as the creator would hold it.
pub(crate) fn supersafe_compiled() -> Compiled {
    let fixture = fstp_programme::supersafe_fixture().unwrap_or_else(|e| panic!("{e:?}"));
    fstp_programme::compile(
        &fixture.spec,
        &fstp_programme::FunderProfile::horizon_europe(),
        fstp_programme::CompileIds::new(P1, PolicyVersionId::from_raw(P1.raw()), None),
    )
    .unwrap_or_else(|e| panic!("compile: {e:?}"))
}

/// The creator environment of these tests: no creator fact, and the
/// Guide facts of every publication.
#[derive(Clone, Debug)]
pub(crate) struct GuideEnv {
    /// The template the Guide is bound from.
    pub(crate) template: Template,
    /// The compiled spec the Guide reads its artefacts from.
    pub(crate) compiled: Compiled,
}

impl GuideEnv {
    /// The shipped template over the compiled SuperSAFE fixture.
    pub(crate) fn supersafe() -> GuideEnv {
        GuideEnv {
            template: shipped_template(),
            compiled: supersafe_compiled(),
        }
    }
}

impl CreatorEnvironment for GuideEnv {
    fn creator_inputs(
        &self,
        state: &EngineState,
        cmd: &CreatorCommand,
        ctx: &Ctx,
    ) -> CreatorInputs {
        NoEnvironment.creator_inputs(state, cmd, ctx)
    }

    fn guide_facts(&self, _state: &EngineState, call: CallId) -> Option<GuideFacts> {
        Some(GuideFacts {
            template: self.template.clone(),
            compiled: Some(self.compiled.clone()),
            identifier: call.raw().to_string(),
            platform_url: PLATFORM.to_owned(),
            data_protection_summary: SUMMARY.to_owned(),
            privacy_statement_url: PRIVACY.to_owned(),
            texts: BTreeMap::new(),
            digest: fstp_crypto::sha256,
        })
    }
}

/// The engine of these tests.
pub(crate) type GuideEngine = Engine<MemStore<Record>, SyntheticVault, CreatorDecider<GuideEnv>>;

/// The engine and the count of contexts drawn so far.
#[derive(Clone)]
pub(crate) struct World {
    /// The engine.
    pub(crate) engine: GuideEngine,
    /// The contexts drawn.
    pub(crate) drawn: u64,
}

impl World {
    /// A context for `step` at `now`, with a fresh command id.
    pub(crate) fn ctx(&mut self, step: &Step, now: Timestamp) -> Ctx {
        self.drawn = self.drawn.saturating_add(1);
        let mut id = [0u8; 16];
        let (head, tail) = id.split_at_mut(8);
        head.copy_from_slice(b"guide-tw");
        tail.copy_from_slice(&self.drawn.to_be_bytes());
        Ctx {
            now,
            actor: step.actor,
            command: CommandId::from_bytes(id),
            via: Via::Web,
            tenant_admin: step.flags.tenant_admin,
            second_tenant_admin: step.flags.second_admin,
            binds_tenant_admin: step.flags.binds_tenant_admin,
        }
    }

    /// Runs `step` at [`T0`] through the engine.
    pub(crate) fn run(&mut self, step: &Step) -> Result<Seq, fstp_engine::ExecError> {
        let ctx = self.ctx(step, T0);
        fstp_domain_testkit::activation::run_core(&mut self.engine, &step.cmd, ctx)
    }

    /// The state reached so far.
    pub(crate) fn state(&self) -> &EngineState {
        self.engine.state()
    }

    /// Every entry of the ledger.
    pub(crate) fn entries(&self) -> Vec<fstp_ledger::Entry<Record>> {
        let mut out = Vec::new();
        fstp_ledger::RecordStore::read(self.engine.store(), Seq::ZERO, usize::MAX, &mut out)
            .unwrap_or_else(|e| panic!("store read: {e:?}"));
        out
    }
}

/// The setup steps of the Guide world, without the publication when
/// `publish` is false.
pub(crate) fn setup_steps(compiled: &Compiled, publish: bool) -> Vec<Step> {
    let setup = SodSetup {
        programmes: vec![P1],
        p12: 0,
        p13: [K1].into_iter().collect(),
        calls: vec![(P1, GUIDE_CALL), (P1, UNPUBLISHED_CALL)],
        published: if publish {
            vec![GUIDE_CALL]
        } else {
            Vec::new()
        },
    };
    let mut steps = setup.steps().unwrap_or_else(|e| panic!("{e}"));
    for s in &mut steps {
        if let fstp_domain::Command::CreateProgramme { policy } = &mut s.cmd {
            let p21 = policy.frozen.p21.clone();
            let mut v = compiled.policy.clone();
            v.frozen.p21 = p21;
            **policy = v;
        }
    }
    steps
}

/// The Guide world over `env`, from genesis through production commands,
/// with call 1 published when `publish` is true.
pub(crate) fn world_with(env: GuideEnv, publish: bool) -> World {
    let steps = setup_steps(&env.compiled, publish);
    let engine = Engine::open_with(
        MemStore::new(),
        SyntheticVault::new(sod_truth()),
        CreatorDecider(env),
    )
    .unwrap_or_else(|e| panic!("open: {e:?}"));
    let mut w = World { engine, drawn: 0 };
    for step in &steps {
        w.run(step)
            .unwrap_or_else(|e| panic!("setup step {:?}: {e:?}", step.cmd.kind()));
    }
    w
}

/// The publication step of call `call`.
pub(crate) fn publish_step(call: CallId) -> Step {
    fstp_domain_testkit::r#gen::roster::publish(call)
}
