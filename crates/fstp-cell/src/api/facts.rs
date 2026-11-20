//! The seam through which the API core's engine port gets the shell's
//! facts (ADR-026 record of lane L5, production design gap G13).
//!
//! A creator command and a publication are decided with the facts the
//! cell's shell supplies: the creator facts (probes, Q35 answers) and the
//! Guide inputs of a call. The API core's own creator reads take
//! `AsyncEngine::creator_inputs`. [`ShellFacts`] gives all three.
//!
//! [`BackendFacts`], the default, keeps today's behaviour: the route
//! backend's synchronous `creator_facts` and `guide_inputs`, and no
//! `creator_inputs` of its own, so the API core's default applies
//! (`fstp_engine::NoEnvironment` with the shipped funder profile). Lane L6
//! builds fresh facts on the shell. The lead plugs them in here at merge,
//! through `ApiParts::facts`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use fstp_cell_core::CellState;
use fstp_cell_core::creator::{CreatorFacts, GuideInputs};
use fstp_domain::Ctx;
use fstp_domain::id::CallId;
use fstp_engine::EngineState;
use fstp_rt::Runtime;

use crate::routes::Backend;
use crate::routes::pg::PgBackend;

/// A boxed future of a facts source.
pub(crate) type FactsFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Where the engine port reads the shell's facts (module documentation).
pub(crate) trait ShellFacts: Send + Sync + 'static {
    /// The creator facts `cmd` is decided with on `state`.
    fn creator_facts<'a>(
        &'a self,
        state: &'a CellState,
        cmd: &'a fstp_creator::CreatorCommand,
    ) -> FactsFuture<'a, CreatorFacts>;

    /// The Guide inputs the publication of `call` is decided with on
    /// `state`, or `None` when the shell supplies none.
    fn guide_inputs<'a>(
        &'a self,
        state: &'a CellState,
        call: CallId,
    ) -> FactsFuture<'a, Option<GuideInputs>>;

    /// The creator inputs of the API core's reads of `cmd` on `state`, or
    /// `None` for the API core's default.
    fn creator_inputs(
        &self,
        state: &EngineState,
        cmd: &fstp_creator::CreatorCommand,
        ctx: &Ctx,
    ) -> Option<fstp_creator::CreatorInputs> {
        let _ = (state, cmd, ctx);
        None
    }
}

/// The default source: the route backend's facts, as the cell's command
/// route reads them.
pub(crate) struct BackendFacts<R: Runtime>(pub(crate) Arc<PgBackend<R>>);

impl<R: Runtime> ShellFacts for BackendFacts<R> {
    fn creator_facts<'a>(
        &'a self,
        state: &'a CellState,
        cmd: &'a fstp_creator::CreatorCommand,
    ) -> FactsFuture<'a, CreatorFacts> {
        Box::pin(std::future::ready(self.0.creator_facts(state, cmd)))
    }

    fn guide_inputs<'a>(
        &'a self,
        state: &'a CellState,
        call: CallId,
    ) -> FactsFuture<'a, Option<GuideInputs>> {
        Box::pin(std::future::ready(self.0.guide_inputs(state, call)))
    }
}

/// The API core's default creator inputs (`AsyncEngine::creator_inputs`):
/// no shell fact, and the shipped funder profile the draft names.
pub(crate) fn default_creator_inputs(
    state: &EngineState,
    cmd: &fstp_creator::CreatorCommand,
    ctx: &Ctx,
) -> fstp_creator::CreatorInputs {
    use fstp_guide::ProfileSource as _;
    let mut inputs = fstp_engine::CreatorEnvironment::creator_inputs(
        &fstp_engine::NoEnvironment,
        state,
        cmd,
        ctx,
    );
    inputs.profile = fstp_engine::compose::profile_ref(state, cmd)
        .and_then(|r| fstp_engine::compose::profile_name(&r))
        .and_then(|name| fstp_guide::ShippedProfiles.profile(&name).ok());
    inputs
}

/// The fresh source of a serving cell (lane L4 at the wave 2 merge,
/// ADR-027): the route backend's shell runs its probes in the request
/// (`CreatorShell::facts_fresh`) and reads the Guide's stored texts from
/// the cell's text store (`CreatorShell::guide_fresh`), as the cell's own
/// command route does. With [`crate::shell::ProductionShell`] it gives the
/// same facts as [`BackendFacts`].
pub(crate) struct FreshFacts<R: Runtime>(pub(crate) Arc<PgBackend<R>>);

impl<R: Runtime> ShellFacts for FreshFacts<R> {
    fn creator_facts<'a>(
        &'a self,
        state: &'a CellState,
        cmd: &'a fstp_creator::CreatorCommand,
    ) -> FactsFuture<'a, CreatorFacts> {
        Box::pin(self.0.creator_facts_fresh(state, cmd))
    }

    fn guide_inputs<'a>(
        &'a self,
        state: &'a CellState,
        call: CallId,
    ) -> FactsFuture<'a, Option<GuideInputs>> {
        Box::pin(self.0.guide_inputs_fresh(state, call))
    }
}
