//! The creator shell of a cell (M4 design section 3.2, lane F-CYCLE2;
//! ADR-027).
//!
//! A creator command reads facts that only the shell holds
//! (`fstp_cell_core::creator`): the probes, the Q35 answers, the ports and
//! the funder profile. The route reads them through [`CreatorShell`] when
//! it admits the command, and hands them to the decision as route inputs.
//! The route asks for fresh facts ([`CreatorShell::facts_fresh`],
//! [`CreatorShell::guide_fresh`]), so a shell can run its probes and read
//! the text store in the request.
//!
//! [`ProductionShell`] is the shell of a cell started without settings:
//!
//! - No prober runs, so every probe is absent. The channel and sending
//!   domain checks then report a failure (Q5, interim, pending Daniel),
//!   and no programme activates.
//! - It gives no Q35 answer of its own, so the cell's decision asks the
//!   vault (`fstp_cell_core::creator::q35_queries`, ADR-027).
//! - The cell has no pre-check provider and no score tools.
//! - The funder profile comes from the shipped profiles only (rule A9b).
//!   Their legal wording is pending (Q6), so the creator reports
//!   `LegalWordingPending` until Daniel approves it.
//! - It supplies no Guide inputs, so a publication is refused with I-52
//!   (D2e strict, Daniel's decision of 2026-11-15).
//!
//! [`facts::FactsShell`] is the shell of a configured serving cell
//! ([`facts::production_shell`]): it runs the probes of [`probe`] and
//! supplies the Guide inputs. A test world passes a shell of its own
//! through `crate::process::StartOptions`, and says so in its claims.

pub mod dns;
pub mod facts;
pub mod mailauth;
pub mod probe;

use std::future::Future;
use std::pin::Pin;

use fstp_cell_core::CellState;
use fstp_cell_core::creator::{CreatorFacts, GuideInputs};
use fstp_creator::{CreatorCommand, PortPresence, ProbeSet};
use fstp_domain::id::CallId;
use fstp_guide::ProfileSource;

use crate::public::TextOpener;

/// One boxed shell answer.
pub type ShellFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The facts a creator command reads from the cell's shell (module
/// documentation).
pub trait CreatorShell: Send + Sync + 'static {
    /// The shell facts of `cmd` on `state`, from what the shell holds now.
    fn facts(&self, state: &CellState, cmd: &CreatorCommand) -> CreatorFacts;

    /// The Guide inputs of the publication of `call` on `state` (I-52,
    /// R-GA-01). The default holds none, so the publication is refused
    /// with I-52.
    fn guide(&self, state: &CellState, call: CallId) -> Option<GuideInputs> {
        let _ = (state, call);
        None
    }

    /// The shell facts of `cmd` on `state` for its request: a shell may
    /// run its probes first (design 3.2 "Fresh probes"). The default is
    /// [`CreatorShell::facts`].
    fn facts_fresh<'a>(
        &'a self,
        state: &'a CellState,
        cmd: &'a CreatorCommand,
    ) -> ShellFuture<'a, CreatorFacts> {
        Box::pin(std::future::ready(self.facts(state, cmd)))
    }

    /// The Guide inputs of the publication of `call` on `state`, reading
    /// stored texts from `texts`. The default is [`CreatorShell::guide`].
    fn guide_fresh<'a>(
        &'a self,
        state: &'a CellState,
        call: CallId,
        texts: &'a dyn TextOpener,
    ) -> ShellFuture<'a, Option<GuideInputs>> {
        let _ = texts;
        Box::pin(std::future::ready(self.guide(state, call)))
    }
}

/// The shell of a cell started without settings (module documentation).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProductionShell;

impl CreatorShell for ProductionShell {
    fn facts(&self, state: &CellState, cmd: &CreatorCommand) -> CreatorFacts {
        let profile = fstp_engine::compose::profile_ref(state.engine(), cmd)
            .and_then(|r| fstp_engine::compose::profile_name(&r))
            .and_then(|name| fstp_guide::ShippedProfiles.profile(&name).ok());
        CreatorFacts {
            probes: ProbeSet::absent(),
            exclusion_classes_known: None,
            proximity_lists_declared: None,
            ports: PortPresence {
                precheck: false,
                score_tools: false,
            },
            profile,
            guide: None,
        }
    }
}
