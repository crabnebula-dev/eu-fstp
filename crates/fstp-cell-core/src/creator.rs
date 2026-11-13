//! The creator environment of a cell (M4 design sections 3.2 and 3.4,
//! change D2e, lane F-CYCLE2).
//!
//! An M2 engine command of the cell is decided by
//! `fstp_engine::CreatorDecider` over [`CellEnvironment`], so a creator
//! command gets the shell facts it reads. The facts come from three
//! places:
//!
//! - The cell's state: the attested tenant admin set is the tenant fold's
//!   (Q31 A), the same set that attests `Ctx::tenant_admin`.
//! - The vault answers the driver obtained: the SoD previews of the draft's
//!   invitations ask their questions with the command's own
//!   ([`preview_queries`]), and each preview reads its answers from them.
//!   A preview whose answer is missing has no outcome, so its invitation
//!   fails closed as `InviteeRefused`.
//! - The route's [`CreatorFacts`], which the route reads from the cell's
//!   shell before admission: the probes, the Q35 answers, the ports and
//!   the funder profile. A command admitted without them gets none, so
//!   every check that needs one fails closed, as `NoEnvironment` did.
//!
//! The engine replaces the facts it owns: the count of unresolved import
//! proposals, and the `IsVerified` and `SameIdentityAsAny` answers, which
//! it reads from the driver's answers (`fstp_engine::compose`). The theme
//! is the M4 default, as the design states for M4.
//!
//! A `SaveFields` holds its saved values once its entry is appended
//! ([`hold_appended`]), as `fstp_engine::Engine` does. The ledger keeps only
//! digests (ADR-007), so after a restart every saved value is unheld, and
//! the checks that read one fail closed until the draft is saved again.

use std::collections::BTreeSet;

use fstp_creator::{CreatorCommand, CreatorInputs, PortPresence, ProbeSet, Theme, VaultChecks};
use fstp_domain::command::Ctx;
use fstp_domain::id::AccountId;
use fstp_domain::oracle::{Answers, Query};
use fstp_engine::{CreatorEnvironment, EngineState};

use crate::CellRecord;
use crate::state::CellState;

/// The shell facts of one creator decision that only the cell's shell
/// holds (module documentation). [`CreatorFacts::default`] holds none:
/// every probe absent, no Q35 answer, no port and no profile.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreatorFacts {
    /// The probe results: run for an approval, peeked for the rest.
    pub probes: ProbeSet,
    /// Whether the vault knows every P-13 class of the draft (Q35).
    pub exclusion_classes_known: Option<bool>,
    /// Whether every P-38 partner organisation declared its list (Q35).
    pub proximity_lists_declared: Option<bool>,
    /// The ports the cell has.
    pub ports: PortPresence,
    /// The funder profile of the draft, from the cell's profile source.
    pub profile: Option<fstp_guide::FunderProfile>,
}

/// The creator environment of one decision (module documentation).
pub(crate) struct CellEnvironment<'a> {
    facts: Option<&'a CreatorFacts>,
    admins: BTreeSet<AccountId>,
    answers: &'a Answers,
}

impl<'a> CellEnvironment<'a> {
    /// The environment of a decision on `s` with the route's `facts` and
    /// the driver's `answers`.
    pub(crate) fn new(
        s: &CellState,
        facts: Option<&'a CreatorFacts>,
        answers: &'a Answers,
    ) -> CellEnvironment<'a> {
        CellEnvironment {
            facts,
            admins: s.tenant().admins().into_iter().collect(),
            answers,
        }
    }
}

impl CreatorEnvironment for CellEnvironment<'_> {
    fn creator_inputs(
        &self,
        state: &EngineState,
        cmd: &CreatorCommand,
        ctx: &Ctx,
    ) -> CreatorInputs {
        let none = CreatorFacts::default();
        let f = self.facts.unwrap_or(&none);
        let admins = &self.admins;
        let sod = fstp_engine::compose::sod_previews(
            state,
            cmd,
            ctx,
            &|a| admins.contains(&a),
            &mut |queries| {
                let mut out = Answers::new();
                for q in queries {
                    out.insert(q.clone(), self.answers.get(q)?.clone());
                }
                Some(out)
            },
        );
        CreatorInputs {
            // The engine replaces it with the import store's count.
            unresolved_imports: 0,
            probes: f.probes.clone(),
            sod,
            vault: VaultChecks {
                // The engine replaces both with the answers it obtained.
                is_verified: Default::default(),
                same_identity: Default::default(),
                exclusion_classes_known: f.exclusion_classes_known,
                proximity_lists_declared: f.proximity_lists_declared,
            },
            tenant_admins: self.admins.clone(),
            ports: f.ports,
            theme: Theme::m4_default(),
            profile: f.profile.clone(),
        }
    }
}

/// The vault questions of the SoD previews of an engine command `cmd` on
/// `s` by `ctx`: none for a command that is not a creator command.
pub(crate) fn preview_queries(s: &CellState, cmd: &fstp_engine::Command, ctx: &Ctx) -> Vec<Query> {
    let fstp_engine::Command::Creator(c) = cmd else {
        return Vec::new();
    };
    let admins: BTreeSet<AccountId> = s.tenant().admins().into_iter().collect();
    fstp_engine::compose::sod_preview_queries(s.engine(), c, ctx, &|a| admins.contains(&a))
}

/// Holds in `after` the values of the entry `batch` of `cmd`, decided by
/// `ctx` on `before` and folded into `after` (module documentation).
pub(crate) fn hold_appended(
    before: &CellState,
    after: &mut CellState,
    cmd: &fstp_engine::Command,
    ctx: &Ctx,
    batch: &[CellRecord],
) {
    let engine: Vec<fstp_engine::Record> = batch
        .iter()
        .filter_map(|r| match r {
            CellRecord::Engine(e) => Some(e.clone()),
            _ => None,
        })
        .collect();
    if engine.is_empty() {
        return;
    }
    // A value that is not held fails its checks closed, so a partial
    // hold is safe to keep.
    let _ = fstp_engine::hold_appended(before.engine(), &mut after.engine, cmd, ctx, &engine);
}
