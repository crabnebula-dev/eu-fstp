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
//! - The two Q35 answers (`overview.md` NOTE 8, ADR-027). A shell that
//!   gives none leaves them to the vault: a command that reads the report
//!   asks `ClassesDefined` and `ProximityListsDeclared` with its other
//!   questions ([`q35_queries`]), and the decision reads their answers. A
//!   test shell may stand in for the vault with answers of its own.
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
    /// The Guide inputs of a call's publication (I-52, R-GA-01). `None`
    /// refuses the publication with I-52, since the engine fold refuses a
    /// `CallPublished` without its `GuidePublished` (D2e).
    pub guide: Option<GuideInputs>,
}

/// What the cell's shell supplies for the Guide of a call at its
/// publication (I-52, R-GA-01, M4 design section 3.10). The cell adds the
/// call's identifier and SHA-256 through `fstp-crypto`
/// (`fstp_engine::compose::GuideFacts`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuideInputs {
    /// The parsed Guide template of the programme's funder profile.
    pub template: fstp_guide::Template,
    /// The programme's compiled spec. `None` compiles the creator draft.
    pub compiled: Option<fstp_programme::Compiled>,
    /// The `https:` address applicants create an account on.
    pub platform_url: String,
    /// The data protection summary.
    pub data_protection_summary: String,
    /// The privacy statement address.
    pub privacy_statement_url: String,
    /// The stored texts the Guide may read, by text id.
    pub texts: std::collections::BTreeMap<fstp_domain::id::TextId, String>,
    /// Whether the cell has a pre-check provider (Q38).
    pub precheck_available: bool,
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
        let q35 = q35_queries(state, cmd);
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
                exclusion_classes_known: q35_answer(
                    f.exclusion_classes_known,
                    q35.as_ref().map(|q| &q[0]),
                    self.answers,
                ),
                proximity_lists_declared: q35_answer(
                    f.proximity_lists_declared,
                    q35.as_ref().map(|q| &q[1]),
                    self.answers,
                ),
            },
            tenant_admins: self.admins.clone(),
            ports: f.ports,
            theme: Theme::m4_default(),
            profile: f.profile.clone(),
        }
    }

    /// The Guide facts of the route's [`GuideInputs`], with the call's
    /// identifier and SHA-256 (I-52). `None` without them.
    fn guide_facts(
        &self,
        _state: &EngineState,
        call: fstp_domain::id::CallId,
    ) -> Option<fstp_engine::compose::GuideFacts> {
        let g = self.facts?.guide.as_ref()?;
        Some(fstp_engine::compose::GuideFacts {
            template: g.template.clone(),
            compiled: g.compiled.clone(),
            identifier: call.raw().to_string(),
            platform_url: g.platform_url.clone(),
            data_protection_summary: g.data_protection_summary.clone(),
            privacy_statement_url: g.privacy_statement_url.clone(),
            texts: g.texts.clone(),
            digest: fstp_crypto::sha256,
            precheck_available: g.precheck_available,
        })
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

/// Whether a creator command reads the validation report, as
/// `fstp_engine::compose` asks its own questions for: acknowledging a
/// warning, requesting activation, approving and overriding it.
fn reads_report(cmd: &CreatorCommand) -> bool {
    matches!(
        cmd,
        CreatorCommand::AcknowledgeWarning { .. }
            | CreatorCommand::RequestActivation { .. }
            | CreatorCommand::ApproveActivation { .. }
            | CreatorCommand::OverrideActivation { .. }
    )
}

/// The two Q35 questions of `cmd` on `state` (`overview.md` NOTE 8,
/// ADR-027): `ClassesDefined` over the P-13 classes and
/// `ProximityListsDeclared` over the P-38 lists of the draft's head
/// policy, in that order. `None` for a command that reads no report, or a
/// programme with no policy, and then both checks fail closed.
pub fn q35_queries(state: &EngineState, cmd: &CreatorCommand) -> Option<[Query; 2]> {
    if !reads_report(cmd) {
        return None;
    }
    let programme = cmd.programme();
    let policy = state.core.policy().head(programme)?;
    Some(q35_of(programme, policy))
}

/// The two Q35 questions over the policy version `policy` of `programme`.
pub fn q35_of(
    programme: fstp_domain::id::ProgrammeId,
    policy: &fstp_domain::policy::PolicyVersion,
) -> [Query; 2] {
    [
        Query::ClassesDefined {
            programme,
            classes: policy.live.p13.clone(),
        },
        Query::ProximityListsDeclared {
            programme,
            lists: policy.live.p38.0.values().copied().collect(),
        },
    ]
}

/// A Q35 answer: the shell's own if it gives one, else the vault's answer
/// to `query` among `answers`. `None` when neither exists, which fails
/// the check closed.
pub fn q35_answer(shell: Option<bool>, query: Option<&Query>, answers: &Answers) -> Option<bool> {
    shell.or_else(|| query.and_then(|q| answers.get(q)).map(|a| a.holds))
}

/// The Q35 questions `cmd` asks the vault on `s` (module documentation):
/// each one whose answer the route's `facts` do not give.
pub(crate) fn q35_asked(
    s: &CellState,
    cmd: &fstp_engine::Command,
    facts: Option<&CreatorFacts>,
) -> Vec<Query> {
    let fstp_engine::Command::Creator(c) = cmd else {
        return Vec::new();
    };
    let Some([classes, lists]) = q35_queries(s.engine(), c) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if facts.is_none_or(|f| f.exclusion_classes_known.is_none()) {
        out.push(classes);
    }
    if facts.is_none_or(|f| f.proximity_lists_declared.is_none()) {
        out.push(lists);
    }
    out
}
