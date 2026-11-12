//! Independent reference for policy, programmes and calls, written from the spec text (design section 6.1).
//!
//! Sources, read for this file and for nothing else:
//!
//! - `SPEC/02-domain/policy-parameters.md`: the Frozen column, NOTE 7
//!   (P-05 and P-13 snapshot, live edits) and NOTE 10 (P-21 primary model
//!   and fallback list).
//! - `SPEC/02-domain/invariants.md`: I-12, I-14 and I-50.
//! - `SPEC/01-requirements/functional.md`: R-PC-01, R-PC-02 and R-PC-03 with
//!   their NOTES.
//! - `docs/handoff/m2-design.md` sections 2.4, 2.5 and 3.3, with Daniel's
//!   answers to Q7, Q9, Q14 and Q16 in section 12.
//!
//! The reference shares only ids, the command type and the record type with
//! production. It never calls a production guard or reads a production
//! sub-state. The frozen and live parameter sets are parsed from the spec
//! file at test time, so a spec edit reaches the reference at once.
//!
//! Readings taken where the sources leave a choice. Each is reported to
//! Daniel and sits in one function:
//!
//! - A policy version carries every frozen programme parameter. The
//!   parameters M2 does not type sit in `FrozenValues::opaque`, so the
//!   opaque keys are exactly the frozen parameters without a typed field.
//!   A missing frozen key, a typed key or a live key in the frozen map, and a
//!   frozen, typed or tenant-level key in the live map are refused (I-12,
//!   design 2.4 "FrozenPolicy carries every frozen parameter" and "Tenant-level
//!   parameters are not in the programme policy").
//! - The last author of P-01 or P-09 is the author of the latest version
//!   that changed its value. An edit that keeps the value does not make its
//!   author a drafter (R-PC-03 NOTE).
//! - An approval covers the call text, P-01 and P-09 as they were. A later
//!   change of any of them ends it, because the call is being drafted again
//!   (state-machine.md Call states, DRAFT and APPROVED). Publication then
//!   needs a new approval, and an approval of such a call is accepted. An
//!   approver who became a drafter never counts (R-PC-03 second AC).
//! - A second approval of a call whose approval still holds is open, so the
//!   reference accepts either outcome.
//! - A call whose deadline is not after its opening is open. Generators do
//!   not draw one, and the reference accepts either outcome.
//! - The machines grant no money, so every recipient's counted sum is zero
//!   and lowering P-05 is always within the cap (I-14).
//! - Every amount of a version is in the version's currency (design 2.4,
//!   ADR-006). `Currency` has only EUR outside the money crate's own unit
//!   tests, so no generator can draw a foreign amount yet. The rule is here
//!   so a second currency reaches the reference at once.
//! - A repeated P-09 criterion id is inconsistent, as a repeated P-01
//!   criterion is (design 2.4).
//! - The drafters of a published call are fixed at publication: its
//!   authors plus the last authors of P-01 and P-09 in the frozen version
//!   (R-PC-03 NOTE "in that call's policy").
//! - A published call enforces the lower of the P-05 snapshot and the live
//!   P-05, and every class of the P-13 snapshot or the live P-13 (P-05 and
//!   P-13 NOTE 7). An unpublished call enforces the live values.
//!
//! Readings added for milestone M4, from `docs/handoff/m4-design.md`
//! sections 3.2, 3.4 and 12.3 and `SPEC/02-domain/invariants.md` I-67.
//! Each is interim, pending Daniel, as section 15.0 records:
//!
//! - A programme is a draft from its creation until an activation is
//!   accepted (D1). Policy edits run on a draft. Call commands on a
//!   draft are refused (D3).
//! - The core builders of a draft are its creator and every author of a
//!   policy version while it is a draft (Q1). The creator adds its own
//!   builders through `creator_builders`.
//! - The core `ActivateProgramme` is accepted only from an account the
//!   shell attests as a tenant admin, outside the builder set and the
//!   creator builders, on a draft, with a fresh decision id (D2, Q1). A
//!   shared verified identity with a builder refuses it too (Q2). The
//!   machines' vault gives every account its own identity.
//! - The report digest and the revision are data in the core. The engine
//!   pairs them with the creator's records once D2e lands.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use fstp_domain::command::{Actor, Command};
use fstp_domain::id::{
    AccountId, CallId, CallSeq, DecisionId, LlmConfigId, PolicyVersionId, ProgrammeId,
};
use fstp_domain::policy::{ExclusionClasses, FrozenValues, ModelRef, PolicyVersion};
use fstp_domain::record::Record;
use fstp_domain::roles::Role;
use fstp_money::{Currency, NonNegAmount};

// ---------------------------------------------------------------------------
// The parameter table of the spec
// ---------------------------------------------------------------------------

/// One row of the parameter tables in `SPEC/02-domain/policy-parameters.md`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecParam {
    /// The spec id, such as `"P-01"`.
    pub id: String,
    /// Whether the Frozen column says "Yes".
    pub frozen: bool,
    /// Whether the parameter is set per programme. Tenant-level rows and
    /// the row that is not tenant-configurable are not.
    pub programme: bool,
}

/// The path of the parameter file, relative to this crate.
const PARAMETER_FILE: &str = "../../SPEC/02-domain/policy-parameters.md";

/// The number of parameters the spec defines, P-01 to P-78.
const PARAMETER_COUNT: usize = 78;

/// Parses the parameter tables of the spec text.
fn parse_parameters(text: &str) -> Result<Vec<SpecParam>, String> {
    let mut out: Vec<SpecParam> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("| P-") {
            continue;
        }
        let cells: Vec<&str> = line
            .split('|')
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .collect();
        let (Some(id), Some(column)) = (cells.first(), cells.last()) else {
            return Err(format!("parameter row without cells: {line:?}"));
        };
        if cells.len() < 4 {
            return Err(format!("parameter row with too few cells: {line:?}"));
        }
        let frozen = *column == "Yes";
        let programme =
            !(column.contains("tenant-level") || column.contains("Not tenant-configurable"));
        if out.iter().any(|p| p.id == *id) {
            return Err(format!("parameter {id} appears twice"));
        }
        out.push(SpecParam {
            id: (*id).to_owned(),
            frozen,
            programme,
        });
    }
    if out.len() != PARAMETER_COUNT {
        return Err(format!(
            "expected {PARAMETER_COUNT} parameter rows in {PARAMETER_FILE}, found {}",
            out.len()
        ));
    }
    Ok(out)
}

/// The parameter rows of the spec, read once per test binary.
pub fn spec_parameters() -> Result<&'static [SpecParam], String> {
    static TABLE: OnceLock<Result<Vec<SpecParam>, String>> = OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(PARAMETER_FILE);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        parse_parameters(&text)
    });
    match table {
        Ok(rows) => Ok(rows.as_slice()),
        Err(e) => Err(e.clone()),
    }
}

/// The frozen programme parameters of the spec (I-12).
pub fn spec_frozen() -> Result<BTreeSet<String>, String> {
    Ok(spec_parameters()?
        .iter()
        .filter(|p| p.frozen && p.programme)
        .map(|p| p.id.clone())
        .collect())
}

/// The programme parameters of the spec that are not frozen.
pub fn spec_live() -> Result<BTreeSet<String>, String> {
    Ok(spec_parameters()?
        .iter()
        .filter(|p| !p.frozen && p.programme)
        .map(|p| p.id.clone())
        .collect())
}

/// The frozen parameters that design section 2.4 gives a typed field of
/// `FrozenValues`, with P-75 since M4 change D6. The pure I-12 test ties
/// this list to the struct.
pub const TYPED_FROZEN: [&str; 19] = [
    "P-01", "P-02", "P-03", "P-04", "P-07", "P-09", "P-10", "P-11", "P-14", "P-15", "P-16", "P-17",
    "P-21", "P-24", "P-26", "P-39", "P-53", "P-75", "P-77",
];

/// The live parameters that design section 2.4 gives a typed field of
/// `LiveValues`. The pure I-12 test ties this list to the struct.
pub const TYPED_LIVE: [&str; 6] = ["P-05", "P-12", "P-13", "P-38", "P-56", "P-58"];

/// The keys `FrozenValues::opaque` must hold: every frozen programme
/// parameter without a typed field (I-12).
pub fn expected_frozen_opaque() -> Result<BTreeSet<String>, String> {
    let mut keys = spec_frozen()?;
    for typed in TYPED_FROZEN {
        keys.remove(typed);
    }
    Ok(keys)
}

/// The keys `LiveValues::opaque` may hold: live programme parameters
/// without a typed field.
pub fn allowed_live_opaque() -> Result<BTreeSet<String>, String> {
    let mut keys = spec_live()?;
    for typed in TYPED_LIVE {
        keys.remove(typed);
    }
    Ok(keys)
}

// ---------------------------------------------------------------------------
// Validation of a policy version
// ---------------------------------------------------------------------------

/// Why the reference refuses a policy version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invalid {
    /// An amount in another currency than the version's (design 2.4, ADR-006).
    CurrencyMismatch,
    /// A P-09 criterion id appears twice (design 2.4).
    RepeatedP09,
    /// P-03 above 64, unsafe for exact arithmetic (design 2.4).
    P03TooLarge,
    /// P-05 above P-58 (I-50).
    P05AboveP58,
    /// The frozen opaque keys are not exactly the untyped frozen parameters (I-12).
    FrozenKeys,
    /// The live opaque map holds a frozen, typed or non-programme key (I-12).
    LiveKeys,
}

/// The largest P-03 the design accepts (design 2.4).
const P03_MAX: u8 = 64;

/// The reference verdict on the values of `v` alone, from design section
/// 2.4 and I-50. Cross-checks the spec does not state, such as P-04 max
/// above P-05 or P-39 above P-03, are warnings and never refusals.
pub fn validate(v: &PolicyVersion) -> Result<Result<(), Invalid>, String> {
    let amounts = [
        Some(v.frozen.p04.min()),
        Some(v.frozen.p04.max()),
        Some(v.live.p05),
        v.live.p56,
        v.live.p58,
    ];
    if amounts
        .iter()
        .flatten()
        .any(|a| a.amount().currency() != v.currency)
    {
        return Ok(Err(Invalid::CurrencyMismatch));
    }
    let knock_outs: BTreeSet<_> = v.frozen.p09.0.iter().map(|k| k.id).collect();
    if knock_outs.len() != v.frozen.p09.0.len() {
        return Ok(Err(Invalid::RepeatedP09));
    }
    if v.frozen.p03.get() > P03_MAX {
        return Ok(Err(Invalid::P03TooLarge));
    }
    if let Some(ceiling) = v.live.p58 {
        let above = v
            .live
            .p05
            .amount()
            .cmp_same(ceiling.amount())
            .map_err(|e| format!("P-05 and P-58 not comparable: {e:?}"))?
            == core::cmp::Ordering::Greater;
        if above {
            return Ok(Err(Invalid::P05AboveP58));
        }
    }
    let frozen_keys: BTreeSet<String> = v
        .frozen
        .opaque
        .keys()
        .map(|k| k.spec_id().to_owned())
        .collect();
    if frozen_keys != expected_frozen_opaque()? {
        return Ok(Err(Invalid::FrozenKeys));
    }
    let allowed = allowed_live_opaque()?;
    if v.live.opaque.keys().any(|k| !allowed.contains(k.spec_id())) {
        return Ok(Err(Invalid::LiveKeys));
    }
    Ok(Ok(()))
}

// ---------------------------------------------------------------------------
// The ghost: what the spec says the policy part must hold
// ---------------------------------------------------------------------------

/// The reference verdict on one command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// The sources require acceptance.
    Accept,
    /// The sources require refusal.
    Refuse,
    /// The sources leave the outcome open. Either outcome passes, and the
    /// ghost follows production (see the module readings).
    Either,
}

/// One programme as the reference sees it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProgrammeGhost {
    /// The programme currency, fixed at creation.
    pub currency: Currency,
    /// The head version.
    pub head: PolicyVersionId,
    /// The author of the latest version that changed P-01.
    pub last_author_p01: AccountId,
    /// The author of the latest version that changed P-09.
    pub last_author_p09: AccountId,
    /// How many calls the programme has published.
    pub published: u32,
    /// Whether an activation was accepted. A programme starts as a draft
    /// (M4 change D1).
    pub active: bool,
    /// The core builders while the programme is a draft: its creator and
    /// every author of a policy version of it (I-67, Q1 interim reading).
    /// The machines grant no binding, so no grantor joins the set here.
    pub builders: BTreeSet<AccountId>,
}

/// One approval of a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ApprovalGhost {
    /// The approver.
    pub approver: AccountId,
    /// Whether the call text, P-01 and P-09 are unchanged since the approval.
    pub clean: bool,
}

/// What a publication froze, copied when it happened (design 6.1 ghost state).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublishedGhost {
    /// The call's sequence number in its programme.
    pub seq: CallSeq,
    /// The version that was the head at publication.
    pub version: PolicyVersionId,
    /// A copy of the frozen values at publication (I-12).
    pub frozen: FrozenValues,
    /// The P-05 snapshot at publication (P-05 and P-13 NOTE 7).
    pub p05: NonNegAmount,
    /// The P-13 snapshot at publication (NOTE 7).
    pub p13: ExclusionClasses,
    /// The pinned configuration (I-11).
    pub config: LlmConfigId,
    /// The drafters at publication: the authors plus the last authors of
    /// P-01 and P-09 in the frozen version (R-PC-03 NOTE).
    pub drafters: BTreeSet<AccountId>,
}

/// One call as the reference sees it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CallGhost {
    /// The programme.
    pub programme: ProgrammeId,
    /// Every account that drafted or edited the call.
    pub authors: BTreeSet<AccountId>,
    /// The approvals recorded, in order.
    pub approvals: Vec<ApprovalGhost>,
    /// Set once the call is published.
    pub published: Option<PublishedGhost>,
}

/// The reference state of programmes, policy versions and calls.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ghost {
    /// Programmes by id.
    pub programmes: BTreeMap<ProgrammeId, ProgrammeGhost>,
    /// Every version recorded, as recorded.
    pub versions: BTreeMap<PolicyVersionId, PolicyVersion>,
    /// Calls by id.
    pub calls: BTreeMap<CallId, CallGhost>,
    /// Decision ids taken.
    pub decisions: BTreeSet<DecisionId>,
    /// Configurations pinned so far.
    pub configs: BTreeSet<LlmConfigId>,
    /// Programme manager and call drafter bindings the setup established.
    /// They stay active for the whole run.
    pub holders: BTreeSet<(AccountId, ProgrammeId, Role)>,
}

impl Default for Ghost {
    fn default() -> Ghost {
        Ghost::new()
    }
}

/// The account behind `actor`, if it is an account.
fn account(actor: Actor) -> Option<AccountId> {
    match actor {
        Actor::Account(a) => Some(a),
        Actor::System(_) => None,
    }
}

impl Ghost {
    /// The reference state before any record.
    pub fn new() -> Ghost {
        Ghost {
            programmes: BTreeMap::new(),
            versions: BTreeMap::new(),
            calls: BTreeMap::new(),
            decisions: BTreeSet::new(),
            configs: BTreeSet::new(),
            holders: BTreeSet::new(),
        }
    }

    /// Records that `account` holds `role` in `programme` for the whole run.
    pub fn bind(&mut self, account: AccountId, programme: ProgrammeId, role: Role) {
        self.holders.insert((account, programme, role));
    }

    /// Whether `account` holds `role` in `programme`.
    pub fn holds(&self, account: AccountId, programme: ProgrammeId, role: Role) -> bool {
        self.holders.contains(&(account, programme, role))
    }

    /// The head version of `programme`.
    pub fn head(&self, programme: ProgrammeId) -> Option<&PolicyVersion> {
        let p = self.programmes.get(&programme)?;
        self.versions.get(&p.head)
    }

    /// The drafters of `call`: its authors plus the last authors of P-01
    /// and P-09 in that call's policy (R-PC-03 NOTE). Before publication
    /// that policy is the head. After it, the set taken at publication.
    pub fn drafters(&self, call: CallId) -> BTreeSet<AccountId> {
        let mut out = BTreeSet::new();
        if let Some(c) = self.calls.get(&call) {
            if let Some(p) = &c.published {
                return p.drafters.clone();
            }
            out.extend(c.authors.iter().copied());
            if let Some(p) = self.programmes.get(&c.programme) {
                out.insert(p.last_author_p01);
                out.insert(p.last_author_p09);
            }
        }
        out
    }

    /// The P-05 cap that `call` enforces now (NOTE 7): the lower of the
    /// publication snapshot and the live value, or the live value before
    /// publication. `None` for an unknown call.
    pub fn effective_p05(&self, call: CallId) -> Result<Option<NonNegAmount>, String> {
        let Some(c) = self.calls.get(&call) else {
            return Ok(None);
        };
        let live = self
            .head(c.programme)
            .ok_or("a call without a programme head")?
            .live
            .p05;
        let Some(p) = &c.published else {
            return Ok(Some(live));
        };
        let order = live
            .amount()
            .cmp_same(p.p05.amount())
            .map_err(|e| format!("live and snapshot P-05 not comparable: {e:?}"))?;
        Ok(Some(if order == core::cmp::Ordering::Less {
            live
        } else {
            p.p05
        }))
    }

    /// The P-13 classes that `call` enforces now (NOTE 7): every class of
    /// the publication snapshot or the live value, or the live value before
    /// publication. `None` for an unknown call.
    pub fn effective_p13(&self, call: CallId) -> Result<Option<ExclusionClasses>, String> {
        let Some(c) = self.calls.get(&call) else {
            return Ok(None);
        };
        let mut classes = self
            .head(c.programme)
            .ok_or("a call without a programme head")?
            .live
            .p13
            .0
            .clone();
        if let Some(p) = &c.published {
            classes.extend(p.p13.0.iter().copied());
        }
        Ok(Some(ExclusionClasses(classes)))
    }

    /// The largest version id taken, or 0.
    pub fn max_version(&self) -> u128 {
        self.versions.keys().next_back().map_or(0, |v| v.raw())
    }

    /// The largest call id taken, or 0.
    pub fn max_call(&self) -> u128 {
        self.calls.keys().next_back().map_or(0, |c| c.raw())
    }

    /// The largest decision id taken, or 0.
    pub fn max_decision(&self) -> u128 {
        self.decisions.iter().next_back().map_or(0, |d| d.raw())
    }

    /// The largest configuration id pinned, or 0.
    pub fn max_config(&self) -> u128 {
        self.configs.iter().next_back().map_or(0, |c| c.raw())
    }

    /// The reference verdict on `cmd` issued by `actor`. `tenant_admin` is
    /// the shell's attestation in the context.
    pub fn verdict(
        &self,
        actor: Actor,
        tenant_admin: bool,
        cmd: &Command,
    ) -> Result<Verdict, String> {
        let Some(who) = account(actor) else {
            return Ok(Verdict::Refuse);
        };
        let v = match cmd {
            Command::CreateProgramme { policy } => self.create_verdict(tenant_admin, policy)?,
            Command::EditPolicy { base, version } => self.edit_verdict(who, *base, version)?,
            Command::DraftCall {
                call,
                programme,
                opens,
                deadline,
                budget,
                ..
            } => {
                let Some(p) = self.programmes.get(programme) else {
                    return Ok(Verdict::Refuse);
                };
                if !self.may_write_calls(who, *programme)
                    || self.calls.contains_key(call)
                    || budget.amount().currency() != p.currency
                {
                    Verdict::Refuse
                } else if deadline <= opens {
                    Verdict::Either
                } else {
                    Verdict::Accept
                }
            }
            Command::EditCall {
                call,
                opens,
                deadline,
                budget,
                ..
            } => {
                let Some(c) = self.calls.get(call) else {
                    return Ok(Verdict::Refuse);
                };
                let currency = self.programmes.get(&c.programme).map(|p| p.currency);
                if !self.may_write_calls(who, c.programme)
                    || c.published.is_some()
                    || Some(budget.amount().currency()) != currency
                {
                    Verdict::Refuse
                } else if deadline <= opens {
                    Verdict::Either
                } else {
                    Verdict::Accept
                }
            }
            Command::ApproveCallPublication { call, decision } => {
                let Some(c) = self.calls.get(call) else {
                    return Ok(Verdict::Refuse);
                };
                if !self.holds(who, c.programme, Role::ProgrammeManager)
                    || c.published.is_some()
                    || self.decisions.contains(decision)
                    || self.drafters(*call).contains(&who)
                {
                    Verdict::Refuse
                } else if !c.approvals.iter().any(|a| a.clean) {
                    // No approval holds any more, so the call is DRAFT again.
                    Verdict::Accept
                } else {
                    Verdict::Either
                }
            }
            Command::PublishCall {
                call, config_model, ..
            } => self.publish_verdict(who, *call, config_model),
            Command::ActivateProgramme {
                programme,
                decision,
                creator_builders,
                ..
            } => self.activate_verdict(who, tenant_admin, *programme, *decision, creator_builders),
            other => return Err(format!("not a policy or call command: {other:?}")),
        };
        // M4 change D3: nothing runs on a draft programme beside policy
        // edits. A call command on a draft is refused.
        if v != Verdict::Refuse && self.on_draft(cmd) {
            return Ok(Verdict::Refuse);
        }
        Ok(v)
    }

    /// Whether `cmd` is a call command on a programme that is still a
    /// draft (M4 change D3).
    fn on_draft(&self, cmd: &Command) -> bool {
        let programme = match cmd {
            Command::DraftCall { programme, .. } => Some(*programme),
            Command::EditCall { call, .. }
            | Command::ApproveCallPublication { call, .. }
            | Command::PublishCall { call, .. } => self.calls.get(call).map(|c| c.programme),
            _ => None,
        };
        programme
            .and_then(|p| self.programmes.get(&p))
            .is_some_and(|p| !p.active)
    }

    /// Whether `programme` is known and activated (M4 change D1).
    pub fn is_active(&self, programme: ProgrammeId) -> bool {
        self.programmes.get(&programme).is_some_and(|p| p.active)
    }

    /// The core builders of `programme` (I-67), empty for an unknown one.
    pub fn builders(&self, programme: ProgrammeId) -> BTreeSet<AccountId> {
        self.programmes
            .get(&programme)
            .map(|p| p.builders.clone())
            .unwrap_or_default()
    }

    /// The reference verdict on a core `ActivateProgramme` (I-67, M4 change
    /// D2, Q1 and Q2 interim readings): the approver is a tenant admin
    /// outside the builder set of a draft programme, with a fresh decision
    /// id. Every account of the machines' vault has its own identity, so
    /// `SameIdentityAsAny` never holds there.
    fn activate_verdict(
        &self,
        who: AccountId,
        tenant_admin: bool,
        programme: ProgrammeId,
        decision: DecisionId,
        creator_builders: &BTreeSet<AccountId>,
    ) -> Verdict {
        let Some(p) = self.programmes.get(&programme) else {
            return Verdict::Refuse;
        };
        if !tenant_admin
            || p.active
            || self.decisions.contains(&decision)
            || p.builders.contains(&who)
            || creator_builders.contains(&who)
        {
            return Verdict::Refuse;
        }
        Verdict::Accept
    }

    /// Whether `who` may draft and edit calls in `programme`.
    fn may_write_calls(&self, who: AccountId, programme: ProgrammeId) -> bool {
        self.holds(who, programme, Role::ProgrammeManager)
            || self.holds(who, programme, Role::CallDrafter)
    }

    /// Whether `id` is taken by any recorded version.
    fn version_taken(&self, id: PolicyVersionId) -> bool {
        self.versions.contains_key(&id)
    }

    fn create_verdict(&self, tenant_admin: bool, v: &PolicyVersion) -> Result<Verdict, String> {
        if !tenant_admin
            || v.parent.is_some()
            || self.programmes.contains_key(&v.programme)
            || self.version_taken(v.id)
            || validate(v)?.is_err()
        {
            return Ok(Verdict::Refuse);
        }
        Ok(Verdict::Accept)
    }

    fn edit_verdict(
        &self,
        who: AccountId,
        base: PolicyVersionId,
        v: &PolicyVersion,
    ) -> Result<Verdict, String> {
        let Some(p) = self.programmes.get(&v.programme) else {
            return Ok(Verdict::Refuse);
        };
        // The roles table: the programme manager sets policy parameters,
        // and the call drafter writes the knock-out criteria, so a call
        // drafter may author a version whose only change is P-09.
        let knock_outs_only = self.head(v.programme).is_some_and(|h| {
            let mut rest = v.frozen.clone();
            rest.p09 = h.frozen.p09.clone();
            v.frozen.p09 != h.frozen.p09
                && rest == h.frozen
                && v.live == h.live
                && v.currency == h.currency
        });
        let editor = self.holds(who, v.programme, Role::ProgrammeManager)
            || (knock_outs_only && self.holds(who, v.programme, Role::CallDrafter));
        if !editor
            || p.head != base
            || v.parent != Some(base)
            || self.version_taken(v.id)
            || v.currency != p.currency
            || validate(v)?.is_err()
        {
            return Ok(Verdict::Refuse);
        }
        // No machine grants money, so every counted sum is zero and a lower
        // P-05 keeps every recipient within the cap (I-14).
        Ok(Verdict::Accept)
    }

    fn publish_verdict(&self, who: AccountId, call: CallId, model: &ModelRef) -> Verdict {
        let Some(c) = self.calls.get(&call) else {
            return Verdict::Refuse;
        };
        let Some(head) = self.head(c.programme) else {
            return Verdict::Refuse;
        };
        if !self.holds(who, c.programme, Role::ProgrammeManager)
            || c.published.is_some()
            || *model != head.frozen.p21.primary
        {
            return Verdict::Refuse;
        }
        let drafters = self.drafters(call);
        let eligible: Vec<&ApprovalGhost> = c
            .approvals
            .iter()
            .filter(|a| !drafters.contains(&a.approver))
            .collect();
        // An approval made before a change of the call text, P-01 or P-09
        // no longer covers the call (R-PC-03, Call states).
        if eligible.iter().any(|a| a.clean) {
            Verdict::Accept
        } else {
            Verdict::Refuse
        }
    }

    /// The records an accepted `cmd` must append, computed before it runs.
    /// Production may append further records, such as vault outcomes.
    pub fn expected_records(&self, actor: Actor, cmd: &Command) -> Result<Vec<Record>, String> {
        let who = account(actor).ok_or("a System actor has no expected records")?;
        let out = match cmd {
            Command::CreateProgramme { policy } => vec![
                Record::ProgrammeCreated {
                    programme: policy.programme,
                    currency: policy.currency,
                    by: who,
                },
                Record::PolicyVersionRecorded {
                    version: policy.clone(),
                    author: who,
                },
            ],
            Command::EditPolicy { version, .. } => vec![Record::PolicyVersionRecorded {
                version: version.clone(),
                author: who,
            }],
            Command::DraftCall {
                call,
                programme,
                opens,
                deadline,
                deadline_zone,
                budget,
                text,
            } => vec![Record::CallDrafted {
                call: *call,
                programme: *programme,
                opens: *opens,
                deadline: *deadline,
                deadline_zone: deadline_zone.clone(),
                budget: *budget,
                text: *text,
                author: who,
            }],
            Command::EditCall {
                call,
                opens,
                deadline,
                deadline_zone,
                budget,
                text,
            } => vec![Record::CallEdited {
                call: *call,
                opens: *opens,
                deadline: *deadline,
                deadline_zone: deadline_zone.clone(),
                budget: *budget,
                text: *text,
                author: who,
            }],
            Command::ApproveCallPublication { call, decision } => vec![Record::CallApproved {
                call: *call,
                decision: *decision,
                approver: who,
            }],
            Command::PublishCall { call, config, .. } => {
                let c = self
                    .calls
                    .get(call)
                    .ok_or("publication of an unknown call")?;
                let p = self
                    .programmes
                    .get(&c.programme)
                    .ok_or("call of an unknown programme")?;
                let next = p.published.checked_add(1).ok_or("call sequence overflow")?;
                let seq = core::num::NonZeroU32::new(next)
                    .map(CallSeq::new)
                    .ok_or("call sequence zero")?;
                vec![Record::CallPublished {
                    call: *call,
                    policy: p.head,
                    seq,
                    config: *config,
                    by: who,
                }]
            }
            // I-67, M4 change D2: the activation names its approver and
            // the builder set it was checked against, the core builders
            // plus the creator's. The payload has private fields, so the
            // expected record is built through the codec.
            Command::ActivateProgramme {
                programme,
                decision,
                report,
                revision,
                creator_builders,
            } => {
                let mut builders = self.builders(*programme);
                builders.extend(creator_builders.iter().copied());
                vec![crate::activation::forge_programme_activated(
                    *programme,
                    *decision,
                    report.bytes(),
                    *revision,
                    who,
                    &builders,
                    fstp_domain::record::RulesVersion::M4.0,
                )?]
            }
            other => return Err(format!("not a policy or call command: {other:?}")),
        };
        Ok(out)
    }

    /// Advances the ghost by `cmd`, which production accepted and the
    /// reference did not refuse.
    pub fn apply(&mut self, actor: Actor, cmd: &Command) -> Result<(), String> {
        let who = account(actor).ok_or("a System actor issued a policy command")?;
        match cmd {
            Command::CreateProgramme { policy } => {
                self.programmes.insert(
                    policy.programme,
                    ProgrammeGhost {
                        currency: policy.currency,
                        head: policy.id,
                        last_author_p01: who,
                        last_author_p09: who,
                        published: 0,
                        active: false,
                        builders: [who].into_iter().collect(),
                    },
                );
                self.versions.insert(policy.id, (**policy).clone());
            }
            Command::ActivateProgramme {
                programme,
                decision,
                ..
            } => {
                let p = self
                    .programmes
                    .get_mut(programme)
                    .ok_or("activation of an unknown programme")?;
                p.active = true;
                self.decisions.insert(*decision);
            }
            Command::EditPolicy { base, version } => {
                let parent = self
                    .versions
                    .get(base)
                    .ok_or("edit of an unknown base")?
                    .clone();
                let changes_criteria = parent.frozen.p01 != version.frozen.p01
                    || parent.frozen.p09 != version.frozen.p09;
                let p = self
                    .programmes
                    .get_mut(&version.programme)
                    .ok_or("edit of an unknown programme")?;
                if parent.frozen.p01 != version.frozen.p01 {
                    p.last_author_p01 = who;
                }
                if parent.frozen.p09 != version.frozen.p09 {
                    p.last_author_p09 = who;
                }
                if !p.active {
                    // I-67: a policy author on the draft is a builder.
                    p.builders.insert(who);
                }
                p.head = version.id;
                self.versions.insert(version.id, (**version).clone());
                if changes_criteria {
                    self.taint_approvals(|c| c.programme == version.programme);
                }
            }
            Command::DraftCall {
                call, programme, ..
            } => {
                self.calls.insert(
                    *call,
                    CallGhost {
                        programme: *programme,
                        authors: [who].into_iter().collect(),
                        approvals: Vec::new(),
                        published: None,
                    },
                );
            }
            Command::EditCall { call, .. } => {
                let c = self.calls.get_mut(call).ok_or("edit of an unknown call")?;
                c.authors.insert(who);
                for a in &mut c.approvals {
                    a.clean = false;
                }
            }
            Command::ApproveCallPublication { call, decision } => {
                let c = self
                    .calls
                    .get_mut(call)
                    .ok_or("approval of an unknown call")?;
                c.approvals.push(ApprovalGhost {
                    approver: who,
                    clean: true,
                });
                self.decisions.insert(*decision);
            }
            Command::PublishCall { call, config, .. } => {
                let programme = self
                    .calls
                    .get(call)
                    .ok_or("publication of an unknown call")?
                    .programme;
                let head = self
                    .head(programme)
                    .ok_or("publication without a head")?
                    .clone();
                let drafters = self.drafters(*call);
                let p = self
                    .programmes
                    .get_mut(&programme)
                    .ok_or("publication in an unknown programme")?;
                p.published = p.published.checked_add(1).ok_or("call sequence overflow")?;
                let seq = core::num::NonZeroU32::new(p.published)
                    .map(CallSeq::new)
                    .ok_or("call sequence zero")?;
                let c = self
                    .calls
                    .get_mut(call)
                    .ok_or("publication of an unknown call")?;
                c.published = Some(PublishedGhost {
                    seq,
                    version: head.id,
                    frozen: head.frozen.clone(),
                    p05: head.live.p05,
                    p13: head.live.p13.clone(),
                    config: *config,
                    drafters,
                });
                self.configs.insert(*config);
            }
            other => return Err(format!("not a policy or call command: {other:?}")),
        }
        Ok(())
    }

    /// Marks every approval of the unpublished calls that `which` selects as no longer clean.
    fn taint_approvals(&mut self, which: impl Fn(&CallGhost) -> bool) {
        for c in self.calls.values_mut() {
            if c.published.is_none() && which(c) {
                for a in &mut c.approvals {
                    a.clean = false;
                }
            }
        }
    }

    /// The published calls with what each froze.
    pub fn published(&self) -> impl Iterator<Item = (CallId, &PublishedGhost)> {
        self.calls
            .iter()
            .filter_map(|(id, c)| c.published.as_ref().map(|p| (*id, p)))
    }
}
