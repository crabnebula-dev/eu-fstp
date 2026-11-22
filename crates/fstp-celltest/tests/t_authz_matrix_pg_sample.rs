//! T-AUTHZ-MATRIX on PostgreSQL (I-84, H-01, M4 design section 8.3,
//! production design section 3.3, lane L7).
//!
//! A deterministic sample of the authorisation matrix runs against the
//! production cell: `ApiCore` over the cell's PostgreSQL ports, mounted
//! behind the cell table (`World::start_with_api`). Every request goes
//! through the cell's own HTTP listener: the web cells to `/api/v1` and
//! `/p` with a session cookie, the MCP cells to `/mcp` as a `tools/call`
//! with a bearer token from the cell's own OAuth server. Each sampled
//! cell is compared with the independent reference
//! (`fstp_api_testkit::reference::authz`) in both directions, with
//! `fstp_api_testkit::matrix::{agrees, class_of}`.
//!
//! # Worlds
//!
//! A world is one cell built through its routes. The cycle's `login`,
//! `create-programme` and `publish-call` steps give the programme P, its
//! call C and the cycle's staff. Every other principal enrols through an
//! invitation of the first admin, gets a seeded verification (design
//! section 6.9), and is granted its role with a passkey step-up through
//! `POST /api/v1/commands`. The lead of X drafts and submits X while C is
//! open. The coordinator then assigns and the reviewers declare after the
//! deadline. The suspended reviewer shares the identity of the call
//! drafter in the seeded vault, so the cell's own reaction to the vault
//! epoch suspends its binding (I-06). The world of `Proposal(IrcReview)`
//! goes on: knock-out, admission, scores, the close of stage 1, "no
//! questions", the cut-off round with a recused and a delegating member,
//! and the IRC assignments.
//!
//! # Sampling rule
//!
//! The candidate cells are `Matrix::group_cells(state, policy)` of the
//! covering matrix (`fstp_api_testkit::matrix::matrix`) for each state
//! the PostgreSQL worlds build, at the policy row the worlds hold, with
//! these left out, each because a production cell cannot hold it:
//!
//! - the OPAQUE login method: a production cell never offers it (Q10 A,
//!   `fstp_auth::EnabledMethods::offers`);
//! - `Who::SoleTenantAdmin` and `Who::FinancialSignatory`: a world cell's
//!   ledger holds no tenant part, since no control plane records
//!   `TenantProvisioned` (D1, ADR-021), so onboarding and the tenant-wide
//!   signatory roles do not exist there;
//! - `Who::VoidedLead`: its world (`Proposal(Negotiation)`, with the lead
//!   voided by a P-13 exclusion through the seeded vault) is not built
//!   yet. That is a gap of this sample, not of the cell;
//! - the operations that need a ceremony the sample does not run per
//!   cell: `me.add_passkey` (a WebAuthn registration over the session's
//!   own options) and `agents.consent` and `agents.consent_request` (an
//!   authorize request per cell);
//! - for now, the operations of ADR-030 (`tenant.branding.logos`,
//!   `tenant.branding.set_logo`, `me.set_theme`, `programme.logos`), added
//!   after the sample was
//!   fixed. Their cells would reshuffle every stratum, and the reshuffled
//!   sample reaches `me.set_display_name` in a cell whose production text
//!   store keeps no display names yet (it fails closed under SA-11). That
//!   is a gap of the cell, recorded for the lead, not of this sample. The
//!   matrices over fake ports cover the three operations on every channel;
//!   the request bodies below are ready for when they rejoin, which a
//!   follow-up lane does once it fixes those display names;
//! - `Who::SuspendedReviewer` with a magic-link session: the cell refuses
//!   the login, since M3 design section 8.2 counts a suspended binding as
//!   held for I-77, while the reference counts it as not held
//!   (`roles-and-sod.md` Identity discovery). This waits for Daniel.
//!
//! The cells are split into strata by channel (web or MCP) and principal.
//! Each stratum is shuffled by a SplitMix64 stream from the fixed seed
//! [`SEED`] and the first [`PER_STRATUM`] cells are taken, so the sample
//! is the same on every run and covers every channel and principal that
//! the worlds hold. A cell the reference expects to complete a non-read
//! operation may change its world. Such a cell runs after every quiet
//! cell of its world, and the world is rebuilt after any cell that
//! appended an engine record. At most [`EFFECTFUL_PER_WORLD`] such cells
//! are taken per world, in stratum order, so the run stays inside one
//! CI part.
//!
//! # Readings
//!
//! - A management account cannot open a magic-link session: the cell
//!   refuses its login (I-77, ADR-008). Such a web cell observes the
//!   refused login as `StrongMethodRequired`, the class the reference
//!   gives every weak session of a management account. A public operation
//!   needs no session, so it is sent without one.
//! - A stale step-up is answered within P-71, and the world clock then
//!   moves past P-71 by one microsecond before the call is sent again.
//!
//! `FSTP_PG_MATRIX_LIMIT=<n>` runs only the first `n` sampled cells of each
//! world, for a local run, and `FSTP_PG_MATRIX_SKIP=<n>` skips the first `n`
//! of each world. `FSTP_PG_MATRIX_OPS=<a,b>` runs only the sampled cells of
//! those operations. Unset, the whole sample runs. Every account and text is
//! synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};

use fstp_api_testkit::matrix::{Cell, ChannelFault, Denial, Observed, agrees, class_of, matrix};
use fstp_api_testkit::reference::authz::{
    Channel as Via, Expected, Login, Policy, StateProfile, StepUp, Who,
};
use fstp_cell_core::CellCommand;
use fstp_cell_core::gate::{Action, HighRiskAction};
use fstp_celltest::cycle::Cycle;
use fstp_celltest::mc::auth_model::http::{AuthClient, Cookie, FIRST_ADMIN};
use fstp_celltest::reference::auth::RefMethod;
use fstp_celltest::world::{
    CellHandle, DbMode, HttpReply, HttpRequest, VaultLayout, World, WorldSpec,
};
use fstp_domain::StateTag;
use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Command as Core, DeclarationSubject, KnockOutResult};
use fstp_domain::decision::Vote;
use fstp_domain::id::{
    AccountId, AssignmentId, BindingId, CallId, DecisionId, Handle, OrganisationId, PlanVersionId,
    ProgrammeId, ProposalId,
};
use fstp_domain::roles::Role;
use fstp_domain::scoring::{ScoreKey, Stage};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{ADMIN_2, P1, STAFF_DRAFTER, STAFF_PM};
use fstp_json::{Array, Object, Value};

// ---------------------------------------------------------------------------
// The sample
// ---------------------------------------------------------------------------

/// The seed of the sample.
const SEED: u64 = 0x7a07_4c37_2026_1121;

/// The cells drawn per stratum of channel and principal.
const PER_STRATUM: usize = 5;

/// The most cells per world that the reference expects to complete a
/// non-read operation.
const EFFECTFUL_PER_WORLD: usize = 4;

/// The states the PostgreSQL worlds build.
const STATES: [StateProfile; 2] = [
    StateProfile::Proposal(StateTag::Submitted),
    StateProfile::Proposal(StateTag::IrcReview),
];

/// Operations whose cells need a ceremony per cell (module documentation).
const CEREMONY_OPS: [&str; 3] = ["me.add_passkey", "agents.consent", "agents.consent_request"];

/// The operations of ADR-030 (lane L22), left out of the candidates so the
/// sample stays the one it was (module documentation). Temporary: they
/// return once production display names (SA-11) work (ADR-030, lead
/// reading of 2026-11-22).
const ADR030_OPS: [&str; 4] = [
    "tenant.branding.logos",
    "tenant.branding.set_logo",
    "me.set_theme",
    "programme.logos",
];

/// A SplitMix64 stream.
struct Mix(u64);

impl Mix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A Fisher-Yates shuffle of `v`.
    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = usize::try_from(self.next() % (i as u64 + 1)).unwrap_or(0);
            v.swap(i, j);
        }
    }
}

/// Whether the PostgreSQL worlds hold the principal (module
/// documentation).
const fn realisable(who: Who) -> bool {
    !matches!(
        who,
        Who::SoleTenantAdmin | Who::FinancialSignatory | Who::VoidedLead
    )
}

/// Whether the reference expects `cell` to complete an operation that is
/// not a read: it may change its world.
fn effectful(expected: Expected, op: &str) -> bool {
    expected == Expected::Allow
        && fstp_access::op(op).is_some_and(|o| {
            !matches!(
                o.kind,
                fstp_access::OpKind::Read(_) | fstp_access::OpKind::Public(_)
            )
        })
}

/// The deterministic sample, by world state, in run order.
fn sample() -> BTreeMap<StateProfile, Vec<(Cell, Expected)>> {
    let m = matrix().unwrap_or_else(|e| panic!("the matrix: {e}"));
    let reference = m.reference().clone();
    // Strata of channel and principal, each in the matrix's order.
    let mut strata: BTreeMap<(bool, Who), Vec<(Cell, Expected)>> = BTreeMap::new();
    for state in STATES {
        for cell in m.group_cells(state, Policy::SUPERSAFE) {
            if cell.session.login == Some(Login::Opaque)
                || !realisable(cell.who)
                || CEREMONY_OPS.contains(&cell.op)
                || ADR030_OPS.contains(&cell.op)
                || (cell.who == Who::SuspendedReviewer
                    && cell.session.login == Some(Login::MagicLink))
            {
                continue;
            }
            let Some(expected) = reference.expected(&cell) else {
                continue;
            };
            let mcp = matches!(cell.session.channel, Via::Mcp { .. });
            strata
                .entry((mcp, cell.who))
                .or_default()
                .push((cell, expected));
        }
    }
    let mut mix = Mix(SEED);
    let mut effectful_taken: BTreeMap<StateProfile, usize> = BTreeMap::new();
    let mut out: BTreeMap<StateProfile, Vec<(Cell, Expected)>> = BTreeMap::new();
    for cells in strata.values_mut() {
        mix.shuffle(cells);
        let mut taken = 0;
        for (cell, expected) in cells.iter() {
            if taken == PER_STRATUM {
                break;
            }
            if effectful(*expected, cell.op) {
                let n = effectful_taken.entry(cell.state).or_insert(0);
                if *n >= EFFECTFUL_PER_WORLD {
                    continue;
                }
                *n += 1;
            }
            out.entry(cell.state).or_default().push((*cell, *expected));
            taken += 1;
        }
    }
    // Quiet cells first, then the effectful ones.
    for cells in out.values_mut() {
        cells.sort_by_key(|(c, e)| effectful(*e, c.op));
    }
    out
}

// ---------------------------------------------------------------------------
// The cast
// ---------------------------------------------------------------------------

/// The model ids of the sample's own accounts start here, apart from the
/// cycle's and the M2 generators'.
const CAST_BASE: u128 = 70_000;

const fn model(n: u128) -> AccountId {
    AccountId::from_raw(CAST_BASE + n)
}

const UNBOUND: AccountId = model(1);
const PM_ENDED: AccountId = model(2);
const PM_OTHER: AccountId = model(3);
const COORD: AccountId = model(10);
const COORD_UNDECLARED: AccountId = model(11);
const COORD_CONFLICTED: AccountId = model(12);
const CHAIR: AccountId = model(20);
const MEMBER: AccountId = model(21);
const REVIEWER: AccountId = model(22);
const REVIEWER_UNDECLARED: AccountId = model(23);
const REVIEWER_CONFLICTED: AccountId = model(24);
const REVIEWER_RELEASED: AccountId = model(25);
const REVIEWER_SUSPENDED: AccountId = model(26);
const RECUSED: AccountId = model(27);
const DELEGATOR: AccountId = model(28);
const REVIEWER_2: AccountId = model(29);
const IRC_MEMBER: AccountId = model(30);
const IRC_ASSIGNEE: AccountId = model(31);
const IRC_UNDECLARED: AccountId = model(32);
const IRC_CONFLICTED: AccountId = model(33);
const IRC_2: AccountId = model(34);
const LEAD: AccountId = model(40);
const TEAM: AccountId = model(41);
const GUARDIAN: AccountId = model(42);
const LEAD_Y: AccountId = model(43);
const FINANCE: AccountId = model(50);
const RELEASER: AccountId = model(51);
const SIGNATORY: AccountId = model(52);
const AUDITOR: AccountId = model(53);

/// The model account of a principal.
const fn account_of(who: Who) -> Option<AccountId> {
    Some(match who {
        Who::Anonymous | Who::SoleTenantAdmin | Who::FinancialSignatory | Who::VoidedLead => {
            return None;
        }
        Who::Unbound => UNBOUND,
        Who::TenantAdmin => ADMIN_2,
        Who::TenantAdminBuilder => FIRST_ADMIN,
        Who::ProgrammeManager => STAFF_PM,
        Who::ProgrammeManagerDrafter => fstp_celltest::cycle::BUILDER,
        Who::EndedProgrammeManager => PM_ENDED,
        Who::OtherProgrammeManager => PM_OTHER,
        Who::CallDrafter => STAFF_DRAFTER,
        Who::Coordinator => COORD,
        Who::CoordinatorUndeclared => COORD_UNDECLARED,
        Who::CoordinatorConflicted => COORD_CONFLICTED,
        Who::CommitteeMember => MEMBER,
        Who::CommitteeChair => CHAIR,
        Who::AssignedReviewer => REVIEWER,
        Who::AssignedReviewerUndeclared => REVIEWER_UNDECLARED,
        Who::AssignedReviewerConflicted => REVIEWER_CONFLICTED,
        Who::ReleasedReviewer => REVIEWER_RELEASED,
        Who::SuspendedReviewer => REVIEWER_SUSPENDED,
        Who::RecusedCommitteeMember => RECUSED,
        Who::DelegatingCommitteeMember => DELEGATOR,
        Who::IrcMember => IRC_MEMBER,
        Who::IrcAssignee => IRC_ASSIGNEE,
        Who::IrcAssigneeUndeclared => IRC_UNDECLARED,
        Who::IrcAssigneeConflicted => IRC_CONFLICTED,
        Who::Lead => LEAD,
        Who::TeamMember => TEAM,
        Who::Guardian => GUARDIAN,
        Who::FinanceApprover => FINANCE,
        Who::PaymentReleaser => RELEASER,
        Who::ContractSignatory => SIGNATORY,
        Who::Auditor => AUDITOR,
    })
}

/// Whether the model account holds a Drafting, Judging or Operations
/// role or is a tenant admin in every world (I-77).
fn management(who: Who) -> bool {
    who.management()
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

const REDIRECT: &str = "http://127.0.0.1:8765/callback";
const VERIFIER: &str = "l7-verifier-0123456789abcdefghijklmnopqrstuvwxyz";
const MODERN: &str = "2026-07-28";
const DAY: i64 = 86_400_000_000;

fn json(r: &HttpReply) -> Value {
    fstp_json::parse(&r.body).unwrap_or(Value::Null)
}

fn text(r: &HttpReply) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn str_member(v: &Value, k: &str) -> Option<String> {
    v.as_object()?.get(k)?.as_str().map(str::to_owned)
}

fn obj(members: Vec<(&str, Value)>) -> Value {
    let mut o = Object::new();
    for (k, v) in members {
        let _ = o.insert(k, v);
    }
    Value::Object(o)
}

fn s(x: &str) -> Value {
    Value::String(x.to_owned())
}

fn dec(x: u128) -> Value {
    Value::String(x.to_string())
}

fn send(cell: &CellHandle, req: HttpRequest) -> HttpReply {
    cell.request(&req.header("host", cell.host()))
        .unwrap_or_else(|e| panic!("{e}"))
}

/// A web API call, as `web/src/core/api.ts` sends it. `path` is the full
/// path.
fn web(
    cell: &CellHandle,
    method: &str,
    path: &str,
    cookie: Option<&Cookie>,
    body: &[u8],
) -> HttpReply {
    let mut r = HttpRequest::new(method, path).header("accept", "application/json");
    if let Some(c) = cookie {
        r = r.header("cookie", c.0.clone());
    }
    if method != "GET" {
        r = r
            .header("origin", format!("https://{}", cell.host()))
            .header("x-fstp-request", "1");
    }
    if !body.is_empty() {
        r = r
            .header("content-type", "application/json")
            .body(body.to_vec());
    }
    send(cell, r)
}

/// The challenge of a `step_up_required` reply: its id and bytes.
fn challenge_of(r: &HttpReply) -> Option<(String, [u8; 32])> {
    let v = json(r);
    if str_member(&v, "code").as_deref() != Some("step_up_required") {
        return None;
    }
    let ch = v.as_object()?.get("challenge")?;
    let id = str_member(ch, "challenge_id")?;
    let bytes = ch
        .as_object()?
        .get("public_key")
        .and_then(|p| str_member(p, "challenge"))?;
    let challenge: [u8; 32] = fstp_oauth::decode_base64url(bytes.as_bytes())
        .ok()?
        .as_bytes()
        .try_into()
        .ok()?;
    Some((id, challenge))
}

/// A modern MCP request.
fn mcp(
    cell: &CellHandle,
    bearer: Option<&str>,
    method: &str,
    name: Option<&str>,
    params: &str,
) -> HttpReply {
    let sep = if params.is_empty() { "" } else { "," };
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{{{params}{sep}"_meta":{{"io.modelcontextprotocol/protocolVersion":"{MODERN}","io.modelcontextprotocol/clientInfo":{{"name":"synthetic-agent","version":"0.0.1"}},"io.modelcontextprotocol/clientCapabilities":{{}}}}}}}}"#
    );
    let mut r = HttpRequest::new(
        "POST",
        if bearer.is_some() {
            "/mcp"
        } else {
            "/mcp/public"
        },
    )
    .header("content-type", "application/json")
    .header("accept", "application/json, text/event-stream")
    .header("mcp-protocol-version", MODERN)
    .header("mcp-method", method)
    .body(body.into_bytes());
    if let Some(b) = bearer {
        r = r.header("authorization", format!("Bearer {b}"));
    }
    if let Some(n) = name {
        r = r.header("mcp-name", n);
    }
    send(cell, r)
}

/// The JSON-RPC message of an MCP reply, plain or as one SSE event.
fn rpc_of(r: &HttpReply) -> Value {
    let t = text(r);
    let body = t
        .lines()
        .find_map(|l| l.strip_prefix("data:"))
        .map_or(t.as_str(), str::trim);
    fstp_json::parse(body.as_bytes()).unwrap_or(Value::Null)
}

// ---------------------------------------------------------------------------
// A world
// ---------------------------------------------------------------------------

/// The objects of a world that cells act on, by cell id.
#[derive(Default)]
struct Targets {
    programme: Option<ProgrammeId>,
    call: Option<CallId>,
    proposal: Option<ProposalId>,
    plan: Option<PlanVersionId>,
    assignments: BTreeMap<AccountId, AssignmentId>,
    irc: BTreeMap<AccountId, AssignmentId>,
    round: Option<DecisionId>,
    ranked: Vec<ProposalId>,
    binding_end: Option<BindingId>,
    binding_suspended: Option<BindingId>,
    pm_binding: Option<BindingId>,
    knock_outs: Vec<u128>,
    criteria: usize,
    scale: u32,
    /// The head revision of the draft of P, as `creator.get_draft` shows it.
    revision: String,
    /// The key of the roster warning the cycle's builder acknowledged, as
    /// the draft report names it (`fstp_api_core` `warning_key`).
    warning: String,
}

/// One built world: its client, its OAuth client and its targets.
struct Pg<'w> {
    client: AuthClient<'w>,
    agent: String,
    t: Targets,
    next: u128,
    /// The engine entries the cell held once the world was built.
    engine_head: usize,
}

impl<'w> Pg<'w> {
    fn cell(&self) -> &'w CellHandle {
        self.client.cell()
    }

    fn now(&self) -> i64 {
        self.cell().clock().now()
    }

    fn fresh(&mut self) -> u128 {
        self.next += 1;
        self.next
    }

    /// The cell account of a model account.
    fn id(&self, model: AccountId) -> AccountId {
        self.client
            .cell_account(model)
            .unwrap_or_else(|| panic!("{} is not enrolled", model.raw()))
    }

    fn session(&self, model: AccountId) -> Cookie {
        self.client
            .login(model, RefMethod::Passkey)
            .unwrap()
            .unwrap_or_else(|| panic!("the passkey login of {} was refused", model.raw()))
    }

    /// `command` by `model`, with a step-up where the gate asks for one.
    /// It must commit.
    fn by(&mut self, model: AccountId, command: CellCommand) {
        let stepup = !matches!(
            HighRiskAction::of(&Action::Command(command.clone())),
            Ok(None)
        );
        let session = self.session(model);
        let r = self
            .client
            .command_reply(&session, &command, stepup)
            .unwrap()
            .unwrap_or_else(|| panic!("the step-up of {command:?} was refused"));
        assert!(
            r.ok(),
            "the world command {command:?} by {}: {} {}",
            model.raw(),
            r.status,
            String::from_utf8_lossy(&r.body)
        );
    }

    /// A web API call by `model` in a fresh passkey session, answering a
    /// step-up challenge once. It must succeed: its body.
    fn api(&self, model: AccountId, method: &str, path: &str, body: &Value) -> Value {
        let session = self.session(model);
        let bytes = body.to_compact().into_bytes();
        let full = format!("/api/v1{path}");
        let mut r = web(self.cell(), method, &full, Some(&session), &bytes);
        if let Some((id, ch)) = challenge_of(&r) {
            assert!(self.client.prove_api_step_up(&session, &id, ch).unwrap());
            r = web(self.cell(), method, &full, Some(&session), &bytes);
        }
        assert!(
            r.ok(),
            "the world call {method} {path} by {}: {} {}",
            model.raw(),
            r.status,
            text(&r)
        );
        json(&r)
    }

    fn core(&mut self, model: AccountId, c: Core) {
        self.by(model, CellCommand::Engine(fstp_engine::Command::Core(c)));
    }

    fn enrol(&self, model: AccountId) {
        assert!(
            self.client.enrol(model).unwrap(),
            "the enrolment of {}",
            model.raw()
        );
    }

    /// Seeds a verification of `model` with the identity `tuple`.
    fn verify(&self, model: AccountId, tuple: &str) {
        self.cell()
            .seed_verification(self.id(model), tuple.as_bytes())
            .unwrap_or_else(|e| panic!("the seeded verification of {}: {e}", model.raw()));
    }

    fn grant(
        &mut self,
        grantor: AccountId,
        model: AccountId,
        p: ProgrammeId,
        role: Role,
    ) -> BindingId {
        let binding = BindingId::from_raw(self.fresh());
        let account = self.id(model);
        let start = Timestamp::from_micros(self.now());
        let staff = !matches!(
            role,
            Role::Applicant | Role::ApplicantTeamMember | Role::Guardian
        );
        self.core(
            grantor,
            Core::GrantRole {
                binding,
                account,
                programme: p,
                role,
                start,
                second_admin: None,
                confidentiality: staff
                    .then(|| fstp_domain_testkit::r#gen::policy::text(binding.raw() + 50_000)),
                organisation: matches!(role, Role::CommitteeMember | Role::CommitteeChair)
                    .then(|| OrganisationId::from_raw(account.raw())),
                end: None,
            },
        );
        binding
    }

    fn assign(&mut self, x: ProposalId, model: AccountId, kind: AssignmentKind) -> AssignmentId {
        let a = AssignmentId::from_raw(self.fresh());
        let reviewer = self.id(model);
        self.core(
            COORD,
            Core::Assign {
                assignment: a,
                proposal: x,
                reviewer,
                kind,
                handle: Some(Handle::from_bytes(a.raw().to_be_bytes())),
            },
        );
        a
    }

    fn declare(&mut self, model: AccountId, subject: DeclarationSubject, conflicted: bool) {
        self.core(
            model,
            Core::DeclareConflict {
                subject,
                conflicted,
                notifiable: false,
            },
        );
    }

    /// The number of engine entries the cell holds.
    fn engine_entries(&self) -> usize {
        self.cell()
            .cell_engine()
            .unwrap()
            .engine_entries_after(fstp_ledger::Seq::from_raw(0))
            .len()
    }

    /// The engine state.
    fn state(&self) -> std::sync::Arc<fstp_cell_core::CellState> {
        self.cell().cell_engine().unwrap().state()
    }

    /// Moves the clock to `t`, if later.
    fn at(&self, t: i64) {
        if t > self.now() {
            self.cell().clock().set(t);
        }
    }
}

/// The world start: one SaaS cell with the API core mounted.
fn start() -> World {
    World::start_with_api(WorldSpec {
        cells: 1,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("{e}"))
}

/// Builds the world of `state` on the cell of `world` (module
/// documentation).
fn build(world: &World, state: StateProfile) -> Pg<'_> {
    let StateProfile::Proposal(target) = state else {
        panic!("no PostgreSQL world of {state:?}");
    };
    let cell = world.cell(0).unwrap();
    let mut cycle = Cycle::new(cell);
    for step in ["login", "create-programme"] {
        cycle
            .step(step)
            .unwrap_or_else(|e| panic!("the cycle step {step}: {e}"));
    }
    p09_wording(cell, cycle.client());
    cycle
        .step("publish-call")
        .unwrap_or_else(|e| panic!("the cycle step publish-call: {e}"));
    let client = cycle.into_client();
    let mut w = Pg {
        client,
        agent: String::new(),
        t: Targets::default(),
        next: 7_000_000,
        engine_head: 0,
    };
    let p = P1;
    w.t.programme = Some(p);
    let call = w
        .state()
        .engine()
        .core
        .calls()
        .iter()
        .map(|(c, _)| c)
        .max_by_key(|c| c.raw())
        .expect("the cycle's call");
    w.t.call = Some(call);
    // The policy row of P: the SuperSAFE column (the cycle saves the
    // SuperSAFE fixture).
    {
        let st = w.state();
        let v = fstp_domain::policy::head(&st.engine().core, p).expect("the policy of P");
        assert_eq!(
            v.frozen.p10,
            fstp_domain::policy::ReadAccess::AssignedReviewersOnly,
            "P-10 of P"
        );
        w.t.criteria = v.frozen.p01.items().len();
        w.t.scale = u32::from(v.frozen.p01.scale_max().get());
        w.t.knock_outs = v.frozen.p09.0.iter().map(|k| k.id.raw()).collect();
    }
    // The cast.
    let cast = [
        UNBOUND,
        PM_ENDED,
        PM_OTHER,
        COORD,
        COORD_UNDECLARED,
        COORD_CONFLICTED,
        CHAIR,
        MEMBER,
        REVIEWER,
        REVIEWER_UNDECLARED,
        REVIEWER_CONFLICTED,
        REVIEWER_RELEASED,
        REVIEWER_SUSPENDED,
        RECUSED,
        DELEGATOR,
        REVIEWER_2,
        IRC_MEMBER,
        IRC_ASSIGNEE,
        IRC_UNDECLARED,
        IRC_CONFLICTED,
        IRC_2,
        LEAD,
        TEAM,
        GUARDIAN,
        LEAD_Y,
        FINANCE,
        RELEASER,
        SIGNATORY,
        AUDITOR,
    ];
    for m in cast {
        w.enrol(m);
        w.verify(m, &format!("pg-matrix-person-{}", m.raw()));
    }
    // The leads are adults (I-18).
    for m in [LEAD, LEAD_Y, TEAM] {
        cell.seed_vault_fact(
            fstp_celltest::vault_seed::SeedSource::SyntheticVerification,
            fstp_vault_core::fact::Fact::AdultAttestation {
                account: fstp_vault_proto::WireAccount(w.id(m).raw()),
                adult_from: fstp_celltest::world::WORLD_CLOCK_START,
            },
        )
        .unwrap_or_else(|e| panic!("the attestation of {}: {e}", m.raw()));
    }
    // The staff of P.
    let g = FIRST_ADMIN;
    let ended = w.grant(g, PM_ENDED, p, Role::ProgrammeManager);
    for a in [COORD, COORD_UNDECLARED, COORD_CONFLICTED] {
        w.grant(g, a, p, Role::FstpCoordinator);
    }
    w.grant(g, CHAIR, p, Role::CommitteeChair);
    let mut suspended = None;
    for a in [
        MEMBER,
        REVIEWER,
        REVIEWER_UNDECLARED,
        REVIEWER_CONFLICTED,
        REVIEWER_RELEASED,
        REVIEWER_SUSPENDED,
        RECUSED,
        DELEGATOR,
        REVIEWER_2,
    ] {
        let b = w.grant(g, a, p, Role::CommitteeMember);
        if a == REVIEWER_SUSPENDED {
            suspended = Some(b);
        }
    }
    for a in [
        IRC_MEMBER,
        IRC_ASSIGNEE,
        IRC_UNDECLARED,
        IRC_CONFLICTED,
        IRC_2,
    ] {
        w.grant(g, a, p, Role::IrcMember);
    }
    w.grant(g, FINANCE, p, Role::FinanceApprover);
    w.grant(g, RELEASER, p, Role::PaymentReleaser);
    w.grant(g, SIGNATORY, p, Role::ContractSignatory);
    w.grant(g, AUDITOR, p, Role::Auditor);
    w.t.binding_suspended = suspended;
    // The programme manager's binding, which `identity.unmask` names, and
    // the call drafter's, which `roles.end` names.
    {
        let st = w.state();
        let roster = st.engine().core.roster();
        let pm = w.id(STAFF_PM);
        let drafter = w.id(STAFF_DRAFTER);
        w.t.pm_binding = roster
            .bindings()
            .find(|(_, b)| b.account == pm && b.programme == p)
            .map(|(id, _)| id);
        w.t.binding_end = roster
            .bindings()
            .find(|(_, b)| b.account == drafter && b.programme == p)
            .map(|(id, _)| id);
    }
    // P2, a draft with its own programme manager.
    let p2 = ProgrammeId::from_raw(7_777);
    {
        let he = fstp_programme::FunderProfile::horizon_europe();
        let version = fstp_domain::id::PolicyVersionId::from_raw(7_777);
        let profile = fstp_programme::compile(
            &he.blank(),
            &he,
            fstp_programme::CompileIds::new(p2, version, None),
        )
        .expect("the blank policy")
        .policy
        .frozen
        .p53;
        w.by(
            FIRST_ADMIN,
            CellCommand::Engine(fstp_engine::Command::Creator(
                fstp_creator::CreatorCommand::OpenDraft {
                    programme: p2,
                    version,
                    profile,
                    name: None,
                },
            )),
        );
        w.grant(FIRST_ADMIN, PM_OTHER, p2, Role::ProgrammeManager);
    }
    // X, with its team, while C is open.
    let (opens, deadline) = {
        let st = w.state();
        let view = st.engine().core.calls().get(call).expect("C");
        (view.opens().micros(), view.deadline().micros())
    };
    w.at(opens + DAY / 24);
    let (x, plan) = draft(&mut w, LEAD, call, true, deadline);
    w.t.proposal = Some(x);
    w.t.plan = Some(plan);
    let with_y = target != StateTag::Submitted;
    let y = with_y.then(|| draft(&mut w, LEAD_Y, call, false, deadline));
    submit(&mut w, LEAD, x);
    if let Some((yp, _)) = y {
        submit(&mut w, LEAD_Y, yp);
    }
    // After the deadline.
    w.at(deadline + 1_000_000);
    w.declare(COORD, DeclarationSubject::Proposal(x), false);
    w.declare(COORD_CONFLICTED, DeclarationSubject::Proposal(x), true);
    let mut reviewers = vec![
        REVIEWER,
        REVIEWER_2,
        REVIEWER_CONFLICTED,
        REVIEWER_RELEASED,
        REVIEWER_SUSPENDED,
    ];
    if target == StateTag::Submitted {
        reviewers.push(REVIEWER_UNDECLARED);
    }
    let mut assigned = BTreeMap::new();
    for r in &reviewers {
        let a = w.assign(x, *r, AssignmentKind::Reviewer);
        assigned.insert(*r, a);
    }
    for r in [REVIEWER, REVIEWER_2, REVIEWER_SUSPENDED] {
        w.declare(r, DeclarationSubject::Assignment(assigned[&r]), false);
    }
    w.declare(
        REVIEWER_CONFLICTED,
        DeclarationSubject::Assignment(assigned[&REVIEWER_CONFLICTED]),
        true,
    );
    w.core(
        COORD,
        Core::Unassign {
            assignment: assigned[&REVIEWER_RELEASED],
        },
    );
    if target == StateTag::IrcReview {
        irc_review(&mut w, call, x, plan, y.expect("Y"), &assigned);
    }
    w.t.assignments = assigned.iter().map(|(m, a)| (w.id(*m), *a)).collect();
    // The suspended reviewer shares the identity of the call drafter, a
    // Drafting holder: the cell's reaction suspends its Judging binding
    // (I-06, identity discovery).
    let tuple = "pg-matrix-shared-identity";
    w.verify(STAFF_DRAFTER, tuple);
    w.verify(REVIEWER_SUSPENDED, tuple);
    let now = Timestamp::from_micros(w.now());
    cell.block_on(cell.cell_engine().unwrap().react_to_vault(now))
        .unwrap()
        .unwrap_or_else(|e| panic!("the vault reaction: {e:?}"));
    {
        let st = w.state();
        let status = st
            .engine()
            .core
            .roster()
            .binding(suspended.expect("the binding"))
            .map(|b| b.status);
        assert!(
            matches!(
                status,
                Some(fstp_domain::roles::BindingStatus::Suspended(_))
            ),
            "the suspended reviewer's binding is {status:?}"
        );
    }
    // The ended programme manager.
    w.core(
        ADMIN_2,
        Core::EndRole {
            binding: ended,
            at: Timestamp::from_micros(w.now()),
        },
    );
    w.at(w.now() + 1_000_000);
    // The OAuth client every MCP cell's token is issued to.
    w.t.revision = {
        let st = w.state();
        st.engine().creator.head(p).map_or_else(
            || "1.1".to_owned(),
            |r| format!("{}.{}", r.seq(), r.entry().raw()),
        )
    };
    w.t.warning = {
        use fstp_json::ToJson as _;
        let ack = fstp_creator::CreatorCommand::AcknowledgeWarning {
            programme: p,
            revision: fstp_creator::DraftRevision::new(0, fstp_ledger::Seq::ZERO),
            warning: fstp_creator::WarningKey {
                check: fstp_creator::CheckId::RosterShort,
                subject: fstp_creator::CheckSubject::Draft,
            },
        }
        .to_json();
        ack.as_object()
            .and_then(|o| o.get("warning"))
            .and_then(|v| fstp_json::to_canonical(v).ok())
            .unwrap_or_else(|| "null".to_owned())
    };
    w.agent = register(cell);
    w.engine_head = w.engine_entries();
    w
}

/// The day `micros` as `YYYY-MM-DD`, for days within 1970 (the world
/// clock starts there).
fn day_of(micros: i64) -> String {
    const MONTHS: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut d = micros.div_euclid(DAY);
    let mut m = 0usize;
    for (i, len) in MONTHS.iter().enumerate() {
        if d < *len {
            m = i;
            break;
        }
        d -= *len;
        m = i + 1;
    }
    format!("1970-{:02}-{:02}", m + 1, d + 1)
}

/// The P-09 wording of P as public texts of the cell's text store, which
/// the knock-out reads open (`fstp_api_core` `knock_out_criteria`). The
/// cycle's spec names synthetic text ids that no store holds
/// (`fstp_celltest::cycle::synthetic_spec`). So each wording is stored as
/// the cell's text store keeps a public text, its class and owner in an
/// 18-byte header (`fstp_cell::api::content`), and the builder of P
/// points P-09 at them with one `EditPolicy` before C is published. The
/// builder already wrote P-09, so its authors stay the same (R-PC-03).
fn p09_wording(cell: &CellHandle, client: &AuthClient<'_>) {
    let st = cell.cell_engine().unwrap().state();
    let head = fstp_domain::policy::head(&st.engine().core, P1)
        .expect("the policy of P")
        .clone();
    let mut v = fstp_domain_testkit::r#gen::policy::next_version(
        &head,
        fstp_domain::id::PolicyVersionId::from_raw(7_000_001),
    );
    for (n, k) in v.frozen.p09.0.iter_mut().enumerate() {
        let id = (1u128 << 90) + u128::try_from(n).unwrap_or(0);
        let wording = format!("SYNTHETIC KNOCK-OUT CRITERION {n}");
        let mut plain = vec![2u8, 2u8];
        plain.extend_from_slice(&P1.raw().to_be_bytes());
        plain.extend_from_slice(wording.as_bytes());
        cell.store_text(id.to_be_bytes(), &plain)
            .unwrap_or_else(|e| panic!("the P-09 text {id}: {e}"));
        k.text = fstp_domain::id::TextRef::new(
            fstp_domain::id::TextId::from_raw(id),
            fstp_domain::id::ContentDigest::from_bytes(fstp_crypto::sha256(wording.as_bytes())),
        );
    }
    let builder = client
        .login(fstp_celltest::cycle::BUILDER, RefMethod::Passkey)
        .unwrap()
        .expect("the builder's session");
    // Each text's `PutOwnedText`, so the cycle's publication finds it
    // stored (`Cycle` `store_call_texts`).
    let owner = client
        .cell_account(fstp_celltest::cycle::BUILDER)
        .expect("the builder");
    for k in &v.frozen.p09.0 {
        let put = CellCommand::Text(fstp_cell_core::text::TextCommand::PutOwnedText {
            id: k.text.id().raw().to_be_bytes(),
            owner: fstp_cell_core::text::TextOwner::Account(owner),
            len: 64,
        });
        let r = client
            .command_reply(&builder, &put, false)
            .unwrap()
            .expect("the text record");
        assert!(
            r.ok(),
            "PutOwnedText: {} {}",
            r.status,
            String::from_utf8_lossy(&r.body)
        );
    }
    let edit = CellCommand::Engine(fstp_engine::Command::Core(Core::EditPolicy {
        base: head.id,
        version: Box::new(v),
    }));
    let r = client
        .command_reply(&builder, &edit, false)
        .unwrap()
        .expect("the edit");
    assert!(
        r.ok(),
        "the P-09 edit: {} {}",
        r.status,
        String::from_utf8_lossy(&r.body)
    );
}

/// A draft of `lead` in `c` through the web API, with its team, plan and
/// workspace, as the test kit's harness drafts: its id and plan.
fn draft(
    w: &mut Pg<'_>,
    lead: AccountId,
    c: CallId,
    team: bool,
    deadline: i64,
) -> (ProposalId, PlanVersionId) {
    let body = w.api(
        lead,
        "POST",
        &format!("/calls/{}/proposals", c.raw()),
        &obj(vec![]),
    );
    let raw: u128 = str_member(&body, "proposal")
        .and_then(|x| x.parse().ok())
        .unwrap_or_else(|| panic!("proposal.create gave {}", body.to_compact()));
    if team {
        let t = w.id(TEAM).raw();
        let g = w.id(GUARDIAN).raw();
        w.api(
            lead,
            "POST",
            &format!("/proposals/{raw}/team"),
            &obj(vec![("account", dec(t))]),
        );
        w.api(
            lead,
            "POST",
            &format!("/proposals/{raw}/guardian"),
            &obj(vec![("account", dec(g))]),
        );
    }
    let start = deadline + 10 * DAY;
    let plan_body = obj(vec![
        ("description", s("SYNTHETIC WORK PLAN")),
        (
            "tasks",
            Value::Array(Array::from(vec![obj(vec![(
                "milestones",
                Value::Array(Array::from(vec![obj(vec![
                    ("amount", s("20000.00")),
                    ("start", s(&day_of(start))),
                    ("due", s(&day_of(start + 150 * DAY))),
                ])])),
            )])])),
        ),
    ]);
    let plan = w.api(lead, "PUT", &format!("/proposals/{raw}/plan"), &plan_body);
    let plan: u128 = str_member(&plan, "plan")
        .and_then(|x| x.parse().ok())
        .unwrap_or_else(|| panic!("proposal.record_plan gave {}", plan.to_compact()));
    w.api(
        lead,
        "PUT",
        &format!("/proposals/{raw}/workspace"),
        &obj(vec![
            ("narrative", s("SYNTHETIC NARRATIVE")),
            ("summary", s("SYNTHETIC SUMMARY")),
            ("title", s("SYNTHETIC TITLE")),
        ]),
    );
    (ProposalId::from_raw(raw), PlanVersionId::from_raw(plan))
}

/// Submits `x` through the web API.
fn submit(w: &mut Pg<'_>, lead: AccountId, x: ProposalId) {
    w.api(
        lead,
        "POST",
        &format!("/proposals/{}/submission", x.raw()),
        &obj(vec![("ethics", s("none")), ("notice_version", s("1"))]),
    );
}

/// X and Y from SUBMITTED to IRC_REVIEW of X (module documentation).
fn irc_review(
    w: &mut Pg<'_>,
    call: CallId,
    x: ProposalId,
    plan: PlanVersionId,
    (y, yplan): (ProposalId, PlanVersionId),
    assigned: &BTreeMap<AccountId, AssignmentId>,
) {
    // Y's reviewers: the two scorers and the recused member.
    w.declare(COORD, DeclarationSubject::Proposal(y), false);
    let mut ya = BTreeMap::new();
    for r in [REVIEWER, REVIEWER_2, RECUSED] {
        ya.insert(r, w.assign(y, r, AssignmentKind::Reviewer));
    }
    for r in [REVIEWER, REVIEWER_2] {
        w.declare(r, DeclarationSubject::Assignment(ya[&r]), false);
    }
    w.declare(RECUSED, DeclarationSubject::Assignment(ya[&RECUSED]), true);
    let kos: Vec<KnockOutResult> =
        w.t.knock_outs
            .iter()
            .map(|k| KnockOutResult {
                criterion: fstp_domain::id::KnockOutCriterionId::from_raw(*k),
                passed: true,
            })
            .collect();
    for q in [x, y] {
        let decision = DecisionId::from_raw(w.fresh());
        w.core(
            COORD,
            Core::RecordKnockOut {
                decision,
                proposal: q,
                outcomes: kos.clone(),
                reason: None,
            },
        );
        let decision = DecisionId::from_raw(w.fresh());
        w.core(
            COORD,
            Core::AdmitToStage1 {
                decision,
                proposal: q,
            },
        );
    }
    let n = w.t.criteria;
    let max = u8::try_from(w.t.scale).unwrap_or(5);
    let top: Vec<u8> = vec![max; n];
    let mut lower = top.clone();
    lower[0] = max.saturating_sub(1);
    let score = |w: &mut Pg<'_>, r: AccountId, a: AssignmentId, plan: PlanVersionId, v: &[u8]| {
        let key = ScoreKey {
            assignment: a,
            stage: Stage::One,
            plan,
        };
        let step = fstp_domain_testkit::mc::life_model::score(r, key, v);
        w.core(r, step.cmd);
    };
    for r in [REVIEWER, REVIEWER_2, REVIEWER_SUSPENDED] {
        score(w, r, assigned[&r], plan, &top);
    }
    w.core(COORD, Core::CloseStage1 { proposal: x });
    for r in [REVIEWER, REVIEWER_2] {
        score(w, r, ya[&r], yplan, &lower);
    }
    w.core(COORD, Core::CloseStage1 { proposal: y });
    // Stage 2: "no questions" ranks each.
    for r in [REVIEWER, REVIEWER_2, REVIEWER_SUSPENDED] {
        w.core(
            r,
            Core::RecordNoQuestions {
                proposal: x,
                assignment: assigned[&r],
            },
        );
    }
    for r in [REVIEWER, REVIEWER_2] {
        w.core(
            r,
            Core::RecordNoQuestions {
                proposal: y,
                assignment: ya[&r],
            },
        );
    }
    // The round: X first. The delegator votes through the member.
    let round = DecisionId::from_raw(w.fresh());
    let open =
        fstp_domain_testkit::mc::life_model::open_round(MEMBER, round, call, vec![x, y], 1, false);
    let mut cmd = open.cmd;
    if let Core::OpenCutOffRound { .. } = &mut cmd {
    } else {
        panic!("open_round gave {cmd:?}");
    }
    w.core(MEMBER, cmd);
    w.t.round = Some(round);
    w.t.ranked = vec![x, y];
    let to = w.id(MEMBER);
    w.core(DELEGATOR, Core::DelegateVote { round, to });
    for m in [
        MEMBER,
        CHAIR,
        REVIEWER,
        REVIEWER_2,
        REVIEWER_RELEASED,
        REVIEWER_SUSPENDED,
    ] {
        w.core(
            m,
            Core::CastBallot {
                round,
                vote: Vote::For,
            },
        );
    }
    w.core(MEMBER, Core::RecordCutOff { round });
    // IRC review of X.
    for i in [IRC_ASSIGNEE, IRC_2, IRC_CONFLICTED, IRC_UNDECLARED] {
        let a = w.assign(x, i, AssignmentKind::Irc);
        let id = w.id(i);
        w.t.irc.insert(id, a);
    }
    for i in [IRC_ASSIGNEE, IRC_2] {
        let a = w.t.irc[&w.id(i)];
        w.declare(i, DeclarationSubject::Assignment(a), false);
    }
    let a = w.t.irc[&w.id(IRC_CONFLICTED)];
    w.declare(IRC_CONFLICTED, DeclarationSubject::Assignment(a), true);
}

/// Registers the OAuth client of the world's MCP cells.
fn register(cell: &CellHandle) -> String {
    let r = send(
        cell,
        HttpRequest::new("POST", "/oauth/register")
            .header("content-type", "application/json")
            .body(
                format!(r#"{{"client_name":"Synthetic agent","redirect_uris":["{REDIRECT}"]}}"#)
                    .into_bytes(),
            ),
    );
    assert_eq!(r.status, 201, "registration: {}", text(&r));
    str_member(&json(&r), "client_id").expect("client_id")
}

/// An access token of `model` for `scopes`, consented in a passkey
/// session with a step-up (ADR-013).
fn token(w: &Pg<'_>, model: AccountId, scopes: &str) -> String {
    let cell = w.cell();
    let challenge = fstp_oauth::encode_base64url(&fstp_crypto::sha256(VERIFIER.as_bytes()));
    let resource = format!("https://{}/mcp", cell.host());
    let q = fstp_oauth::encode_form_urlencoded(&[
        ("response_type", "code"),
        ("client_id", w.agent.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("scope", scopes),
        ("state", "synthetic-state"),
        ("resource", resource.as_str()),
    ]);
    let r = send(
        cell,
        HttpRequest::new("GET", &format!("/oauth/authorize?{q}")),
    );
    assert_eq!(r.status, 303, "authorize: {}", text(&r));
    let to = String::from_utf8(r.header("location").unwrap().to_vec()).unwrap();
    let handle = to.strip_prefix("/app/connect#").unwrap().to_owned();
    let session = w.session(model);
    let body = format!(r#"{{"consent":"{handle}"}}"#);
    let asked = web(
        cell,
        "POST",
        "/api/v1/oauth/consent",
        Some(&session),
        body.as_bytes(),
    );
    let (id, ch) = challenge_of(&asked)
        .unwrap_or_else(|| panic!("the consent asked no step-up: {}", text(&asked)));
    assert!(w.client.prove_api_step_up(&session, &id, ch).unwrap());
    let done = web(
        cell,
        "POST",
        "/api/v1/oauth/consent",
        Some(&session),
        body.as_bytes(),
    );
    assert_eq!(done.status, 200, "the consent: {}", text(&done));
    let to = text(&done);
    let code = to
        .split(['?', '&', '"'])
        .find_map(|p| p.strip_prefix("code="))
        .unwrap()
        .to_owned();
    let form = fstp_oauth::encode_form_urlencoded(&[
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("client_id", w.agent.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("resource", resource.as_str()),
    ]);
    let r = send(
        cell,
        HttpRequest::new("POST", "/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form.into_bytes()),
    );
    assert_eq!(r.status, 200, "token: {}", text(&r));
    str_member(&json(&r), "access_token").expect("access_token")
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// One request of an operation: its method, path relative to `/api/v1`
/// (or absolute under `/p/`), body and path parameters.
struct Request {
    method: &'static str,
    path: String,
    body: Object,
    params: Object,
}

impl Request {
    fn body_bytes(&self) -> Vec<u8> {
        if self.method == "GET" && self.body.is_empty() {
            return Vec::new();
        }
        Value::Object(self.body.clone()).to_compact().into_bytes()
    }

    fn tool_args(&self) -> String {
        let mut o = self.params.clone();
        for (k, v) in self.body.iter() {
            let _ = o.insert(k, v.clone());
        }
        Value::Object(o).to_compact()
    }
}

/// The path parameter `name` of a cell's request.
fn param(w: &Pg<'_>, name: &str, op: &str, who: Who, session: Option<&str>) -> String {
    let t = &w.t;
    let me = account_of(who).and_then(|m| w.client.cell_account(m));
    let id = |x: Option<u128>| x.map_or_else(|| "1".to_owned(), |v| v.to_string());
    match (name, op) {
        ("binding", "roles.reinstate") => id(t.binding_suspended.map(|b| b.raw())),
        ("programme", _) => id(t.programme.map(|p| p.raw())),
        ("slug", _) => "supersafe".to_owned(),
        ("call", _) => id(t.call.map(|c| c.raw())),
        ("proposal", _) => id(t.proposal.map(|p| p.raw())),
        ("assignment", _) => {
            let own = me.and_then(|a| t.assignments.get(&a).copied());
            let any = t
                .assignments
                .get(&w.id(REVIEWER))
                .copied()
                .or_else(|| t.assignments.values().next().copied());
            id(own.or(any).map(|a| a.raw()))
        }
        ("irc_assignment", _) => {
            let own = me.and_then(|a| t.irc.get(&a).copied());
            let any = w
                .client
                .cell_account(IRC_ASSIGNEE)
                .and_then(|a| t.irc.get(&a).copied())
                .or_else(|| t.irc.values().next().copied());
            id(own.or(any).map(|a| a.raw()))
        }
        ("round", _) => id(t.round.map(|r| r.raw())),
        ("score", _) => id(t.plan.map(|p| p.raw())),
        ("step", _) => "agreements".to_owned(),
        ("binding", _) => id(t.binding_end.map(|b| b.raw())),
        ("role", _) => "financial_signatory".to_owned(),
        ("account", _) => w.id(UNBOUND).raw().to_string(),
        ("invitation_token", _) => "0123456789abcdef0123456789abcdef".to_owned(),
        ("field", _) => "identity.narrative".to_owned(),
        ("preview", _) => "guide".to_owned(),
        ("session", _) => session.unwrap_or("1").to_owned(),
        _ => "1".to_owned(),
    }
}

/// The body members of a valid request of `op` by `who`, after the test
/// kit's harness (`fstp_api_testkit::harness`), with the world's ids.
fn body_of(w: &Pg<'_>, op: &str, state: StateProfile) -> Value {
    let t = &w.t;
    let plan = t.plan.map_or(1, |p| p.raw());
    let now = u128::try_from(w.now()).unwrap_or(0);
    let call_body = || {
        obj(vec![
            ("opens", dec(now + 86_400_000_000)),
            ("deadline", dec(now + 30 * 86_400_000_000)),
            ("deadline_zone", s("Europe/Brussels")),
            ("currency", s("EUR")),
            ("budget", s("400000.00")),
            ("text", s("SYNTHETIC CALL TEXT")),
        ])
    };
    let scores = |n: usize, max: u32| -> Value {
        Value::Array(
            (0..n)
                .map(|_| Value::Number(fstp_json::Number::from(max)))
                .collect::<Array>(),
        )
    };
    let stage = if state == StateProfile::Proposal(StateTag::Stage2) {
        "Two"
    } else {
        "One"
    };
    match op {
        "identity.unmask" => obj(vec![
            (
                "subject",
                obj(vec![
                    ("type", s("Binding")),
                    ("binding", dec(t.pm_binding.map_or(1, |b| b.raw()))),
                ]),
            ),
            ("purpose", s("SYNTHETIC PURPOSE")),
        ]),
        "people.accept_invitation" => obj(vec![(
            "terms_version",
            Value::Number(fstp_json::Number::from(1u32)),
        )]),
        "tenant.invite_admin" => obj(vec![("email", s("new-admin@matrix.invalid"))]),
        "proposal.request_copy" => obj(vec![("email", s("copy@matrix.invalid"))]),
        "tenant.grant_signatory" => obj(vec![
            ("account", dec(w.id(UNBOUND).raw())),
            ("role", s("legal_signatory")),
        ]),
        "tenant.approve_activation" => obj(vec![("request", s("1"))]),
        "tenant.set_login_methods" => obj(vec![(
            "value",
            Value::Array(Array::from(vec![s("eudi_wallet"), s("passkey")])),
        )]),
        "tenant.set_step_up_freshness" => obj(vec![("value", s("60000000"))]),
        "tenant.set_session_lifetimes" => obj(vec![(
            "value",
            obj(vec![
                ("absolute_us", s("3600000000")),
                ("idle_us", s("600000000")),
            ]),
        )]),
        "tenant.set_mcp" => obj(vec![(
            "value",
            fstp_json::parse(br#"{"enabled":true,"public_tools":true,"roles":null}"#)
                .unwrap_or(Value::Null),
        )]),
        "tenant.set_payment_mode" => obj(vec![("value", s("record_only"))]),
        "tenant.set_template_licence" => obj(vec![("value", s("MIT"))]),
        "tenant.set_guide_notice" => obj(vec![
            (
                "privacy_statement_url",
                s("https://privacy.matrix.example/statement"),
            ),
            (
                "summary",
                s("Synthetic data protection summary, matrix cell."),
            ),
        ]),
        "tenant.branding.check" | "tenant.branding.set" => obj(vec![(
            "tokens",
            fstp_brand::BrandTokens::platform("Matrix Fund")
                .map_or(Value::Null, |t| fstp_brand::to_value(&t)),
        )]),
        "tenant.terminology.set" => obj(vec![
            ("labels", obj(vec![("vocab.call", s("Subgrant call"))])),
            ("voyage_on", Value::Bool(true)),
        ]),
        "tenant.set_mail_relay" => obj(vec![
            ("ca_pem", s("")),
            ("credential", s("mail-relay")),
            ("host", s("smtp.relay.example")),
        ]),
        "tenant.funder_profile.copy" => obj(vec![
            ("id", s("tenant-matrix")),
            ("from_profile", s("horizon-europe")),
            ("from_version", s("1")),
        ]),
        "tenant.funder_profile.save" => obj(vec![
            ("id", s("tenant-written")),
            (
                "profile",
                fstp_json::parse(include_bytes!(
                    "../../fstp-report/profiles/horizon-europe/profile.v1.json"
                ))
                .unwrap_or(Value::Null),
            ),
        ]),
        "admin.approve_break_glass" => obj(vec![("approve", Value::Bool(true))]),
        "admin.request_erasure" => obj(vec![("cause", s("retention_expiry")), ("grant", s("41"))]),
        "creator.invite" => obj(vec![
            ("email", s("invitee@matrix.invalid")),
            ("role", s("programme_manager")),
        ]),
        "creator.apply_start" => obj(vec![
            ("base", s(&t.revision)),
            (
                "start",
                fstp_api_testkit::fake::creator_requests::supersafe_start(),
            ),
        ]),
        "creator.save_fields" => obj(vec![
            ("base", s(&t.revision)),
            (
                "fields",
                Value::Array(Array::from(vec![obj(vec![
                    ("field", s("evaluation.p28_rubric_bands")),
                    ("value", Value::Bool(false)),
                ])])),
            ),
        ]),
        "creator.edit_narrative" => obj(vec![
            ("base", s(&t.revision)),
            ("value", s("SYNTHETIC narrative text, matrix cell.")),
        ]),
        "import.remove" | "creator.accept_narrative" => obj(vec![("base", s(&t.revision))]),
        "creator.acknowledge" => obj(vec![
            ("revision", s(&t.revision)),
            ("warning", s(&t.warning)),
        ]),
        "creator.request_activation" | "creator.approve_activation" => {
            obj(vec![("revision", s(&t.revision))])
        }
        "creator.override_activation" => obj(vec![
            ("revision", s(&t.revision)),
            ("reason", s("SYNTHETIC: the second admin is on leave.")),
        ]),
        "import.upload" => obj(vec![
            ("media", s("text/plain")),
            (
                "text",
                s("SYNTHETIC ANNEX: the grant range is 1000 to 2000 EUR."),
            ),
        ]),
        "import.resolve" => obj(vec![
            ("base", s(&t.revision)),
            ("conflict_acknowledged", Value::Bool(false)),
            ("resolution", obj(vec![("kind", s("dismiss"))])),
            ("shown", s(&"0".repeat(64))),
        ]),
        "roles.grant" => obj(vec![
            ("account", dec(w.id(UNBOUND).raw())),
            ("role", s("Auditor")),
            ("start", dec(now)),
        ]),
        "me.set_display_name" => obj(vec![("display_name", s("Synthetic Matrix Name"))]),
        // ADR-030: a theme choice, and a synthetic PNG for the light slot.
        "me.set_theme" => obj(vec![("theme", s("dark"))]),
        "tenant.branding.set_logo" => obj(vec![
            (
                "image",
                s(&fstp_brand::image::to_base64(
                    &fstp_brand::image::sample_png(64, 32),
                )),
            ),
            ("mode", s("light")),
            ("programme", Value::Null),
        ]),
        "roles.reinstate" => obj(vec![("reason", s("SYNTHETIC REINSTATEMENT REASON"))]),
        "call.draft" | "call.edit" => call_body(),
        "proposal.save_workspace" => obj(vec![
            ("narrative", s("SYNTHETIC NARRATIVE")),
            ("summary", s("SYNTHETIC SUMMARY")),
            ("title", s("SYNTHETIC TITLE")),
        ]),
        "proposal.record_plan" => obj(vec![
            ("description", s("SYNTHETIC WORK PLAN")),
            (
                "tasks",
                Value::Array(Array::from(vec![obj(vec![(
                    "milestones",
                    Value::Array(Array::from(vec![obj(vec![
                        ("amount", s("50000.00")),
                        ("start", s("2027-01-01")),
                        ("due", s("2027-06-01")),
                    ])])),
                )])])),
            ),
        ]),
        "proposal.add_member" | "proposal.add_guardian" => {
            obj(vec![("account", dec(w.id(UNBOUND).raw()))])
        }
        "proposal.state_country" => obj(vec![("country", s("BE"))]),
        "me.mailbox.mark_read" => obj(vec![("message", s("notice.outcome:1"))]),
        "proposal.declare_affiliations" => obj(vec![("affiliations", s("SYNTHETIC AFFILIATIONS"))]),
        "proposal.state_birth_date" => obj(vec![("date_of_birth", s("1990-01-01"))]),
        "proposal.submit" => obj(vec![("ethics", s("none")), ("notice_version", s("1"))]),
        "stage2.answer" => obj(vec![("text", s("SYNTHETIC ANSWERS"))]),
        "stage2.revise" | "amendment.propose" => obj(vec![("plan", dec(plan))]),
        "negotiation.acknowledge_notice" => obj(vec![("notice_version", s("1"))]),
        "review.declare_proposal" | "review.declare_assignment" | "irc.declare" => obj(vec![
            ("conflicted", Value::Bool(false)),
            ("notifiable", Value::Bool(false)),
        ]),
        "review.knock_out" => obj(vec![(
            "outcomes",
            Value::Array(
                t.knock_outs
                    .iter()
                    .map(|k| obj(vec![("criterion", dec(*k)), ("passed", Value::Bool(true))]))
                    .collect(),
            ),
        )]),
        "review.assign" => obj(vec![
            ("reviewer", dec(w.id(MEMBER).raw())),
            ("kind", obj(vec![("type", s("Reviewer"))])),
        ]),
        "review.score" => obj(vec![
            ("plan", dec(plan)),
            ("stage", s(stage)),
            ("values", scores(t.criteria, t.scale)),
        ]),
        "review.correct_score" => obj(vec![
            ("stage", s(stage)),
            ("values", scores(t.criteria, t.scale)),
            ("reason", s("SYNTHETIC CORRECTION")),
        ]),
        "review.ranking_summary" => obj(vec![
            ("neutral_summary", s("SYNTHETIC NEUTRAL SUMMARY")),
            ("rationale", s("SYNTHETIC RATIONALE")),
            ("title", s("SYNTHETIC TITLE")),
        ]),
        "stage2.ask" => obj(vec![("text", s("SYNTHETIC QUESTION"))]),
        "committee.open_round" => obj(vec![
            (
                "order",
                Value::Array(t.ranked.iter().map(|p| dec(p.raw())).collect()),
            ),
            ("nominated", Value::Number(fstp_json::Number::from(1u32))),
            ("rationale", s("SYNTHETIC ROUND RATIONALE")),
        ]),
        "committee.cast" => obj(vec![("vote", s("For"))]),
        "review.mark_finding" => obj(vec![("mark", s("Agreed"))]),
        "committee.delegate" => obj(vec![("to", dec(w.id(MEMBER).raw()))]),
        "irc.review" => obj(vec![("verdict", obj(vec![("type", s("Validate"))]))]),
        "grant.determine_amount" => obj(vec![
            ("agreed", dec(plan)),
            ("deductions", Value::Array(Array::new())),
            ("currency", s("EUR")),
        ]),
        "grant.accept" | "grant.approve" => obj(vec![("determination", s("1"))]),
        "grant.terminate" | "milestone.close" => obj(vec![("reason", s("SYNTHETIC REASON"))]),
        "grant.publicity.withdraw" => obj(vec![("phase", s("Funded"))]),
        "amendment.route" => obj(vec![("route", s("Irc"))]),
        "contract.propose_change" => obj(vec![
            ("clause", Value::Number(fstp_json::Number::from(1u32))),
            ("text", s("SYNTHETIC CLAUSE CHANGE")),
        ]),
        "contract.decide_change" => obj(vec![("accept", Value::Bool(true))]),
        "contract.sign" => obj(vec![("route", s("wallet_qes"))]),
        "contract.decline" | "payment.close" | "payment.request_changes" => {
            obj(vec![("reason", s("SYNTHETIC REASON"))])
        }
        "payment.review_line" => obj(vec![("approved", s("100.00")), ("currency", s("EUR"))]),
        "payment.resubmit" | "payment.submit" => obj(vec![
            ("kind", obj(vec![("type", s("Milestone"))])),
            ("currency", s("EUR")),
            ("lines", Value::Array(Array::new())),
        ]),
        "report.generate" => obj(vec![
            ("kind", s("audit_file")),
            ("call", dec(t.call.map_or(1, |c| c.raw()))),
        ]),
        "pending.confirm" => obj(vec![("shown", s(&"0".repeat(64)))]),
        _ => obj(vec![]),
    }
}

/// The request of `cell`.
fn request_of(w: &Pg<'_>, cell: &Cell, session: Option<&str>) -> Request {
    let spec = fstp_access::op(cell.op).unwrap_or_else(|| panic!("no operation {}", cell.op));
    let (method, pattern) = spec
        .route
        .unwrap_or_else(|| panic!("{} has no route", cell.op));
    let method = match method {
        fstp_access::Method::Get => "GET",
        fstp_access::Method::Post => "POST",
        fstp_access::Method::Put => "PUT",
        fstp_access::Method::Delete => "DELETE",
    };
    let mut params = Object::new();
    let mut path = String::new();
    for (i, seg) in pattern.split('/').enumerate() {
        if i > 0 {
            path.push('/');
        }
        match seg.strip_prefix('{').and_then(|x| x.strip_suffix('}')) {
            Some(name) => {
                let v = param(w, name, cell.op, cell.who, session);
                path.push_str(&v);
                let _ = params.insert(name, s(&v));
            }
            None => path.push_str(seg),
        }
    }
    if matches!(spec.kind, fstp_access::OpKind::Public(_)) {
        match pattern {
            "/p/{slug}" => path.push('/'),
            "/p/{slug}/feed" => path.push_str(".json"),
            _ => {}
        }
    }
    let body = match body_of(w, cell.op, cell.state) {
        Value::Object(o) => o,
        _ => Object::new(),
    };
    Request {
        method,
        path,
        body,
        params,
    }
}

// ---------------------------------------------------------------------------
// Observing a cell
// ---------------------------------------------------------------------------

/// The stable error code and rule of a refusal body.
fn observed_of(code: &str, rule: Option<&str>) -> Result<Observed, ChannelFault> {
    fstp_api_testkit::harness::observed_of(code, rule)
}

/// The observed outcome of an MCP `tools/call` reply.
fn observed_of_mcp(r: &HttpReply, tool: bool) -> Result<Observed, ChannelFault> {
    let v = rpc_of(r);
    let Some(o) = v.as_object() else {
        return Err(ChannelFault::Setup(format!(
            "an MCP reply that is no JSON-RPC message: {} {}",
            r.status,
            text(r)
        )));
    };
    if let Some(e) = o.get("error") {
        let code = e
            .as_object()
            .and_then(|e| e.get("code"))
            .map(Value::to_compact)
            .unwrap_or_default();
        if !tool && code == "-32602" {
            return Ok(Observed::ChannelDenied(Denial::NotExposed));
        }
        return Err(ChannelFault::NotImplemented(format!(
            "JSON-RPC error: {} (HTTP {} {:?})",
            e.to_compact(),
            r.status,
            r.header("www-authenticate").map(String::from_utf8_lossy)
        )));
    }
    let result = o
        .get("result")
        .ok_or_else(|| ChannelFault::Setup(format!("no result: {}", v.to_compact())))?;
    let sc = result
        .as_object()
        .and_then(|o| o.get("structuredContent"))
        .ok_or_else(|| ChannelFault::Setup(format!("no structuredContent: {}", v.to_compact())))?;
    let error = result
        .as_object()
        .and_then(|o| o.get("isError"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if error {
        let code = str_member(sc, "code").ok_or_else(|| {
            ChannelFault::Setup(format!("an error result with no code: {}", v.to_compact()))
        })?;
        return match code.as_str() {
            "step_up_required" => Ok(Observed::StepUpRequired),
            "strong_method_required" => Ok(Observed::StrongMethodRequired),
            other => observed_of(other, str_member(sc, "rule").as_deref()),
        };
    }
    let data = sc.as_object().and_then(|s| s.get("data"));
    if data.and_then(|d| str_member(d, "status")).as_deref() == Some("awaiting_confirmation") {
        return Ok(Observed::Pending);
    }
    Ok(Observed::Completed)
}

/// The token of an MCP cell: every scope, less the operation's own when
/// the cell has no scope. Each MCP cell gets a token of its own,
/// consented for that cell, since a later consent of the same account and
/// client ends the grant behind an earlier token.
fn mcp_token(w: &mut Pg<'_>, model: AccountId, op: &'static str, scope: bool) -> String {
    let own = fstp_access::op(op)
        .and_then(|o| o.scope)
        .map(|s| s.as_str());
    let scopes: Vec<&str> = fstp_access::Scope::ALL
        .iter()
        .map(|s| s.as_str())
        .filter(|s| scope || Some(*s) != own)
        .collect();
    token(w, model, &scopes.join(" "))
}

/// Runs `cell` on the world `w`.
fn observe(w: &mut Pg<'_>, cell: &Cell) -> Result<Observed, ChannelFault> {
    let c = w.cell();
    let model = account_of(cell.who);
    match cell.session.channel {
        Via::Mcp { scope } => {
            let bearer = model.map(|m| mcp_token(w, m, cell.op, scope));
            let req = request_of(w, cell, None);
            let tool = fstp_access::op(cell.op)
                .and_then(|o| o.tool)
                .map(|t| t.name);
            let name = tool.unwrap_or(cell.op);
            let params = format!(r#""name":"{name}","arguments":{}"#, req.tool_args());
            let r = mcp(c, bearer.as_deref(), "tools/call", Some(name), &params);
            observed_of_mcp(&r, tool.is_some())
        }
        Via::Web => {
            let public = fstp_access::op(cell.op)
                .is_some_and(|o| matches!(o.kind, fstp_access::OpKind::Public(_)));
            let cookie = match (model, cell.session.login) {
                (Some(m), Some(Login::Passkey)) => Some(w.session(m)),
                (Some(m), Some(Login::MagicLink)) => {
                    match w.client.login(m, RefMethod::MagicLink).unwrap() {
                        Some(c) => Some(c),
                        // I-77: the cell refused the weak login of a
                        // management account (module documentation).
                        None if management(cell.who) && !public => {
                            return Ok(Observed::StrongMethodRequired);
                        }
                        None if management(cell.who) => None,
                        None => {
                            return Err(ChannelFault::Setup(format!(
                                "the magic-link login of {:?} was refused",
                                cell.who
                            )));
                        }
                    }
                }
                _ => None,
            };
            // `me.end_session` names one of the caller's own sessions, as
            // `me.sessions` lists them.
            let session_id = match (cell.op, cookie.as_ref()) {
                ("me.end_session", Some(c)) => {
                    let r = web(w.cell(), "GET", "/api/v1/me/sessions", Some(c), &[]);
                    let v = json(&r);
                    let list = v.as_array().or_else(|| {
                        v.as_object()
                            .and_then(|o| o.values().find_map(Value::as_array))
                    });
                    list.and_then(|a| a.iter().find_map(|s| str_member(s, "session")))
                }
                _ => None,
            };
            let req = request_of(w, cell, session_id.as_deref());
            let path = if req.path.starts_with("/p/") {
                req.path.clone()
            } else {
                format!("/api/v1{}", req.path)
            };
            let body = req.body_bytes();
            let mut r = web(c, req.method, &path, cookie.as_ref(), &body);
            if cell.session.step_up != StepUp::Absent
                && let (Some((id, ch)), Some(cookie)) = (challenge_of(&r), cookie.as_ref())
            {
                let proved = w.client.prove_api_step_up(cookie, &id, ch).unwrap();
                if !proved {
                    return Err(ChannelFault::Setup("the step-up was refused".to_owned()));
                }
                if cell.session.step_up == StepUp::Stale {
                    let p71 = fstp_cell_core::tenant::P71_DEFAULT_US;
                    c.clock().advance(p71 + 1);
                }
                r = web(c, req.method, &path, Some(cookie), &body);
            }
            fstp_api_testkit::harness::observed_of_http(r.status, &r.body)
        }
    }
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// A disagreement of one cell.
struct Miss {
    cell: Cell,
    expected: Expected,
    observed: Result<Observed, ChannelFault>,
}

/// T-AUTHZ-MATRIX, I-84, H-01 on PostgreSQL: every sampled cell of the
/// authorisation matrix, run against the production cell, agrees with
/// the reference both ways (module documentation, "Sampling rule").
#[test]
fn t_authz_matrix_pg_sample() {
    let limit: usize = std::env::var("FSTP_PG_MATRIX_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(usize::MAX);
    let ops: Option<Vec<String>> = std::env::var("FSTP_PG_MATRIX_OPS")
        .ok()
        .map(|v| v.split(',').map(str::to_owned).collect());
    let skip: usize = std::env::var("FSTP_PG_MATRIX_SKIP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let started = std::time::Instant::now();
    let sample = sample();
    let total: usize = sample.values().map(Vec::len).sum();
    // Coverage of the sample: both channels and every realisable
    // principal.
    let mut channels = BTreeSet::new();
    let mut whos = BTreeSet::new();
    for (cell, _) in sample.values().flatten() {
        channels.insert(matches!(cell.session.channel, Via::Mcp { .. }));
        whos.insert(cell.who);
    }
    assert_eq!(channels.len(), 2, "the sample covers web and MCP");
    for who in Who::ALL.into_iter().filter(|w| realisable(*w)) {
        assert!(whos.contains(&who), "the sample has no cell of {who:?}");
    }
    let mut misses: Vec<Miss> = Vec::new();
    let mut ran = 0usize;
    let mut rebuilds = 0usize;
    for (state, cells) in &sample {
        let mut queue = cells
            .iter()
            .filter(|(c, _)| ops.as_ref().is_none_or(|o| o.iter().any(|x| x == c.op)))
            .skip(skip)
            .take(limit)
            .peekable();
        while queue.peek().is_some() {
            let world = start();
            let mut w = build(&world, *state);
            rebuilds += 1;
            for (cell, expected) in queue.by_ref() {
                ran += 1;
                let observed = observe(&mut w, cell);
                let ok = matches!(&observed, Ok(o) if agrees(*expected, class_of(o)));
                if !ok {
                    misses.push(Miss {
                        cell: *cell,
                        expected: *expected,
                        observed,
                    });
                }
                // A cell that appended an engine record changed its world.
                if w.engine_entries() != w.engine_head {
                    break;
                }
            }
        }
    }
    assert!(
        ran > 0 && ran <= total,
        "the sample ran {ran} of {total} cells"
    );
    if !misses.is_empty() {
        let mut report = String::new();
        for m in &misses {
            report.push_str(&format!(
                "  {} {:?} {:?} {:?}: expected {:?}, observed {:?}\n",
                m.cell.op, m.cell.who, m.cell.state, m.cell.session, m.expected, m.observed
            ));
        }
        panic!(
            "T-AUTHZ-MATRIX on PostgreSQL: {} of {ran} sampled cells disagree with the reference ({rebuilds} worlds built, {:?}):\n{report}",
            misses.len(),
            started.elapsed()
        );
    }
}
