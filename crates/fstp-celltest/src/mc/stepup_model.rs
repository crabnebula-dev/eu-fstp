//! M-STEPUP (design section 14.2, I-78). Lane W1b owns this file.
//!
//! The universe: one tenant admin with a passkey session, and one
//! applicant with a magic-link session. Four high-risk commands: two of
//! kind `ManagementRoleChange` (so a digest compared by kind only shows),
//! `ReleasePayment` and `AddPasskey`. Step-ups by passkey with user
//! verification, by passkey without it, and from the magic-link session,
//! all asserted at the first tick. Ticks at P-71 minus 1 µs, P-71 and
//! P-71 plus 1 µs. P-71 is 5 minutes or a tenant's 1 minute. Admission and
//! commit are separate steps, so freshness is checked at both. One replay:
//! at most two commits, so a consumed step-up can be offered again.
//!
//! The applicant b already holds a passkey, so `AddPasskey` in its
//! magic-link session adds a second passkey to its own account. Only the
//! magic-link rule refuses it, not the first-passkey rule (design section
//! 8.3). This is the takeover path of a stolen mailbox.
//!
//! The model runs over a [`StepUpBackend`]: [`Reference`],
//! [`Production`] (`fstp_cell_core::gate::admit_command` over a
//! production cell from genesis, and the commit through `DriverCore`) or
//! a [`Mutant`] with one seeded defect. Admission and commit decisions are
//! both compared with the reference.

use fstp_auth::AuthCommand;
use fstp_cell_core::driver::ExecError;
use fstp_cell_core::gate::{self, Action, Deny, LoginPolicy, StepUpView};
use fstp_cell_core::tenant::TenantCommand;
use fstp_cell_core::{CellCommand, CellRecord};
use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, DeclarationSubject};
use fstp_domain::decision::Vote;
use fstp_domain::id::{AccountId, BindingId, LineId, RequestId};
use fstp_domain::roles::Role;
use fstp_domain::scoring::{ScoreKey, Stage};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::money::{self, FIN, LC, MoneyDraft, MoneySetup, PC};
use fstp_domain_testkit::r#gen::review::{COORDINATOR, IRC, R1, R2, R3, declare, plan_of, submit};
use fstp_domain_testkit::r#gen::roster::{
    A, ADMIN, ADMIN_2, B, P1, STAFF_PM, Step, T0, call, grant,
};
use fstp_domain_testkit::mc::life_model::{
    IRC2, admit as admit_to_stage1, assign_declared, assignment_of, ballots, close, cut_off,
    cut_off_decision, irc_review, knock_out, no_questions, score,
};
use fstp_domain_testkit::vault::{GroundTruth, IdentityTag};
use fstp_mc::{Model, Property};

use crate::NotImplemented;
use crate::mc::auth_model::{ProdCell, ProdError, credential_of, prod_session};
use crate::reference::auth::{self as r, MINUTE_US, RefHighRisk, RefMethod, RefSession, RefStepUp};

// ---------------------------------------------------------------------------
// The universe.

/// The instant every step-up is asserted at.
pub const ASSERTED_AT: Timestamp = Timestamp::from_micros(3_000_000_000);

/// The P-71 values: the default and a tenant's shorter value.
pub const P71_VALUES: [i64; 2] = [r::P71_DEFAULT_US, MINUTE_US];

/// The P-71 of variant `v`.
pub fn p71(v: u8) -> i64 {
    P71_VALUES
        .get(usize::from(v))
        .copied()
        .unwrap_or(r::P71_DEFAULT_US)
}

/// The time at `tick` under P-71 variant `v`: the assertion, then P-71
/// minus 1 µs, P-71 and P-71 plus 1 µs after it.
pub fn at(v: u8, tick: u8) -> Timestamp {
    let base = ASSERTED_AT.micros();
    let off = match tick {
        0 => 0,
        1 => p71(v).saturating_sub(1),
        2 => p71(v),
        _ => p71(v).saturating_add(1),
    };
    Timestamp::from_micros(base.saturating_add(off))
}

/// The index of the admin's passkey session.
pub const S_ADMIN: u8 = 0;
/// The index of the applicant's magic-link session.
pub const S_MAGIC: u8 = 1;

/// The session at index `i`.
pub fn session(i: u8) -> RefSession {
    let (account, method, id) = if i == S_MAGIC {
        (B, RefMethod::MagicLink, 0x52)
    } else {
        (ADMIN, RefMethod::Passkey, 0x51)
    };
    let mut sid = [0u8; 16];
    sid[0] = id;
    RefSession {
        id: sid,
        account,
        method,
        device: (method == RefMethod::Passkey).then_some(0),
        started: ASSERTED_AT,
        last_used: ASSERTED_AT,
        ended: None,
    }
}

/// The commands, by index: two role grants, a payment release and adding a passkey.
pub const COMMANDS: [&str; 4] = ["GrantRole", "GrantRole", "ReleasePayment", "AddPasskey"];

/// The command id of command `c`.
pub fn command_id(c: u8) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[0] = 0xC0;
    id[1] = c;
    id
}

/// The reference canonical form of command `c`: its name and its index.
/// The digest binds the command id too, so two equal names still differ.
pub fn canonical(c: u8) -> Vec<u8> {
    let mut out = COMMANDS
        .get(usize::from(c))
        .copied()
        .unwrap_or("")
        .as_bytes()
        .to_vec();
    out.push(b'#');
    out.push(c);
    out
}

/// The action digest of command `c`.
pub fn digest(c: u8) -> [u8; 32] {
    r::action_digest(&canonical(c), command_id(c))
}

/// The high-risk class of command `c`.
pub fn class(c: u8) -> Option<RefHighRisk> {
    COMMANDS
        .get(usize::from(c))
        .and_then(|n| r::high_risk_of(n))
}

/// The command whose digest is `d`, if any.
pub fn command_of(d: &[u8; 32]) -> Option<u8> {
    (0..4u8).find(|c| digest(*c) == *d)
}

/// The production cell command of command `c` in the admin session.
///
/// Gap: the stubs have no `AddPasskey` command. `RegisterCredential`
/// stands in for it, as the only credential command of `AuthCommand`.
pub fn cell_command(c: u8) -> CellCommand {
    cell_command_in(S_ADMIN, c)
}

/// The start of the role grants of the production universe: twice the
/// default P-71 after [`ASSERTED_AT`], so later than every tick. The
/// domain refuses a grant whose start lies before its command instant (no
/// backdating, design 2.6), and every commit of M-STEPUP lies at or before
/// `ASSERTED_AT + P-71 + 1 µs`.
pub const GRANT_START: Timestamp = Timestamp::from_micros(
    ASSERTED_AT
        .micros()
        .saturating_add(r::P71_DEFAULT_US)
        .saturating_add(r::P71_DEFAULT_US),
);

/// The production cell command of command `c` in session `session`.
/// `AddPasskey` names the session's own account, so the applicant's
/// magic-link session asks to add a passkey to its own account. The role
/// grants start at [`GRANT_START`], so production decides them at every
/// tick of the universe.
pub fn cell_command_in(session: u8, c: u8) -> CellCommand {
    let core = |cmd| CellCommand::Engine(fstp_engine::Command::Core(cmd));
    let own = if session == S_MAGIC { B } else { ADMIN };
    match c {
        0 => core(
            grant(
                BindingId::from_raw(2_001),
                A,
                P1,
                Role::CommitteeMember,
                GRANT_START,
            )
            .cmd,
        ),
        1 => core(
            grant(
                BindingId::from_raw(2_002),
                B,
                P1,
                Role::FinanceApprover,
                GRANT_START,
            )
            .cmd,
        ),
        2 => core(fstp_domain::Command::ReleasePayment {
            request: RequestId::from_raw(1),
        }),
        _ => CellCommand::Auth(AuthCommand::RegisterCredential {
            account: own,
            credential: vec![0x5E, c, session],
        }),
    }
}

/// The session index of session id `id`.
pub fn session_index(id: [u8; 16]) -> u8 {
    if id == session(S_MAGIC).id {
        S_MAGIC
    } else {
        S_ADMIN
    }
}

/// The seam of [`prod_action_digest`], closed by lane W2c:
/// `fstp_cell_core::action_digest` gives the digest, and
/// `gate::admit_command` checks it under the command id (design section
/// 8.4). The constant stays for the suites that name it.
pub const DIGEST_SEAM: &str = "fstp_celltest::mc::stepup_model::prod_action_digest: fstp-cell-core exposes no canonical command encoding and gate::admit takes no command id (design section 8.4, lane W2c)";

/// `SHA-256(canonical(command) || command_id)` as production computes it
/// (design section 8.4): `fstp_cell_core::action_digest`.
pub fn prod_action_digest(
    cmd: &CellCommand,
    command_id: [u8; 16],
) -> Result<[u8; 32], NotImplemented> {
    Ok(fstp_cell_core::action_digest(cmd, command_id))
}

/// The seam of [`prod_self_grant_digest`], closed by lane W2c:
/// `fstp_cell_core::self_grant_digest` gives the digest, and
/// `fstp_cell_core::attest_at` and `decide_with_id` take the command id
/// (design section 5.1). It remains the refusal for a command that is not
/// a `GrantRole`.
pub const SELF_GRANT_DIGEST_SEAM: &str = "fstp_celltest::mc::stepup_model::prod_self_grant_digest: fstp-cell-core exposes no canonical GrantRole encoding without second_admin, and CellCtx and attest take no command id (design section 5.1, lane W2c)";

/// `grant_digest = SHA-256(canonical(GrantRole without second_admin) ||
/// command_id)` as production computes it (design section 5.1, SoD-07).
/// Production computes it with `fstp_cell_core::self_grant_digest`. A
/// command that is not a `GrantRole` refuses with
/// [`SELF_GRANT_DIGEST_SEAM`].
pub fn prod_self_grant_digest(
    grant: &CellCommand,
    command_id: [u8; 16],
) -> Result<[u8; 32], NotImplemented> {
    match grant {
        CellCommand::Engine(g) => fstp_cell_core::self_grant_digest(g, command_id)
            .ok_or(NotImplemented::new(SELF_GRANT_DIGEST_SEAM)),
        _ => Err(NotImplemented::new(SELF_GRANT_DIGEST_SEAM)),
    }
}

/// The seam that stood for [`Production::commit`], closed by the lead.
/// Lanes W2b and W2c gave `StepUpConsumed { id }`, which `DriverCore`
/// appends in the batch of an admitted high-risk command. The commit now
/// runs `DriverCore` over the `fstp-ledger` store of a [`ProdCell`]
/// ([`ProdCell::execute`]). The harness runs the step-up route for each
/// model step-up before the gate ([`ProdCell::grant_stepup`]): the
/// assertion is verified by `fstp_auth::stepup::verify_step_up`, and only
/// an accepted one is recorded as `StepUpGranted`, as a test harness that
/// writes the ledger may. The route's own admission is lane W3a's
/// (`fstp_cell_core::gate::ROUTE_ADMISSION_SEAM`). No production path
/// returns this constant. It stays for the suites that name it.
pub const CONSUME_SEAM: &str = "fstp_celltest::mc::stepup_model::Production::commit: closed by the lead; the commit runs DriverCore over the fstp-ledger store of a ProdCell, and no production path returns this seam (design sections 5.1, 5.4 and 8.4)";

/// The seam of [`login_policy_p71`], closed by lane W2c: the canonical
/// form is `fstp_cell_core::tenant::TenantLoginPolicy` (design section
/// 5.1). The constant stays for the suites that name it.
pub const POLICY_SEAM: &str = "fstp_celltest::mc::stepup_model::login_policy_p71: the canonical login policy form of SetLoginPolicy is not defined (design section 5.1, lane W2c)";

/// The canonical login policy that sets P-71 to `p71_us`, for
/// `SetLoginPolicy`: `fstp_cell_core::tenant::TenantLoginPolicy`.
pub fn login_policy_p71(p71_us: i64) -> Result<Vec<u8>, NotImplemented> {
    Ok(fstp_cell_core::tenant::TenantLoginPolicy {
        p71_us: Some(p71_us),
        ..Default::default()
    }
    .encode())
}

// ---------------------------------------------------------------------------
// Backends.

/// The decisions M-STEPUP asks of a backend.
pub trait StepUpBackend {
    /// Whether command `c` is admitted in `session` with `stepup` at `now`.
    fn admit(
        &self,
        session: &RefSession,
        c: u8,
        stepup: Option<&RefStepUp>,
        now: Timestamp,
        p71_us: i64,
    ) -> Result<bool, NotImplemented>;

    /// Whether the admitted command `c` commits at `now`. `Some(consumed)`
    /// when it commits, saying whether its batch consumes the step-up.
    fn commit(
        &self,
        session: &RefSession,
        c: u8,
        stepup: Option<&RefStepUp>,
        now: Timestamp,
        p71_us: i64,
    ) -> Result<Option<bool>, NotImplemented>;
}

/// The reference backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct Reference;

impl StepUpBackend for Reference {
    fn admit(
        &self,
        session: &RefSession,
        c: u8,
        stepup: Option<&RefStepUp>,
        now: Timestamp,
        p71_us: i64,
    ) -> Result<bool, NotImplemented> {
        Ok(r::admit_high_risk(
            session,
            digest(c),
            stepup,
            now,
            r::effective_p71(Some(p71_us)),
        )
        .is_ok())
    }

    fn commit(
        &self,
        session: &RefSession,
        c: u8,
        stepup: Option<&RefStepUp>,
        now: Timestamp,
        p71_us: i64,
    ) -> Result<Option<bool>, NotImplemented> {
        let ok = self.admit(session, c, stepup, now, p71_us)?;
        Ok(ok.then_some(stepup.is_some()))
    }
}

/// The call deadline of the production cell's money path. It lies before
/// every tick of the universe, so the payment request is approved before
/// any step-up is asserted: the ledger is time-monotone (design section
/// 2.2), and every step-up is asserted at [`ASSERTED_AT`].
pub const RELEASE_DEADLINE: Timestamp = Timestamp::from_micros(2_000_000_000);

/// The instant of the money path after the deadline: one second after
/// [`RELEASE_DEADLINE`], and before [`ASSERTED_AT`].
pub const RELEASE_AT: Timestamp = Timestamp::from_micros(2_001_000_000);

/// The payment request that `ReleasePayment` (command 2) releases.
pub const RELEASE_REQUEST: RequestId = RequestId::from_raw(1);

/// The one line of [`RELEASE_REQUEST`].
pub const RELEASE_LINE: LineId = LineId::from_raw(1);

/// The binding that makes the admin a payment releaser of `P1`.
pub const RELEASER_BINDING: BindingId = BindingId::from_raw(2_003);

/// The grant of the money path and its one payment request, in cents.
const RELEASE_CENTS: i64 = 400;

/// The money setup of the production cell: programme `P1` with P-04 =
/// [2.00, 4.00] and P-05 = 6.00, lead c's proposal of one 4.00 milestone,
/// reviewers R1 and R2, and FIN as finance approver.
fn release_setup() -> MoneySetup {
    MoneySetup {
        p04: (200, 400),
        p05: 600,
        drafts: vec![MoneyDraft::one(LC, PC, RELEASE_CENTS)],
        staff: vec![(FIN, Role::FinanceApprover)],
        shared: Vec::new(),
        unverified: Vec::new(),
        consents: Vec::new(),
        reviewers: vec![R1, R2],
        identities: Vec::new(),
    }
}

/// The synthetic vault of the production cell: the money setup's vault,
/// and a and b of the role grants with their own verified identities, as
/// in [`crate::mc::auth_model::auth_truth`].
fn release_truth(setup: &MoneySetup) -> GroundTruth {
    let mut truth = setup.truth();
    truth.set_identity(A, IdentityTag::new(1_101));
    truth.set_identity(B, IdentityTag::new(1_102));
    truth.verify(A);
    truth.verify(B);
    truth
}

/// The M2 steps to lead c's proposal submitted, all at `T0`: the money
/// setup's draft steps, with the call deadline at [`RELEASE_DEADLINE`],
/// then the submission.
fn draft_path(setup: &MoneySetup) -> Result<Vec<Step>, String> {
    let mut out = setup.draft_steps()?;
    for s in &mut out {
        if let fstp_domain::Command::DraftCall { deadline, .. } = &mut s.cmd {
            *deadline = RELEASE_DEADLINE;
        }
    }
    out.push(submit(LC, PC, plan_of(PC), false));
    Ok(out)
}

/// The M2 steps from the submission to [`RELEASE_REQUEST`] in
/// PAYMENT_APPROVED, all at [`RELEASE_AT`], as `MoneySetup::world` and
/// `MoneyStory::execute` run them. Stage 1 and stage 2 with "no
/// questions", the cut-off and the IRC review take the proposal to
/// NEGOTIATION. The amount determination, the acceptance, the approval,
/// the contract fact and the start of execution take it to IN_EXECUTION.
/// Lead c then requests the milestone, R1 accepts the line and FIN
/// approves. So the admin who releases is neither the acceptor nor the
/// approver (I-05, SoD-04).
fn release_path(setup: &MoneySetup) -> Result<Vec<Step>, String> {
    let c1 = call(1);
    let reviewer = |r| assignment_of(r, PC, c1, AssignmentKind::Reviewer);
    let mut out = Vec::new();
    for r in setup.reviewers.iter().copied() {
        out.extend(assign_declared(r, PC, c1, AssignmentKind::Reviewer));
    }
    out.push(declare(
        COORDINATOR,
        DeclarationSubject::Proposal(PC),
        false,
        false,
    ));
    out.push(knock_out(PC, true));
    out.push(admit_to_stage1(PC));
    for r in setup.reviewers.iter().copied() {
        let key = ScoreKey {
            assignment: reviewer(r),
            stage: Stage::One,
            plan: plan_of(PC),
        };
        out.push(score(r, key, &[2, 2]));
    }
    out.push(close(Actor::Account(COORDINATOR), PC));
    for r in setup.reviewers.iter().copied() {
        out.push(no_questions(r, PC, reviewer(r)));
    }
    out.push(cut_off(
        R1,
        cut_off_decision(1),
        c1,
        vec![PC],
        1,
        false,
        ballots(&[R1, R2, R3], Vote::For),
    ));
    for i in [IRC, IRC2] {
        out.extend(assign_declared(i, PC, c1, AssignmentKind::Irc));
    }
    for i in [IRC, IRC2] {
        out.push(irc_review(
            i,
            assignment_of(i, PC, c1, AssignmentKind::Irc),
            true,
        ));
    }
    let determination = money::amount_decision(PC, 1);
    out.push(money::determine(R1, PC, determination, plan_of(PC), &[])?);
    out.push(money::accept_grant_as(
        LC,
        PC,
        money::accept_decision(PC),
        determination,
    ));
    out.push(money::approve_grant_as(
        STAFF_PM,
        PC,
        money::approve_decision(PC),
        determination,
    ));
    out.push(money::contract_effective(PC));
    out.push(money::start_execution(PC));
    out.push(money::request_payment(
        LC,
        RELEASE_REQUEST,
        PC,
        &[(RELEASE_LINE, money::milestone_n(PC, 0), RELEASE_CENTS)],
    )?);
    out.push(money::accept_line(
        R1,
        RELEASE_REQUEST,
        RELEASE_LINE,
        RELEASE_CENTS,
        false,
    )?);
    out.push(money::approve_payment(FIN, RELEASE_REQUEST));
    Ok(out)
}

/// Runs `steps` at `at` in `cell`, naming the step a refusal stopped at.
fn run_path(cell: &mut ProdCell, steps: &[Step], at: Timestamp) -> Result<(), ProdError> {
    for (i, s) in steps.iter().enumerate() {
        cell.exec_any_step(s, at).map_err(|e| match e {
            ProdError::NotImplemented(op) => ProdError::NotImplemented(op),
            ProdError::Refused(why) => ProdError::Refused(format!(
                "money path step {i} {:?} by {:?}: {why}",
                s.cmd.kind(),
                s.actor
            )),
        })?;
    }
    Ok(())
}

/// Makes the admin a payment releaser of `P1` at `T0`, so the admin's
/// session can run `ReleasePayment`. A grant by the admin to the admin
/// is a self-grant, which needs a second tenant admin (SoD-07). So
/// `ADMIN_2` is made tenant admin, grants the binding, and its tenant
/// admin grant ends again, which leaves one tenant admin.
fn grant_releaser(cell: &mut ProdCell) -> Result<(), ProdError> {
    cell.exec_tenant_admin_grant(ADMIN, ADMIN_2, T0)?;
    let mut step = grant(RELEASER_BINDING, ADMIN, P1, Role::PaymentReleaser, T0);
    if let fstp_domain::Command::GrantRole { second_admin, .. } = &mut step.cmd {
        *second_admin = None;
    }
    step.actor = Actor::Account(ADMIN_2);
    cell.exec_step(&step, T0)?;
    cell.exec(
        CellCommand::Tenant(TenantCommand::EndTenantAdmin { account: ADMIN_2 }),
        ADMIN,
        T0,
    )?;
    Ok(())
}

/// The production backend: `gate::admit_command` over a production cell
/// from genesis with tenant admin `ADMIN`, and the commit through
/// `DriverCore` over that cell.
///
/// The cell holds what each command of the universe needs
/// ([`Production::new`]). Each decision runs on a copy of the cell, so no
/// decision changes the next.
///
/// Before the gate, the harness runs the step-up route for the model's
/// step-up in the copy ([`ProdCell::grant_stepup`]). The passkey of the
/// step-up session's account asserts, and `fstp_auth::stepup::
/// verify_step_up` decides. An accepted step-up is recorded as
/// `StepUpGranted` by production's `decide`, and the gate's view names
/// the id that production derived. The route grants a passkey assertion
/// with user verification only, so a granted step-up is strong. A refused
/// one writes nothing: a step-up without user verification and one from
/// the magic-link session. The view then names an id the ledger never
/// granted, and the gate refuses it as it would in production.
///
/// Single use is production's own. For a step-up the model marks
/// consumed, the harness first commits its command in the copy, through
/// the same path as a commit, so `StepUpConsumed` is in the ledger. The
/// view says it is not consumed, so only the ledger refuses the replay.
///
/// The commit admits the command at the step-up's assertion instant,
/// the earliest instant a route can admit it, and runs it with the commit
/// instant as the store's clock. So P-71 at commit is checked by the
/// store against `SideEffects::stepup_fresh_until`, the limit that
/// `DriverCore` computed (design sections 5.3 and 8.4), not by a second
/// gate check. The trait gives the commit no admission instant, and P-71
/// at admission is checked by [`StepUpBackend::admit`] at that instant.
/// An admitted command runs through `DriverCore` ([`ProdCell::execute`]),
/// whose batch carries `StepUpConsumed` for a high-risk command (design
/// section 5.1). `AddPasskey` runs through the harness route
/// [`ProdCell::add_passkey`], since `decide` refuses `RegisterCredential`
/// without the verified key that only a route holds. A command that
/// production refuses at commit is not committed, and the two-way property
/// compares that with the reference.
#[derive(Clone, Debug)]
pub struct Production {
    cell: ProdCell,
}

/// Not a seam: production refused to record a model step-up that the
/// route accepted, the replay of a consumed step-up did not consume it,
/// or the driver ended a commit in a way no M-STEPUP decision covers.
/// This stops the run as a backend that did not answer.
pub const STEPUP_HARNESS_FAILED: &str = "fstp_celltest::mc::stepup_model::Production: the harness could not record a model step-up or replay its consumption, or the driver ended a commit outside the M-STEPUP decisions";

fn deny_ni(d: Deny) -> Result<bool, NotImplemented> {
    match d {
        Deny::NotImplemented(op) => Err(NotImplemented::new(op)),
        _ => Ok(false),
    }
}

fn prod_err(e: ProdError) -> NotImplemented {
    match e {
        ProdError::NotImplemented(op) => NotImplemented::new(op),
        ProdError::Refused(_) => NotImplemented::new(STEPUP_HARNESS_FAILED),
    }
}

/// Production's digest of the command that the model's step-up `u` was
/// requested for, in its session.
fn prod_digest(u: &RefStepUp) -> Result<[u8; 32], NotImplemented> {
    match command_of(&u.action_digest) {
        Some(c) => prod_action_digest(&cell_command_in(session_index(u.session), c), command_id(c)),
        None => Ok(u.action_digest),
    }
}

/// The passkey a session's account asserts a step-up with: the device
/// the session logged in with, or device 0 for a magic-link session.
fn stepup_credential(s: &RefSession) -> Vec<u8> {
    credential_of(s.account, s.device.unwrap_or(0))
}

/// Whether `batch` consumes the step-up the admission named.
fn consumes(batch: &[CellRecord], admitted: &gate::Admitted) -> bool {
    admitted.stepup().is_some_and(|u| {
        batch.iter().any(|r| {
            matches!(r, CellRecord::Auth(fstp_auth::AuthRecord::StepUpConsumed { id }) if *id == u.id)
        })
    })
}

/// Runs the admitted command in `cell` with `commit_at` as the store's
/// clock: `AddPasskey` through [`ProdCell::add_passkey`], every other
/// command through `DriverCore` ([`ProdCell::execute`]).
fn run_admitted(
    cell: &mut ProdCell,
    admitted: &gate::Admitted,
    session: &RefSession,
    commit_at: Timestamp,
) -> Result<Result<Vec<CellRecord>, ExecError>, ProdError> {
    if matches!(
        admitted.action(),
        Action::Command(CellCommand::Auth(AuthCommand::RegisterCredential { .. }))
    ) {
        cell.add_passkey(admitted, &prod_session(session), commit_at)
            .map(Ok)
    } else {
        cell.execute(admitted.clone(), commit_at)
    }
}

impl Production {
    /// The production backend over a production cell from genesis that
    /// holds what each command of the universe needs. The admin is tenant
    /// admin, and the admin and the applicant b each hold a verified
    /// passkey, registered at `T0` by a first passkey ceremony
    /// ([`ProdCell::register_passkey`]). So `AddPasskey` adds a second
    /// passkey in either session, and in b's magic-link session only the
    /// magic-link rule refuses it (design section 8.3).
    ///
    /// The admin is a payment releaser of `P1` ([`grant_releaser`]), and
    /// [`RELEASE_REQUEST`] is in PAYMENT_APPROVED, accepted by R1 and
    /// approved by FIN ([`release_path`]). So `ReleasePayment` commits in
    /// the admin's session with a fresh strong step-up, as the reference
    /// commits it. Every step is a production command. The contract fact
    /// is decided by the cell's M2 decider for the contract port
    /// ([`ProdCell::exec_port_fact`]).
    pub fn new() -> Result<Production, ProdError> {
        let setup = release_setup();
        let mut cell = ProdCell::genesis(release_truth(&setup))?;
        cell.exec_tenant_admin_grant(ADMIN, ADMIN, T0)?;
        cell.register_passkey(ADMIN, credential_of(ADMIN, 0), T0)?;
        cell.register_passkey(B, credential_of(B, 0), T0)?;
        run_path(
            &mut cell,
            &draft_path(&setup).map_err(ProdError::Refused)?,
            T0,
        )?;
        grant_releaser(&mut cell)?;
        run_path(
            &mut cell,
            &release_path(&setup).map_err(ProdError::Refused)?,
            RELEASE_AT,
        )?;
        Ok(Production { cell })
    }

    /// A copy of the cell after the step-up route for `u`, and the gate's
    /// view of it. `session` is the session the decision runs in, which
    /// the route sees when `u` belongs to it.
    fn granted(
        &self,
        u: &RefStepUp,
        session: &RefSession,
        p71_us: i64,
    ) -> Result<(ProdCell, StepUpView), NotImplemented> {
        let mut cell = self.cell.clone();
        let action_digest = prod_digest(u)?;
        let own = if u.session == session.id {
            *session
        } else {
            self::session(session_index(u.session))
        };
        let route = if u.method.phishing_resistant() {
            cell.grant_stepup(
                &prod_session(&own),
                &stepup_credential(&own),
                action_digest,
                u.uv,
                u.asserted_at,
            )
            .map_err(prod_err)?
            .ok()
        } else {
            None
        };
        let Some(id) = route else {
            // The route refused, so the ledger holds no grant for the id
            // the client names.
            let view = StepUpView {
                id: u.id,
                session: u.session,
                action_digest,
                asserted_at: u.asserted_at,
                strong: false,
                consumed: false,
            };
            return Ok((cell, view));
        };
        let view = StepUpView {
            id,
            session: u.session,
            action_digest,
            asserted_at: u.asserted_at,
            strong: true,
            consumed: false,
        };
        if u.consumed {
            replay_consumption(&mut cell, u, &own, &view, p71_us)?;
        }
        Ok((cell, view))
    }

    /// The gate's admission of `c` in `session` at `now`, with the cell
    /// the decision runs on, or `None` when the gate refuses. Without a
    /// step-up nothing is recorded, so the cell is copied only when the
    /// gate admits.
    fn gate(
        &self,
        session: &RefSession,
        c: u8,
        stepup: Option<&RefStepUp>,
        now: Timestamp,
        p71_us: i64,
    ) -> Result<Option<(ProdCell, gate::Admitted)>, NotImplemented> {
        match stepup {
            Some(u) => {
                let (cell, view) = self.granted(u, session, p71_us)?;
                let admitted = admit_in(&cell, session, c, Some(&view), now, p71_us)?;
                Ok(admitted.map(|a| (cell, a)))
            }
            None => {
                let admitted = admit_in(&self.cell, session, c, None, now, p71_us)?;
                Ok(admitted.map(|a| (self.cell.clone(), a)))
            }
        }
    }
}

/// The gate's admission of `c` in `session` at `now` over `cell`, with
/// the step-up `view`, or `None` when the gate refuses. The gate checks
/// the step-up digest under the command id ([`DIGEST_SEAM`], closed by
/// lane W2c).
fn admit_in(
    cell: &ProdCell,
    session: &RefSession,
    c: u8,
    view: Option<&StepUpView>,
    now: Timestamp,
    p71_us: i64,
) -> Result<Option<gate::Admitted>, NotImplemented> {
    let policy = LoginPolicy {
        stepup_freshness_us: p71_us,
    };
    match gate::admit_command(
        cell.state(),
        &prod_session(session),
        Action::Command(cell_command_in(session_index(session.id), c)),
        command_id(c),
        view,
        now,
        &policy,
    ) {
        Ok(a) => Ok(Some(a)),
        Err(d) => {
            deny_ni(d)?;
            Ok(None)
        }
    }
}

/// Commits, in `cell`, the command that the consumed model step-up `u`
/// was requested for, in `session` at its assertion instant, under the
/// step-up `view` the ledger granted. So the ledger holds the step-up's
/// `StepUpConsumed`, as it does once a command consumed it.
fn replay_consumption(
    cell: &mut ProdCell,
    u: &RefStepUp,
    session: &RefSession,
    view: &StepUpView,
    p71_us: i64,
) -> Result<(), NotImplemented> {
    let failed = || NotImplemented::new(STEPUP_HARNESS_FAILED);
    let c = command_of(&u.action_digest).ok_or_else(failed)?;
    let admitted =
        admit_in(cell, session, c, Some(view), u.asserted_at, p71_us)?.ok_or_else(failed)?;
    match run_admitted(cell, &admitted, session, u.asserted_at).map_err(prod_err)? {
        Ok(batch) if consumes(&batch, &admitted) => Ok(()),
        _ => Err(failed()),
    }
}

impl StepUpBackend for Production {
    fn admit(
        &self,
        session: &RefSession,
        c: u8,
        stepup: Option<&RefStepUp>,
        now: Timestamp,
        p71_us: i64,
    ) -> Result<bool, NotImplemented> {
        Ok(self.gate(session, c, stepup, now, p71_us)?.is_some())
    }

    fn commit(
        &self,
        session: &RefSession,
        c: u8,
        stepup: Option<&RefStepUp>,
        now: Timestamp,
        p71_us: i64,
    ) -> Result<Option<bool>, NotImplemented> {
        // The admission instant: the step-up's assertion instant, never
        // later than the commit. The store checks P-71 at `now`.
        let admit_at = stepup.map_or(now, |u| u.asserted_at.min(now));
        let Some((mut cell, admitted)) = self.gate(session, c, stepup, admit_at, p71_us)? else {
            return Ok(None);
        };
        match run_admitted(&mut cell, &admitted, session, now) {
            Ok(Ok(batch)) if !batch.is_empty() => Ok(Some(consumes(&batch, &admitted))),
            // Production refused the command at commit: the store refused
            // an append past the step-up's P-71 limit, or `decide` or the
            // `AddPasskey` route refused it.
            Ok(Err(ExecError::Refused(_))) | Err(ProdError::Refused(_)) => Ok(None),
            Err(ProdError::NotImplemented(op)) => Err(NotImplemented::new(op)),
            Ok(_) => Err(NotImplemented::new(STEPUP_HARNESS_FAILED)),
        }
    }
}

/// A defect a teeth test seeds into a backend (design section 14.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StepUpDefect {
    /// A step-up 1 µs past P-71 is still accepted.
    StaleAccepted,
    /// `>=` for staleness: a step-up exactly P-71 old is refused.
    FreshAtP71Refused,
    /// The batch does not consume the step-up, and the gate ignores consumption.
    ConsumptionDropped,
    /// The digest is compared by the command's kind only.
    DigestComparedByKind,
    /// The gate forgets that a magic-link session never performs a
    /// high-risk action (design section 8.3).
    MagicLinkRuleDropped,
}

/// `inner` with one seeded defect.
#[derive(Clone, Debug)]
pub struct Mutant<B> {
    inner: B,
    defect: StepUpDefect,
}

impl<B: StepUpBackend> Mutant<B> {
    /// `inner` with `defect`.
    pub fn new(inner: B, defect: StepUpDefect) -> Mutant<B> {
        Mutant { inner, defect }
    }

    fn rewrite(&self, c: u8, stepup: Option<&RefStepUp>, p71_us: i64) -> (Option<RefStepUp>, i64) {
        let mut u = stepup.copied();
        let mut p = p71_us;
        match self.defect {
            StepUpDefect::StaleAccepted => p = p71_us.saturating_add(1),
            StepUpDefect::FreshAtP71Refused => p = p71_us.saturating_sub(1),
            StepUpDefect::ConsumptionDropped => {
                if let Some(x) = u.as_mut() {
                    x.consumed = false;
                }
            }
            StepUpDefect::DigestComparedByKind => {
                if let Some(x) = u.as_mut()
                    && command_of(&x.action_digest).and_then(class) == class(c)
                {
                    x.action_digest = digest(c);
                }
            }
            StepUpDefect::MagicLinkRuleDropped => {}
        }
        (u, p)
    }

    /// The session the inner backend sees: a magic-link session passes as
    /// a passkey session under [`StepUpDefect::MagicLinkRuleDropped`].
    fn session_seen(&self, session: &RefSession) -> RefSession {
        let mut s = *session;
        if self.defect == StepUpDefect::MagicLinkRuleDropped {
            s.method = RefMethod::Passkey;
        }
        s
    }
}

impl<B: StepUpBackend> StepUpBackend for Mutant<B> {
    fn admit(
        &self,
        session: &RefSession,
        c: u8,
        stepup: Option<&RefStepUp>,
        now: Timestamp,
        p71_us: i64,
    ) -> Result<bool, NotImplemented> {
        let (u, p) = self.rewrite(c, stepup, p71_us);
        self.inner
            .admit(&self.session_seen(session), c, u.as_ref(), now, p)
    }

    fn commit(
        &self,
        session: &RefSession,
        c: u8,
        stepup: Option<&RefStepUp>,
        now: Timestamp,
        p71_us: i64,
    ) -> Result<Option<bool>, NotImplemented> {
        let (u, p) = self.rewrite(c, stepup, p71_us);
        let out = self
            .inner
            .commit(&self.session_seen(session), c, u.as_ref(), now, p)?;
        if self.defect == StepUpDefect::ConsumptionDropped {
            return Ok(out.map(|_| false));
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// The model.

/// A step-up of the model, asserted at [`ASSERTED_AT`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Su {
    /// The session index.
    pub session: u8,
    /// The command it was requested for.
    pub cmd: u8,
    /// Whether the passkey gave user verification.
    pub uv: bool,
    /// Whether a committed batch consumed it.
    pub consumed: bool,
}

/// An admitted command waiting to commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Pending {
    /// The session index.
    pub session: u8,
    /// The command.
    pub cmd: u8,
    /// The step-up named, by index.
    pub stepup: Option<u8>,
    /// The tick of admission.
    pub admitted: u8,
}

/// A committed command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Commit {
    /// The session index.
    pub session: u8,
    /// The command.
    pub cmd: u8,
    /// The step-up named, by index.
    pub stepup: Option<u8>,
    /// The tick of admission.
    pub admitted: u8,
    /// The tick of commit.
    pub committed: u8,
}

/// The state of M-STEPUP.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StepUpState {
    /// The P-71 variant: 0 for 5 minutes, 1 for 1 minute.
    pub p71: u8,
    /// The tick.
    pub tick: u8,
    /// The step-ups, by index.
    pub stepups: Vec<Su>,
    /// The admitted command, if any.
    pub pending: Option<Pending>,
    /// The committed commands, in order.
    pub commits: Vec<Commit>,
    /// Whether the backend refused an admission that offered a consumed
    /// step-up again (witness).
    pub replay_refused: bool,
    /// The first commit decision of the backend that differed from the
    /// reference's.
    pub diverged: Option<String>,
    /// The first backend operation that answered `NotImplemented`.
    pub halt: Option<&'static str>,
}

/// The most step-ups of a run.
pub const MAX_STEPUPS: usize = 2;
/// The most commits of a run: one, then one replay.
pub const MAX_COMMITS: usize = 2;

/// The step-up requests of the universe: by passkey with UV for every
/// command, by passkey without UV for a role grant, and from the
/// magic-link session for a role grant and for adding a passkey to its
/// own account.
pub const STEPUP_REQUESTS: [(u8, u8, bool); 7] = [
    (S_ADMIN, 0, true),
    (S_ADMIN, 1, true),
    (S_ADMIN, 2, true),
    (S_ADMIN, 3, true),
    (S_ADMIN, 0, false),
    (S_MAGIC, 0, true),
    (S_MAGIC, 3, true),
];

/// The admissions of the universe: every command in the admin session,
/// and in the magic-link session a role grant and `AddPasskey` for its
/// own account. Only the magic-link rule refuses the last one (design
/// section 8.3).
pub const ADMITS: [(u8, u8); 6] = [
    (S_ADMIN, 0),
    (S_ADMIN, 1),
    (S_ADMIN, 2),
    (S_ADMIN, 3),
    (S_MAGIC, 0),
    (S_MAGIC, 3),
];

impl StepUpState {
    /// The time now.
    pub fn now(&self) -> Timestamp {
        at(self.p71, self.tick)
    }

    /// The P-71 in microseconds.
    pub fn p71_us(&self) -> i64 {
        p71(self.p71)
    }

    /// The reference step-up at index `i`.
    pub fn stepup(&self, i: u8) -> Option<RefStepUp> {
        let su = self.stepups.get(usize::from(i))?;
        let mut id = [0u8; 16];
        id[0] = 0x5C;
        id[1] = i;
        Some(RefStepUp {
            id,
            session: session(su.session).id,
            action_digest: digest(su.cmd),
            asserted_at: ASSERTED_AT,
            method: RefMethod::Passkey,
            uv: su.uv,
            consumed: su.consumed,
        })
    }

    /// The step-up choices of an admission: none, or each existing one.
    pub fn stepup_choices(&self) -> Vec<Option<u8>> {
        let mut out = vec![None];
        for i in 0..self.stepups.len() {
            if let Ok(i) = u8::try_from(i) {
                out.push(Some(i));
            }
        }
        out
    }
}

/// The action of M-STEPUP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StepUpAction {
    /// The clock moves one tick.
    Tick,
    /// `POST /auth/stepup` in the session for the command, with or without UV.
    StepUp(u8, u8, bool),
    /// The gate admits the command in the session, naming the step-up.
    Admit(u8, u8, Option<u8>),
    /// The admitted command commits, or is refused at commit.
    Commit,
}

/// M-STEPUP over a backend.
#[derive(Clone, Debug)]
pub struct StepUpModel<B> {
    backend: B,
}

impl<B: StepUpBackend> StepUpModel<B> {
    /// The model over `backend`.
    pub fn new(backend: B) -> StepUpModel<B> {
        StepUpModel { backend }
    }

    /// The backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

impl<B: StepUpBackend> Model for StepUpModel<B> {
    type State = StepUpState;
    type Action = StepUpAction;

    fn init(&self) -> Vec<StepUpState> {
        (0..2u8)
            .map(|p71| StepUpState {
                p71,
                tick: 0,
                stepups: Vec::new(),
                pending: None,
                commits: Vec::new(),
                replay_refused: false,
                diverged: None,
                halt: None,
            })
            .collect()
    }

    fn actions(&self, s: &StepUpState, out: &mut Vec<StepUpAction>) {
        if s.halt.is_some() {
            return;
        }
        out.push(StepUpAction::Tick);
        for (session, cmd, uv) in STEPUP_REQUESTS {
            out.push(StepUpAction::StepUp(session, cmd, uv));
        }
        for (session, cmd) in ADMITS {
            for u in s.stepup_choices() {
                out.push(StepUpAction::Admit(session, cmd, u));
            }
        }
        out.push(StepUpAction::Commit);
    }

    fn step(&self, s: &StepUpState, a: &StepUpAction) -> Option<StepUpState> {
        let mut next = s.clone();
        match *a {
            StepUpAction::Tick => {
                next.tick = s.tick.checked_add(1).filter(|t| *t <= 3)?;
                Some(next)
            }
            StepUpAction::StepUp(session, cmd, uv) => {
                if s.tick != 0 || s.stepups.len() >= MAX_STEPUPS {
                    return None;
                }
                next.stepups.push(Su {
                    session,
                    cmd,
                    uv,
                    consumed: false,
                });
                Some(next)
            }
            StepUpAction::Admit(sess, cmd, u) => {
                if s.pending.is_some() || s.commits.len() >= MAX_COMMITS {
                    return None;
                }
                let su = match u {
                    Some(i) => Some(s.stepup(i)?),
                    None => None,
                };
                match self
                    .backend
                    .admit(&session(sess), cmd, su.as_ref(), s.now(), s.p71_us())
                {
                    Err(e) => {
                        next.halt = Some(e.operation);
                        Some(next)
                    }
                    Ok(false) => {
                        let replay = su.is_some_and(|x| x.consumed);
                        if replay && !s.replay_refused {
                            next.replay_refused = true;
                            Some(next)
                        } else {
                            None
                        }
                    }
                    Ok(true) => {
                        next.pending = Some(Pending {
                            session: sess,
                            cmd,
                            stepup: u,
                            admitted: s.tick,
                        });
                        Some(next)
                    }
                }
            }
            StepUpAction::Commit => {
                let p = s.pending?;
                next.pending = None;
                let su = match p.stepup {
                    Some(i) => Some(s.stepup(i)?),
                    None => None,
                };
                let got = self.backend.commit(
                    &session(p.session),
                    p.cmd,
                    su.as_ref(),
                    s.now(),
                    s.p71_us(),
                );
                let want =
                    Reference.commit(&session(p.session), p.cmd, su.as_ref(), s.now(), s.p71_us());
                if let (Ok(g), Ok(w)) = (&got, &want)
                    && g != w
                    && next.diverged.is_none()
                {
                    next.diverged = Some(format!(
                        "two-way: commit of {p:?} at tick {} is {g:?}, reference {w:?}",
                        s.tick
                    ));
                }
                match got {
                    Err(e) => next.halt = Some(e.operation),
                    Ok(None) => {}
                    Ok(Some(consumed)) => {
                        next.commits.push(Commit {
                            session: p.session,
                            cmd: p.cmd,
                            stepup: p.stepup,
                            admitted: p.admitted,
                            committed: s.tick,
                        });
                        if let (true, Some(i)) = (consumed, p.stepup)
                            && let Some(x) = next.stepups.get_mut(usize::from(i))
                        {
                            x.consumed = true;
                        }
                    }
                }
                Some(next)
            }
        }
    }

    fn is_terminal(&self, s: &StepUpState) -> bool {
        s.halt.is_some()
    }
}

// ---------------------------------------------------------------------------
// Properties.

/// The property ids of M-STEPUP.
pub mod ids {
    /// Every backend answer was given; a stub halts the run here only.
    pub const BACKEND_ANSWERS: &str = "backend-answers";
    /// I-78: every committed high-risk command had a strong, fresh, unconsumed step-up for its digest.
    pub const I78: &str = "I-78";
    /// I-78: no step-up authorised two commits.
    pub const I78_SINGLE_USE: &str = "I-78-single-use";
    /// Two-way: every admission and commit decision equals the reference's.
    pub const TWO_WAY: &str = "two-way";
    /// Witness: a command commits exactly P-71 after its step-up.
    pub const W_AT_P71: &str = "witness-commit-at-exactly-p71";
    /// Witness: a consumed step-up is offered again, and the backend
    /// refuses the admission.
    pub const W_REPLAY: &str = "witness-replay-refused";
}

/// Why the commit `c` breaks I-78, given the state before it.
fn i78_breach(s: &StepUpState, c: &Commit) -> Option<String> {
    let Some(i) = c.stepup else {
        return Some(format!("I-78: {c:?} committed with no step-up"));
    };
    let Some(su) = s.stepups.get(usize::from(i)) else {
        return Some(format!("I-78: {c:?} named a missing step-up"));
    };
    let sess = session(c.session);
    let p = s.p71_us();
    let fresh = |tick| r::within(ASSERTED_AT, at(s.p71, tick), p);
    if !sess.method.phishing_resistant() {
        Some(format!("I-78: {c:?} committed in a magic-link session"))
    } else if su.session != c.session {
        Some(format!("I-78: {c:?} used another session's step-up"))
    } else if digest(su.cmd) != digest(c.cmd) {
        Some(format!("I-78: {c:?} used a step-up for command {}", su.cmd))
    } else if !su.uv {
        Some(format!(
            "I-78: {c:?} used a step-up without user verification"
        ))
    } else if !fresh(c.admitted) || !fresh(c.committed) {
        Some(format!("I-78: {c:?} used a step-up older than P-71"))
    } else if s.commits.iter().any(|x| x.stepup == c.stepup) {
        Some(format!("I-78: {c:?} used a consumed step-up"))
    } else {
        None
    }
}

/// The two-way check of one state: the commit decisions so far, then
/// every admission.
fn two_way<B: StepUpBackend>(m: &StepUpModel<B>, s: &StepUpState) -> Result<(), String> {
    if let Some(why) = &s.diverged {
        return Err(why.clone());
    }
    for (sess, cmd) in ADMITS {
        for u in s.stepup_choices() {
            let su = u.and_then(|i| s.stepup(i));
            let want = Reference
                .admit(&session(sess), cmd, su.as_ref(), s.now(), s.p71_us())
                .unwrap_or(false);
            if let Ok(got) =
                m.backend()
                    .admit(&session(sess), cmd, su.as_ref(), s.now(), s.p71_us())
                && got != want
            {
                return Err(format!(
                    "two-way: admit of {cmd} in session {sess} with {u:?} at tick {} is {got}, reference {want}",
                    s.tick
                ));
            }
        }
    }
    Ok(())
}

/// Every property of M-STEPUP.
pub fn properties<'a, B: StepUpBackend>(
    m: &'a StepUpModel<B>,
) -> Vec<Property<'a, StepUpModel<B>>> {
    vec![
        Property::always_with(ids::BACKEND_ANSWERS, |s: &StepUpState| match s.halt {
            None => Ok(()),
            Some(op) => Err(format!("the backend did not answer: {op}")),
        }),
        Property::transition_with(
            ids::I78,
            |s: &StepUpState, _a: &StepUpAction, t: &StepUpState| {
                if t.commits.len() <= s.commits.len() {
                    return Ok(());
                }
                match t.commits.last().and_then(|c| i78_breach(s, c)) {
                    None => Ok(()),
                    Some(why) => Err(why),
                }
            },
        ),
        Property::always_with(ids::I78_SINGLE_USE, |s: &StepUpState| {
            for (i, c) in s.commits.iter().enumerate() {
                let reused = s
                    .commits
                    .iter()
                    .skip(i.saturating_add(1))
                    .any(|x| x.stepup.is_some() && x.stepup == c.stepup);
                if reused {
                    return Err(format!(
                        "I-78-single-use: step-up {:?} authorised two commits",
                        c.stepup
                    ));
                }
            }
            Ok(())
        }),
        Property::always_with(ids::TWO_WAY, move |s: &StepUpState| two_way(m, s)),
        Property::reachable(ids::W_AT_P71, |s: &StepUpState| {
            s.commits.iter().any(|c| c.committed == 2)
        }),
        Property::reachable(ids::W_REPLAY, |s: &StepUpState| s.replay_refused),
    ]
}

/// The account of the admin session, for tests that name it.
pub const ADMIN_ACCOUNT: AccountId = ADMIN;
