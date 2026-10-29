//! Shared support for the `fstp-cell-core` suites (M3 design sections 5.1,
//! 5.2, 5.4, 8.4 and 15).
//!
//! The helpers are written from the design text, not from the production
//! code. Helpers return `Result` with a message. Only test functions
//! assert.
//!
//! # Seams
//!
//! Each `*_SEAM` constant names an API the design or a W1 test expects and
//! the W0 stubs lack. Its function refuses with [`Seam`], so a test that
//! needs it is red for that reason and compiles today. These are API
//! requests to the production agent of lane W2c. That agent replaces each
//! seam body with a call into the crate once the API lands, and changes
//! nothing else in these suites. A test that reaches a stub refusal first
//! names the stub's `NotImplemented` instead.
//!
//! # Fixtures
//!
//! Accounts, programmes and instants come from the synthetic corpus of
//! `fstp-domain-testkit` (`gen::roster`).

#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::fmt;

use fstp_auth::{Method, SessionView};
use fstp_cell_core::driver::DriverCore;
use fstp_cell_core::gate::{self, Action, Admitted, Deny, LoginPolicy, StepUpView};
use fstp_cell_core::tenant::TenantRecord;
use fstp_cell_core::{CellCommand, CellRecord, CellState, FoldError};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_ledger::{Entry, MemStore, RecordStore, Seq};

// ---------------------------------------------------------------------------
// Seams.

/// A missing API. It names the seam constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Seam(pub(crate) &'static str);

impl fmt::Display for Seam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (NotImplemented)", self.0)
    }
}

/// The stored bytes of a cell record. `PgRecordStore<_, T, _>` needs
/// `T: fstp_ledger::Canonical` (design section 5.3), and the fuzz targets
/// of section 15 need an encoder for "every schema version round-trips".
/// The stubs hold decoders only.
pub(crate) const ENCODE_RECORD_SEAM: &str = "fstp-cell-core has no CellRecord encoder: impl fstp_ledger::Canonical for CellRecord (design sections 5.1, 5.3 and 15, lane W2c)";

/// The RFC 8785 bytes of `r`, as `Canonical::canonical` gives them.
pub(crate) fn encode_record(r: &CellRecord) -> Result<Vec<u8>, Seam> {
    Ok(fstp_ledger::Canonical::canonical(r))
}

/// The canonical bytes of a cell command. The step-up action digest is
/// `SHA-256(canonical(command) || command_id)` (design section 8.4), and
/// the fuzz target `cell_command_decode` round-trips commands. The stubs
/// hold a decoder only.
pub(crate) const ENCODE_COMMAND_SEAM: &str =
    "fstp-cell-core has no CellCommand encoder (design sections 8.4 and 15, lane W2c)";

/// The canonical bytes of `c`, which `decode_cell_command` reads back.
pub(crate) fn encode_command(c: &CellCommand) -> Result<Vec<u8>, Seam> {
    Ok(fstp_cell_core::encode_cell_command(c))
}

/// The action digest of a command under a command id, as the gate
/// computes it. `gate::admit` takes no command id, so no caller can offer
/// a step-up whose digest the gate would match (design section 8.4;
/// `fstp_celltest::mc::stepup_model::DIGEST_SEAM`).
pub(crate) const ACTION_DIGEST_SEAM: &str = "fstp-cell-core exposes no action digest and gate::admit takes no command id (design section 8.4, lane W2c)";

/// `SHA-256(canonical(cmd) || command_id)`.
pub(crate) fn action_digest(cmd: &CellCommand, command_id: [u8; 16]) -> Result<[u8; 32], Seam> {
    Ok(fstp_cell_core::action_digest(cmd, command_id))
}

/// The gate with the caller's command id, so it can compare the step-up
/// digest with the digest of this command (design section 8.4). Once the
/// gate takes the id, this calls it.
pub(crate) fn admit_with_id(
    s: &CellState,
    session: &SessionView,
    action: Action,
    command_id: [u8; 16],
    stepup: Option<&StepUpView>,
    now: Timestamp,
    policy: &LoginPolicy,
) -> Result<Result<Admitted, Deny>, Seam> {
    Ok(gate::admit_command(
        s, session, action, command_id, stepup, now, policy,
    ))
}

/// The caller's command id at driver start (design section 5.2;
/// `fstp_celltest::mc::driver_model::COMMAND_ID_SEAM`).
pub(crate) const COMMAND_ID_SEAM: &str =
    "DriverCore::start takes no caller command id (design section 5.2, lane W2c)";

/// `DriverCore` for `admitted` under the caller's command id `id`.
pub(crate) fn start_with_id(admitted: Admitted, id: [u8; 16]) -> Result<DriverCore, Seam> {
    Ok(DriverCore::start_with_id(admitted, id))
}

/// The SoD-07 grant digest: SHA-256 over the canonical `GrantRole`
/// without `second_admin`, plus its command id (design section 5.1).
/// Neither `CellCtx` nor `attest` takes a command id, and no encoder
/// exists (`fstp_celltest::mc::stepup_model::SELF_GRANT_DIGEST_SEAM`).
pub(crate) const SELF_GRANT_DIGEST_SEAM: &str = "fstp-cell-core exposes no SoD-07 grant digest, and attest takes no command id and no instant (design section 5.1, lane W2c)";

/// The SoD-07 digest of `grant` under `command_id`.
pub(crate) fn self_grant_digest(
    grant: &fstp_engine::Command,
    command_id: [u8; 16],
) -> Result<[u8; 32], Seam> {
    fstp_cell_core::self_grant_digest(grant, command_id).ok_or(Seam(SELF_GRANT_DIGEST_SEAM))
}

/// `attest` for `cmd` under `command_id` at `now`. The approval matches
/// the grant's digest, which holds the command id, and lapses at its
/// `expires_at` (design section 5.1, Q40).
pub(crate) fn attest_at(
    s: &CellState,
    actor: AccountId,
    cmd: &fstp_engine::Command,
    command_id: [u8; 16],
    now: Timestamp,
) -> Result<fstp_cell_core::Attestation, Seam> {
    Ok(fstp_cell_core::attest_at(s, actor, cmd, command_id, now))
}

/// The record that consumes a step-up. Design section 5.1 names
/// `StepUpConsumed { id }`, and `fstp_auth::AuthRecord` has no such
/// variant (`fstp_celltest::mc::stepup_model::CONSUME_SEAM`).
pub(crate) const CONSUME_SEAM: &str =
    "AuthRecord has no StepUpConsumed { id } (design section 5.1, lanes W2b and W2c)";

/// `CellRecord::Auth(AuthRecord::StepUpConsumed { id })`.
pub(crate) fn step_up_consumed(id: [u8; 16]) -> Result<CellRecord, Seam> {
    let _ = id;
    Err(Seam(CONSUME_SEAM))
}

/// Whether `r` is the consumption of step-up `id`.
pub(crate) fn is_step_up_consumed(r: &CellRecord, id: [u8; 16]) -> Result<bool, Seam> {
    let _ = (r, id);
    Err(Seam(CONSUME_SEAM))
}

// ---------------------------------------------------------------------------
// Stub refusals as messages.

/// A stub refusal, or any other error, as text.
pub(crate) fn shown<E: fmt::Debug>(e: E) -> String {
    format!("{e:?}")
}

/// Whether a `Debug` form names a stub refusal.
pub(crate) fn is_stub(shown: &str) -> bool {
    shown.contains("NotImplemented")
}

// ---------------------------------------------------------------------------
// Instants and policy.

/// One minute in microseconds.
pub(crate) const MINUTE_US: i64 = 60 * 1_000_000;
/// One hour in microseconds.
pub(crate) const HOUR_US: i64 = 60 * MINUTE_US;
/// P-71, the default step-up freshness: 5 minutes (proposed, Q37).
pub(crate) const P71_US: i64 = 5 * MINUTE_US;
/// P-72, the default idle lifetime: 30 minutes (proposed, Q37).
pub(crate) const P72_IDLE_US: i64 = 30 * MINUTE_US;
/// P-72, the default absolute lifetime: 12 hours (proposed, Q37).
pub(crate) const P72_ABSOLUTE_US: i64 = 12 * HOUR_US;

/// The default login policy.
pub(crate) const POLICY: LoginPolicy = LoginPolicy {
    stepup_freshness_us: P71_US,
};

/// The instant most gate tests run at: one hour after the corpus `T0`.
pub(crate) const NOW: Timestamp = Timestamp::from_micros(1_000_000 + HOUR_US);

/// `t` moved by `us` microseconds.
pub(crate) fn plus(t: Timestamp, us: i64) -> Timestamp {
    Timestamp::from_micros(t.micros() + us)
}

// ---------------------------------------------------------------------------
// Sessions and step-ups.

/// A session of `account` by `method`, started at `started` and last used
/// at `last_used`.
pub(crate) fn session(
    id: u8,
    account: AccountId,
    method: Method,
    started: Timestamp,
    last_used: Timestamp,
) -> SessionView {
    SessionView {
        id: [id; 16],
        account,
        method,
        started,
        last_used,
    }
}

/// A passkey session of `account`, started one minute before [`NOW`] and
/// used at [`NOW`].
pub(crate) fn passkey(account: AccountId) -> SessionView {
    session(0x51, account, Method::Passkey, plus(NOW, -MINUTE_US), NOW)
}

/// A magic-link session of `account`, started one minute before [`NOW`].
pub(crate) fn magic(account: AccountId) -> SessionView {
    session(0x52, account, Method::MagicLink, plus(NOW, -MINUTE_US), NOW)
}

/// A strong, unused step-up in `session` for `digest`, asserted at `at`.
pub(crate) fn stepup(session: &SessionView, digest: [u8; 32], at: Timestamp) -> StepUpView {
    StepUpView {
        id: [0x5C; 16],
        session: session.id,
        action_digest: digest,
        asserted_at: at,
        strong: true,
        consumed: false,
    }
}

/// The gate on `action` with no step-up at `now` under [`POLICY`].
pub(crate) fn admit_plain(
    s: &CellState,
    session: &SessionView,
    action: Action,
    now: Timestamp,
) -> Result<Admitted, Deny> {
    gate::admit(s, session, action, None, now, &POLICY)
}

// ---------------------------------------------------------------------------
// Ledgers.

/// One batch of a test ledger: its time, its command id and its records.
pub(crate) type Batch = (Timestamp, [u8; 16], Vec<CellRecord>);

/// A cell ledger: each batch with its time and command id, appended in
/// order to a fresh `MemStore` and read back. Entries outside the crate
/// come only from a store or the decoder.
pub(crate) fn ledger(batches: &[Batch]) -> Result<Vec<Entry<CellRecord>>, String> {
    let mut store: MemStore<CellRecord> = MemStore::new();
    for (at, command, batch) in batches {
        store
            .append(store.head(), at.micros(), *command, batch.clone())
            .map_err(|e| format!("ledger append: {e:?}"))?;
    }
    read_all(&store)
}

/// Every entry of `store`.
pub(crate) fn read_all<R: Clone>(store: &MemStore<R>) -> Result<Vec<Entry<R>>, String> {
    let mut out = Vec::new();
    store
        .read(Seq::ZERO, usize::MAX, &mut out)
        .map_err(|e| format!("read: {e:?}"))?;
    Ok(out)
}

/// The state after `entries`, or the fold error as text.
pub(crate) fn state_of(entries: &[Entry<CellRecord>]) -> Result<CellState, String> {
    fstp_cell_core::replay(entries).map_err(|e: FoldError| format!("replay: {e:?}"))
}

/// The tenant admin grant of `account`.
pub(crate) fn admin_granted(account: AccountId) -> CellRecord {
    CellRecord::Tenant(TenantRecord::TenantAdminGranted { account })
}

/// The tenant admin end of `account`.
pub(crate) fn admin_ended(account: AccountId) -> CellRecord {
    CellRecord::Tenant(TenantRecord::TenantAdminEnded { account })
}

/// A command id from one byte, with no reserved prefix.
pub(crate) const fn cid(n: u8) -> [u8; 16] {
    [n; 16]
}

/// The state in which each of `admins` was made tenant admin at `T0`.
pub(crate) fn with_admins(admins: &[AccountId]) -> Result<CellState, String> {
    let batches: Vec<_> = admins
        .iter()
        .enumerate()
        .map(|(i, a)| {
            (
                fstp_domain_testkit::r#gen::roster::T0,
                cid(0xA0 + u8::try_from(i).unwrap_or(0)),
                vec![admin_granted(*a)],
            )
        })
        .collect();
    state_of(&ledger(&batches)?)
}

/// The M2 entries as cell entries: each record in the `Engine` member,
/// with sequence, time, command id and schema kept.
pub(crate) fn as_cell(entries: &[Entry<fstp_engine::Record>]) -> Vec<Entry<CellRecord>> {
    entries
        .iter()
        .cloned()
        .map(|e| e.map_record(CellRecord::Engine))
        .collect()
}

/// The M2 corpus ledger: one programme with P-12 of 2, call 1 drafted,
/// approved and published, and the programme manager and call drafter
/// granted at `T0`. Every step runs through the M2 reference engine over
/// the synthetic vault of `sod_truth`.
pub(crate) fn m2_setup() -> Result<fstp_domain_testkit::scenario::Scenario, String> {
    use fstp_domain_testkit::r#gen::review::run_records;
    use fstp_domain_testkit::r#gen::roster::{SodSetup, T0, call, sod_truth};
    let mut setup = SodSetup::one(2, &[1]);
    setup.published = vec![call(1)];
    let mut s = fstp_domain_testkit::scenario::Scenario::new(sod_truth())
        .map_err(|e| format!("open: {e:?}"))?;
    for step in setup.steps()? {
        if let Err(r) = run_records(&mut s, &step, T0)? {
            return Err(format!("setup step {:?} refused: {r}", step.cmd.kind()));
        }
    }
    Ok(s)
}

/// Runs `step` at `now` on `s` through the M2 reference engine. A refusal
/// is an error.
pub(crate) fn m2_run(
    s: &mut fstp_domain_testkit::scenario::Scenario,
    step: &fstp_domain_testkit::r#gen::roster::Step,
    now: Timestamp,
) -> Result<(), String> {
    match fstp_domain_testkit::r#gen::review::run_records(s, step, now)? {
        Ok(_) => Ok(()),
        Err(r) => Err(format!("{:?} refused: {r}", step.cmd.kind())),
    }
}

/// The M2 entries of `s`.
pub(crate) fn m2_entries(
    s: &fstp_domain_testkit::scenario::Scenario,
) -> Result<Vec<Entry<fstp_engine::Record>>, String> {
    s.entries().map_err(|e| format!("entries: {e:?}"))
}

// ---------------------------------------------------------------------------
// Designed signatures.
//
// The W0 stub gives `HighRiskAction::of` and `attest` a `Result`, while
// design sections 5.1 and 5.4 make both infallible. The suites call them
// only through these two helpers, so restoring the designed signatures
// changes one line here.

/// `HighRiskAction::of`, with a stub refusal as text.
pub(crate) fn high_risk_of(a: &Action) -> Result<Option<gate::HighRiskAction>, String> {
    gate::HighRiskAction::of(a).map_err(shown)
}

/// `attest`, with a stub refusal as text.
pub(crate) fn attest_of(
    s: &CellState,
    actor: AccountId,
    cmd: &fstp_engine::Command,
) -> Result<fstp_cell_core::Attestation, String> {
    fstp_cell_core::attest(s, actor, cmd).map_err(shown)
}

// ---------------------------------------------------------------------------
// The commands of the high-risk table.

/// One command for each table entry that the stubs can build, by table
/// name (design section 8.4).
///
/// Readings, as lane W1b took them in `fstp-celltest`: `AddPasskey` has
/// no command of its own, so `RegisterCredential` stands in. Removing a
/// device is `RevokeCredential`, which section 8.7 classes as
/// `ChangeLoginMethods`.
pub(crate) fn table_commands() -> Result<Vec<(&'static str, CellCommand)>, String> {
    use fstp_auth::AuthCommand;
    use fstp_cell_core::ops::OpsCommand;
    use fstp_cell_core::tenant::TenantCommand;
    use fstp_domain::assignment::AssignmentKind;
    use fstp_domain::id::{AssignmentId, BindingId, ProposalId, RequestId};
    use fstp_domain::roles::Role;
    use fstp_domain_testkit::r#gen::roster::{
        A, ADMIN_2, P1, SodSetup, T0, call, end, grant, publish, reinstate,
    };
    fn core(c: fstp_domain::Command) -> CellCommand {
        CellCommand::Engine(fstp_engine::Command::Core(c))
    }
    let create = SodSetup::one(2, &[1])
        .steps()?
        .first()
        .map(|s| s.cmd.clone())
        .ok_or("the corpus setup has no steps")?;
    Ok(vec![
        ("CreateProgramme", core(create)),
        (
            "GrantRole",
            core(grant(BindingId::from_raw(4_001), A, P1, Role::CommitteeMember, T0).cmd),
        ),
        ("EndRole", core(end(BindingId::from_raw(11), T0).cmd)),
        (
            "ReinstateBinding",
            core(reinstate(BindingId::from_raw(11)).cmd),
        ),
        (
            "Assign",
            core(fstp_domain::Command::Assign {
                assignment: AssignmentId::from_raw(1),
                proposal: ProposalId::from_raw(1),
                reviewer: A,
                kind: AssignmentKind::Reviewer,
                handle: None,
            }),
        ),
        (
            "Unassign",
            core(fstp_domain::Command::Unassign {
                assignment: AssignmentId::from_raw(1),
            }),
        ),
        (
            "ApprovePayment",
            core(fstp_domain::Command::ApprovePayment {
                request: RequestId::from_raw(1),
            }),
        ),
        (
            "ReleasePayment",
            core(fstp_domain::Command::ReleasePayment {
                request: RequestId::from_raw(1),
            }),
        ),
        ("PublishCall", core(publish(call(1)).cmd)),
        (
            "GrantTenantAdmin",
            CellCommand::Tenant(TenantCommand::GrantTenantAdmin { account: ADMIN_2 }),
        ),
        (
            "EndTenantAdmin",
            CellCommand::Tenant(TenantCommand::EndTenantAdmin { account: ADMIN_2 }),
        ),
        (
            "ApproveSelfGrant",
            CellCommand::Tenant(TenantCommand::ApproveSelfGrant {
                grant_digest: [0x77; 32],
            }),
        ),
        (
            "SetLoginPolicy",
            CellCommand::Tenant(TenantCommand::SetLoginPolicy {
                policy: b"{}".to_vec(),
            }),
        ),
        (
            "AddPasskey",
            CellCommand::Auth(AuthCommand::RegisterCredential {
                account: ADMIN_2,
                credential: vec![1, 2, 3],
            }),
        ),
        (
            "ChangeLoginMethods",
            CellCommand::Auth(AuthCommand::RevokeCredential {
                account: ADMIN_2,
                credential: vec![1, 2, 3],
            }),
        ),
        (
            "ApproveBreakGlass",
            CellCommand::Ops(OpsCommand::ApproveBreakGlass {
                request: [0x42; 16],
            }),
        ),
    ])
}

/// The table action of the entry named `name`.
pub(crate) fn table_action(name: &str) -> Option<gate::HighRiskAction> {
    gate::HIGH_RISK_TABLE
        .iter()
        .find(|e| e.command == name)
        .map(|e| e.action)
}
