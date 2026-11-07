//! The driver seams of design sections 5.2 and 14.6: `DriverCore` against
//! the M2 reference engine, and NOTE 2 and NOTE 3 over `DriverCore`.
//!
//! Lane W1c wrote these tests before the production code. They drive
//! `DriverCore` through `mc::driver_model::Shell` and are red until lane
//! W2c lands the driver and the gate. After that they wait on the ledger
//! seam (`mc::driver_model::LEDGER_SEAM`) and the step-up digest seam
//! (`mc::stepup_model::DIGEST_SEAM`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use fstp_cell_core::driver::ExecError;
use fstp_cell_core::gate::{Admitted, Deny};
use fstp_cell_core::tenant::TenantCommand;
use fstp_cell_core::{CellCommand, CellRecord, CellRefusal};
use fstp_celltest::mc::driver_model::{
    self as d, AdmitError, FaultAt, Seen, Shell, ShellEntry, ShellError, ShellVault, paths,
};
use fstp_celltest::reference::vault::is_reaction_command_id;
use fstp_domain::command::Actor;
use fstp_domain::id::{AccountId, CommandId};
use fstp_domain::oracle::QueryKind;
use fstp_domain::rules::StateTag;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::review::run_records;
use fstp_domain_testkit::r#gen::roster::{ADMIN, Step, T0};
use fstp_domain_testkit::scenario::Scenario;
use fstp_domain_testkit::vault::{GroundTruth, IdentityTag};
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

/// A shell error as text. `ShellError` names a stub refusal or a seam as
/// `NotImplemented` itself, so a protocol fault reads as a seam failure.
fn shell_err(e: ShellError) -> String {
    e.to_string()
}

/// The cell command of an M2 step.
fn cell_command(step: &Step) -> CellCommand {
    CellCommand::Engine(fstp_engine::Command::Core(step.cmd.clone()))
}

/// Admits an M2 step through the gate, as its actor, with a passkey
/// session and a fresh step-up for a high-risk command. The inner `Err` is
/// a refusal of the gate itself. The outer `Err` is a stub refusal or a
/// seam.
fn try_admit_step(
    shell: &Shell,
    step: &Step,
    at: Timestamp,
    n: u8,
) -> Result<Result<Admitted, Deny>, String> {
    let Actor::Account(actor) = step.actor else {
        return Err(format!("{:?} is a system step", step.cmd.kind()));
    };
    match d::admit(shell.state(), cell_command(step), actor, at, [n; 16]) {
        Ok(a) => Ok(Ok(a)),
        Err(AdmitError::Denied(deny)) => Ok(Err(deny)),
        Err(e @ AdmitError::NotImplemented(_)) => Err(e.to_string()),
    }
}

/// [`try_admit_step`] for a step the gate must admit. A refusal of the
/// gate fails the test and names the `Deny`.
fn admit_step(shell: &Shell, step: &Step, at: Timestamp, n: u8) -> Result<Admitted, String> {
    try_admit_step(shell, step, at, n)?
        .map_err(|deny| format!("the gate refused {:?} with {deny:?}", step.cmd.kind()))
}

/// The shell over `truth`, with ADMIN made tenant admin from the tenant
/// fold, so `attest` gives the M2 steps their flags (design section 5.1).
///
/// Gap: the stubs have no first-admin enrolment, so ADMIN grants itself.
fn shell(truth: GroundTruth) -> Result<Shell, String> {
    let mut s = Shell::genesis(ShellVault::Truth(truth)).map_err(shell_err)?;
    let boot = CellCommand::Tenant(TenantCommand::GrantTenantAdmin { account: ADMIN });
    let a = d::admit(s.state(), boot, ADMIN, T0, [0xB0; 16]).map_err(|e| match e {
        AdmitError::Denied(deny) => {
            format!("the gate refused the tenant admin bootstrap with {deny:?}")
        }
        e @ AdmitError::NotImplemented(_) => e.to_string(),
    })?;
    match s.execute(a).map_err(shell_err)? {
        Ok(_) => Ok(s),
        Err(e) => Err(format!("the tenant admin bootstrap failed: {e:?}")),
    }
}

/// Whether `cmd` reaches the engine only through a creator composition
/// since strict D2e: the creator's `OpenDraft` composes a
/// `CreateProgramme` and its `ApproveActivation` an `ActivateProgramme`
/// (M4 design sections 3.4 and 15.0).
fn composed(cmd: &fstp_domain::Command) -> bool {
    matches!(
        cmd,
        fstp_domain::Command::CreateProgramme { .. }
            | fstp_domain::Command::ActivateProgramme { .. }
    )
}

/// The M2 core records of `entries`, in order.
fn core_records(entries: &[ShellEntry]) -> Vec<fstp_domain::Record> {
    entries
        .iter()
        .flat_map(|e| e.batch.iter())
        .filter_map(|r| match r {
            CellRecord::Engine(fstp_engine::Record::Core(c)) => Some(c.clone()),
            _ => None,
        })
        .collect()
}

/// Design sections 5.2 and 14.6: the M2 generators run through
/// `DriverCore` over the shell and through `fstp_engine::Engine`. Each
/// step gives equal M2 records or an equal refusal.
///
/// The inputs are the paths to each state with some steps repeated, or
/// first issued by an account with no role (`paths::mutated`). The M2
/// engine refuses some of them, so the refusals are compared too. A gate
/// refusal (a `Deny` other than the stub one) passes only where the engine
/// refuses the step as well. Otherwise the test fails and names the
/// `Deny`.
///
/// Reading: the cell ledger also holds the tenant admin bootstrap and
/// auth records, which the M2 engine has no member for, so the comparison
/// is over the M2 core records of each step. The byte comparison of each
/// record waits on a `fstp-cell-core` encoder (the stubs hold decoders
/// only).
#[test]
fn seam_driver_core_matches_reference_engine() {
    fstp_prop::check(
        "seam_driver_core_matches_reference_engine",
        |g: &mut Gen| {
            let target = *g.pick(&paths::STATES);
            let adult = g.bool();
            let base = paths::to(target)?;
            let plan: Vec<paths::Mutation> = base
                .iter()
                .map(|_| paths::Mutation::ALL[g.weighted(&[4, 1, 1])])
                .collect();
            let path = paths::mutated(&base, &plan);
            let truth = paths::truth(adult);
            let mut engine = Scenario::new(truth.clone()).map_err(|e| format!("open: {e:?}"))?;
            let mut cell = shell(truth)?;
            // The cell's tenant admin bootstrap processes the vault change
            // first (NOTE 3), and the composed steps ask at the state's
            // epoch. So the reference processes it before the path too.
            let ctx = engine.ctx(T0, Actor::Account(ADMIN));
            engine
                .change_vault(|_| {}, ctx)
                .map_err(|e| format!("the reference vault change: {e:?}"))?;
            for (i, p) in path.iter().enumerate() {
                let want = run_records(&mut engine, &p.step, p.at)?;
                let before = cell.ledger().len();
                if composed(&p.step.cmd) {
                    // Strict D2e: both sides append the creator path's entry.
                    let id = [u8::try_from(i % 170).unwrap(); 16];
                    let got = cell
                        .execute_composed(&p.step, p.at, id)
                        .map_err(shell_err)?;
                    match (want, got) {
                        (Ok(records), Ok(())) => {
                            prop_assert_eq!(
                                core_records(&cell.ledger()[before..]),
                                records,
                                "step {i} {:?}",
                                p.step.cmd.kind()
                            );
                        }
                        (Err(r), Err(c)) => {
                            prop_assert_eq!(c, r, "step {i} {:?}", p.step.cmd.kind());
                        }
                        (w, c) => {
                            return Err(format!(
                                "step {i} {:?}: the engine gave {w:?}, the composed entry gave {c:?}",
                                p.step.cmd.kind()
                            ));
                        }
                    }
                    continue;
                }
                // Ids stay below 0xB0, the bootstrap's command id.
                let admitted =
                    try_admit_step(&cell, &p.step, p.at, u8::try_from(i % 170).unwrap())?;
                let admitted = match (admitted, &want) {
                    (Ok(a), _) => a,
                    // The gate refused a step the engine refuses too, so
                    // neither appends and the run goes on.
                    (Err(_), Err(_)) => continue,
                    (Err(deny), Ok(records)) => {
                        return Err(format!(
                            "step {i} {:?}: the gate refused with {deny:?}, the engine appended {records:?}",
                            p.step.cmd.kind()
                        ));
                    }
                };
                let got = cell.execute(admitted).map_err(shell_err)?;
                match (want, got) {
                    (Ok(records), Ok(_)) => {
                        prop_assert_eq!(
                            core_records(&cell.ledger()[before..]),
                            records,
                            "step {i} {:?}",
                            p.step.cmd.kind()
                        );
                    }
                    (Err(r), Err(ExecError::Refused(CellRefusal::Domain(c)))) => {
                        prop_assert_eq!(c, r, "step {i} {:?}", p.step.cmd.kind());
                    }
                    (w, c) => {
                        return Err(format!(
                            "step {i} {:?}: the engine gave {w:?}, DriverCore gave {c:?}",
                            p.step.cmd.kind()
                        ));
                    }
                }
            }
            Ok(())
        },
    );
}

/// The first step of the NEGOTIATION path whose M2 queries are not
/// empty, by index, from the engine's own state before it. A composed
/// set-up step never runs through `DriverCore` (strict D2e), so it is
/// skipped.
fn first_asking_step(path: &[paths::PathStep], truth: &GroundTruth) -> Result<usize, String> {
    let mut engine = Scenario::new(truth.clone()).map_err(|e| format!("open: {e:?}"))?;
    for (i, p) in path.iter().enumerate() {
        let ctx = p.step.ctx(p.at, CommandId::from_bytes([0xAA; 16]));
        if !composed(&p.step.cmd)
            && let Ok(q) = fstp_domain::queries(&engine.state().core, &p.step.cmd, &ctx)
            && !q.is_empty()
        {
            return Ok(i);
        }
        if let Err(r) = run_records(&mut engine, &p.step, p.at)? {
            return Err(format!("path step {i} refused by the engine: {r}"));
        }
    }
    Err("no step of the path asks the vault".to_owned())
}

/// The shell after the steps of `path` before `upto`, every one accepted.
fn shell_before(
    path: &[paths::PathStep],
    upto: usize,
    truth: GroundTruth,
) -> Result<Shell, String> {
    let mut cell = shell(truth)?;
    for (i, p) in path[..upto].iter().enumerate() {
        if composed(&p.step.cmd) {
            let id = [u8::try_from(i % 200).unwrap(); 16];
            if let Err(e) = cell
                .execute_composed(&p.step, p.at, id)
                .map_err(shell_err)?
            {
                return Err(format!("setup step {i} failed: {e:?}"));
            }
            continue;
        }
        let a = admit_step(&cell, &p.step, p.at, u8::try_from(i % 200).unwrap())?;
        if let Err(e) = cell.execute(a).map_err(shell_err)? {
            return Err(format!("setup step {i} failed: {e:?}"));
        }
    }
    Ok(cell)
}

/// A fresh account the vault verifies, so its epoch moves ahead.
const NEWCOMER: AccountId = AccountId::from_raw(777);

/// NOTE 2: every vault fault fails the command closed. The epoch request,
/// a query, the reaction's query or the acknowledgement fails, and the
/// command appends nothing. A reaction appended before a failed
/// acknowledgement stays, as NOTE 4 allows.
#[test]
fn seam_note2_every_vault_fault_fails_closed_and_appends_nothing() {
    fstp_prop::check(
        "seam_note2_every_vault_fault_fails_closed_and_appends_nothing",
        |g: &mut Gen| {
            let fault = *g.pick(&[
                FaultAt::Epoch,
                FaultAt::Ask,
                FaultAt::ReactionAsk,
                FaultAt::Ack,
            ]);
            let path = paths::to(StateTag::Negotiation)?;
            let truth = paths::truth(true);
            let at = first_asking_step(&path, &truth)?;
            let mut cell = shell_before(&path, at, truth)?;
            let mut faulty = cell.vault_mut().clone();
            if matches!(fault, FaultAt::ReactionAsk | FaultAt::Ack)
                && let ShellVault::Truth(t) = &mut faulty
            {
                t.set_identity(NEWCOMER, IdentityTag::new(777));
                t.verify(NEWCOMER);
            }
            *cell.vault_mut() = ShellVault::Faulty {
                inner: Box::new(faulty),
                faults: BTreeSet::from([fault]),
            };
            let before = cell.ledger().len();
            let a = admit_step(&cell, &path[at].step, path[at].at, 201)?;
            let got = cell.execute(a).map_err(shell_err)?;
            prop_assert_eq!(
                got.map(|_| ()),
                Err(ExecError::VaultFault),
                "NOTE 2: fault at {fault:?}"
            );
            let added = &cell.ledger()[before..];
            prop_assert!(
                added.iter().all(|e| is_reaction_command_id(e.command)),
                "NOTE 2: the failed command appended {added:?}"
            );
            prop_assert!(
                fault == FaultAt::Ack || added.is_empty(),
                "NOTE 2: a fault at {fault:?} appended {added:?}"
            );
            Ok(())
        },
    );
}

/// NOTE 3: when the vault's epoch is ahead, `DriverCore` processes the
/// change first. Its first ask is the reaction's `ChangedSince` with
/// `reaction_for` set, the reaction is appended under its reserved id and
/// acknowledged, and only then does the command ask and append.
#[test]
fn seam_note3_stale_epoch_processes_the_change_first() {
    fstp_prop::check(
        "seam_note3_stale_epoch_processes_the_change_first",
        |g: &mut Gen| {
            let path = paths::to(StateTag::Negotiation)?;
            let truth = paths::truth(true);
            let at = first_asking_step(&path, &truth)?;
            let mut cell = shell_before(&path, at, truth)?;
            let moves = g.u8_in(1..=2);
            if let ShellVault::Truth(t) = cell.vault_mut() {
                for m in 0..moves {
                    let a = AccountId::from_raw(770 + u128::from(m));
                    t.set_identity(a, IdentityTag::new(770 + u64::from(m)));
                    t.verify(a);
                }
            }
            let seen_before = cell.seen().len();
            let a = admit_step(&cell, &path[at].step, path[at].at, 202)?;
            let got = cell.execute(a).map_err(shell_err)?;
            prop_assert!(got.is_ok(), "NOTE 3: the command failed: {got:?}");
            let seen = &cell.seen()[seen_before..];
            let first_ask = seen.iter().position(|s| matches!(s, Seen::Ask { .. }));
            let reaction_append = seen
                .iter()
                .position(|s| matches!(s, Seen::Append(id) if is_reaction_command_id(*id)));
            let ack = seen.iter().position(|s| matches!(s, Seen::Ack(_)));
            let command_append = seen
                .iter()
                .position(|s| matches!(s, Seen::Append(id) if !is_reaction_command_id(*id)));
            let reaction_ask = seen.iter().position(|s| {
                matches!(s, Seen::Ask { reaction_for: Some(_), kinds } if kinds.contains(&QueryKind::ChangedSince))
            });
            prop_assert_eq!(
                first_ask,
                reaction_ask,
                "NOTE 3: the first ask is not the reaction's: {seen:?}"
            );
            let order = [reaction_ask, reaction_append, ack, command_append];
            prop_assert!(
                order.iter().all(Option::is_some) && order.windows(2).all(|w| w[0] < w[1]),
                "NOTE 3 and NOTE 4: reaction ask, reaction append, ack, command append out of order: {seen:?}"
            );
            Ok(())
        },
    );
}
