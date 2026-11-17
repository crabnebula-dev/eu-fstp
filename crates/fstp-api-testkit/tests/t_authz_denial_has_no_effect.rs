//! `t_authz_denial_has_no_effect` (T-AUTHZ-MATRIX; M4 design section
//! 8.3; R-AC-01, I-84, I-85).
//!
//! Every denial leaves the ledger head, the outbox, the workspaces, the
//! caller's pending actions and the token table unchanged. This is a
//! property over a sample of the matrix cells the reference denies, at
//! the SuperSAFE policy row: operations, principals, states and sessions.
//! It is not a matrix run. Each sampled cell runs through dispatch on a
//! clean world of the matrix harness, as `t_authz_matrix_direct` runs it.
//! `fstp_api_testkit::harness::EffectProbe` reads the tables right
//! before the cell is sent and again after its reply.
//!
//! The fake cell's outbox keeps no table of its own: its notices are a
//! function of the ledger, so the ledger head covers it
//! (`fstp_api_testkit::harness::Tables`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Mutex, OnceLock, PoisonError};

use fstp_api_testkit::harness::EffectProbe;
use fstp_api_testkit::matrix::{Cell, Matrix, agrees, class_of, matrix};
use fstp_api_testkit::reference::authz::{Expected, Policy, StateProfile};
use fstp_prop::{Config, check_with};

/// The cases of the property. Each may build a world from genesis.
const CASES: u32 = 256;

/// The matrix, built once.
fn the_matrix() -> &'static Matrix {
    static M: OnceLock<Matrix> = OnceLock::new();
    M.get_or_init(|| matrix().unwrap_or_else(|e| panic!("the matrix: {e}")))
}

/// Per state, the cells the reference denies at the SuperSAFE row.
fn denied() -> &'static Vec<(StateProfile, Vec<Cell>)> {
    static D: OnceLock<Vec<(StateProfile, Vec<Cell>)>> = OnceLock::new();
    D.get_or_init(|| {
        let m = the_matrix();
        let mut out = Vec::new();
        for state in StateProfile::all() {
            let cells: Vec<Cell> = m
                .group_cells(state, Policy::SUPERSAFE)
                .into_iter()
                .filter(|c| matches!(m.reference().expected(c), Some(Expected::Deny(_))))
                .collect();
            if !cells.is_empty() {
                out.push((state, cells));
            }
        }
        out
    })
}

/// T-AUTHZ-MATRIX, R-AC-01: a sampled denied cell is refused as the
/// reference says, and its refusal changes none of the ledger head,
/// outbox, workspaces, pending actions and tokens.
#[test]
fn t_authz_denial_has_no_effect() {
    let states = denied();
    assert!(!states.is_empty(), "the reference denies no cell");
    let probe = Mutex::new(EffectProbe::new());
    check_with(
        "t_authz_denial_has_no_effect",
        Config::default().with_cases(CASES),
        |g| {
            let (_, cells) = g.pick(states);
            let cell = g.pick(cells);
            g.note("cell", cell);
            let expected = the_matrix().reference().expected(cell);
            let mut probe = probe.lock().unwrap_or_else(PoisonError::into_inner);
            let (observed, changed) = probe.run(cell).map_err(|e| format!("{e:?}"))?;
            match expected {
                Some(e) if agrees(e, class_of(&observed)) => {}
                other => {
                    return Err(format!(
                        "the reference denies with {other:?}, and the cell observed {observed:?}"
                    ));
                }
            }
            if changed.is_empty() {
                Ok(())
            } else {
                Err(format!(
                    "{} {:?} {:?}: the denial {observed:?} changed {changed:?}",
                    cell.op, cell.who, cell.state
                ))
            }
        },
    );
}

/// The probe has teeth: allowed command cells that complete move the
/// ledger head, and the probe reports it. A probe that compared nothing
/// would pass every denial.
#[test]
fn t_authz_denial_has_no_effect_probe_sees_an_allowed_write() {
    use fstp_access::OpKind;
    use fstp_api_testkit::matrix::Observed;
    let m = the_matrix();
    let mut probe = EffectProbe::new();
    let mut seen = Vec::new();
    for state in StateProfile::all() {
        for cell in m.group_cells(state, Policy::SUPERSAFE) {
            let command = fstp_access::op(cell.op)
                .is_some_and(|o| !matches!(o.kind, OpKind::Read(_) | OpKind::Public(_)));
            if !command || m.reference().expected(&cell) != Some(Expected::Allow) {
                continue;
            }
            let Ok((Observed::Completed, changed)) = probe.run(&cell) else {
                continue;
            };
            if changed.contains(&"ledger head") {
                return;
            }
            seen.push((cell.op, changed));
            if seen.len() >= 40 {
                break;
            }
        }
    }
    panic!("no completed command moved the ledger head as the probe saw it: {seen:?}");
}
