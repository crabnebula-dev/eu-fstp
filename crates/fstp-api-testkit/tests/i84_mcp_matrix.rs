//! I-84: the authorisation matrix through the MCP channel (T-AUTHZ-MATRIX,
//! H-01, M4 design section 8.3, exit criterion "I-84 to I-87 green").
//!
//! `i84_t_authz_matrix_mcp_equals_channel_policy_of_web` runs every MCP
//! cell of the matrix through the MCP JSON-RPC handler of `fstp-mcp`
//! ([`matrix::mcp_channel`]) and checks two things:
//!
//! - every cell equals the independent reference, both ways, as the
//!   direct and HTTP channels are judged;
//! - parity: every MCP cell of an operation with a tool gives what
//!   `channel_policy` makes of its web twin. The web twin is the same
//!   operation, principal, state and policy row through the web, in a
//!   passkey session with a fresh step-up where the operation is
//!   high-risk. A channel denial must match exactly. `Prepare` must give a
//!   pending action, or the same guard refusal the web gives. `Execute`
//!   must give exactly the web outcome, the refusal rule included.
//!
//! Status: red. `matrix::mcp_channel` refuses until the harness gives it
//! a transport through `fstp_mcp::McpServer` (a harness seam).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_api_testkit::matrix::{self, Cell, Channel, ChannelFault, Denial, Observed};
use fstp_api_testkit::reference::authz::{
    AuthClass, Channel as Via, Expected, Login, Session, StepUp,
};

/// The web twin of an MCP cell: the same operation, principal, state and
/// policy row through the web, in a passkey session, with a fresh step-up
/// for a high-risk operation.
fn web_twin(cell: &Cell) -> Cell {
    let high_risk = fstp_access::op(cell.op).is_some_and(|o| o.high_risk);
    Cell {
        session: Session {
            login: Some(Login::Passkey),
            step_up: if high_risk {
                StepUp::Fresh
            } else {
                StepUp::Absent
            },
            channel: Via::Web,
        },
        ..*cell
    }
}

/// I-84 parity of one MCP cell: what `channel_policy` makes of the web
/// outcome, with the channel part read from the reference.
fn parity(expected: Expected, web: &Observed, mcp: &Observed) -> Result<(), String> {
    let denial = |c: AuthClass| match c {
        AuthClass::NotExposed => Some(Denial::NotExposed),
        AuthClass::Scope => Some(Denial::Scope),
        AuthClass::P74 => Some(Denial::P74),
        _ => None,
    };
    match expected {
        Expected::Deny(c) if denial(c).is_some() => {
            let want = Observed::ChannelDenied(denial(c).unwrap_or(Denial::NotExposed));
            if *mcp == want {
                Ok(())
            } else {
                Err(format!("channel denial {want:?} wanted, MCP gave {mcp:?}"))
            }
        }
        Expected::Pending => match (web, mcp) {
            (_, Observed::Pending) => Ok(()),
            (w, m) if w == m && matches!(w, Observed::Refused(_) | Observed::NotFound(_)) => Ok(()),
            (w, m) => Err(format!(
                "Prepare: MCP gave {m:?}, the web twin {w:?}; a pending action or the web's guard refusal wanted"
            )),
        },
        _ => {
            // Execute: the web outcome itself. A web step-up answer means
            // the twin completed after the fresh step-up, which MCP never
            // runs, so it cannot arise for an executed tool.
            if web == mcp {
                Ok(())
            } else {
                Err(format!("Execute: MCP gave {mcp:?}, the web twin {web:?}"))
            }
        }
    }
}

/// The channel the test runs: [`matrix::mcp_channel`], with the parity of
/// every MCP cell checked against its web twin on the side.
struct Parity {
    inner: Box<dyn Channel>,
    reference: fstp_api_testkit::reference::authz::AuthzReference,
    failures: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl Channel for Parity {
    fn name(&self) -> &'static str {
        "mcp-parity"
    }

    fn observe(&mut self, cell: &Cell) -> Result<Observed, ChannelFault> {
        let got = self.inner.observe(cell)?;
        let tool = fstp_access::op(cell.op).and_then(|o| o.tool).is_some();
        if matches!(cell.session.channel, Via::Mcp { .. }) && tool {
            let twin = web_twin(cell);
            let web = self.inner.observe(&twin)?;
            if let Some(e) = self.reference.expected(cell)
                && let Err(why) = parity(e, &web, &got)
            {
                let mut f = self
                    .failures
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if f.len() < 40 {
                    f.push(format!(
                        "{} {:?} {:?} {:?} {:?}: {why}",
                        cell.op, cell.who, cell.state, cell.session, cell.policy
                    ));
                } else {
                    f.push(String::new());
                }
            }
        }
        Ok(got)
    }
}

/// I-84, T-AUTHZ-MATRIX, H-01: for every tool cell, the MCP outcome equals
/// `channel_policy` applied to the web outcome, and every cell of the MCP
/// channel equals the reference both ways. The MCP cells run through the
/// MCP JSON-RPC handler of `fstp-mcp`, never through dispatch alone.
#[test]
fn i84_t_authz_matrix_mcp_equals_channel_policy_of_web() {
    let m = matrix::matrix().unwrap_or_else(|e| panic!("{e}"));
    assert!(
        m.missing_from_ops().is_empty() && m.unknown_to_reference().is_empty(),
        "the matrix does not cover OPS: missing {:?}, unknown {:?}",
        m.missing_from_ops(),
        m.unknown_to_reference()
    );
    let failures = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let shared = std::sync::Arc::clone(&failures);
    let make = move || -> Result<Box<dyn Channel>, fstp_api_testkit::NotImplemented> {
        let reference = fstp_api_testkit::reference::authz::authz_reference()?;
        Ok(Box::new(Parity {
            inner: matrix::mcp_channel()?,
            reference,
            failures: std::sync::Arc::clone(&shared),
        }))
    };
    let shard = matrix::Shard::from_env().unwrap_or_else(|e| panic!("{e}"));
    let c = matrix::compare_grouped(&m, &make, matrix::threads_from_env(), shard)
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        c.clean(),
        "MCP channel against the reference: {}",
        c.report()
    );
    let f = failures
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        f.is_empty(),
        "{} MCP cells break parity with their web twin:\n{}",
        f.len(),
        f.join("\n")
    );
}

/// I-84: the parity rule itself. A channel denial must match the
/// reference's class, `Prepare` admits a pending action or the web's own
/// guard refusal, and `Execute` admits the web outcome only. Green now.
#[test]
fn i84_parity_rule_self_test() {
    let done = Observed::Completed;
    let guard = Observed::Refused(Some("I-07".to_owned()));
    let other = Observed::Refused(Some("I-03".to_owned()));
    let ne = Observed::ChannelDenied(Denial::NotExposed);
    assert!(parity(Expected::Deny(AuthClass::NotExposed), &done, &ne).is_ok());
    assert!(parity(Expected::Deny(AuthClass::NotExposed), &done, &done).is_err());
    assert!(parity(Expected::Deny(AuthClass::Scope), &done, &ne).is_err());
    assert!(parity(Expected::Pending, &done, &Observed::Pending).is_ok());
    assert!(parity(Expected::Pending, &guard, &guard).is_ok());
    assert!(parity(Expected::Pending, &done, &done).is_err());
    assert!(parity(Expected::Allow, &done, &done).is_ok());
    assert!(parity(Expected::Allow, &guard, &other).is_err());
    assert!(parity(Expected::Allow, &done, &Observed::Pending).is_err());
    assert!(parity(Expected::Deny(AuthClass::Actor), &other, &other).is_ok());
}
