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
//!   high-risk. A public research tool has no page under `/p`, so its
//!   twin is the same operation through the API core as the web would
//!   dispatch it, with no tool and no credential (the harness's
//!   `research_twin`). A channel denial must match exactly. `Prepare`
//!   must give a pending action, or the same guard refusal the web gives.
//!   `Execute` must give exactly the web outcome, the refusal rule
//!   included.
//!
//! Status: red. `matrix::mcp_channel` refuses until the harness gives it
//! a transport through `fstp_mcp::McpServer` (a harness seam).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_api_testkit::matrix::{self, Cell, Channel, ChannelFault, Denial, Observed};
use fstp_api_testkit::reference::authz::{
    AuthClass, AuthzReference, Channel as Via, Expected, Login, Session, StepUp,
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

/// M4 design change D6 (TH-62): with P-75 off, a content reader outside
/// the applicant team is refused through MCP only. The domain's read check
/// refuses it, not `channel_policy`, so the web twin of the cell may
/// complete. An MCP refusal under P-75 keeps parity only when P-75 is off
/// and the reference allows the same cell with P-75 on. P-75 is then the
/// only difference between the channels (CI run 43853477946).
fn p75_alone(reference: &AuthzReference, cell: &Cell, mcp: &Observed) -> bool {
    if cell.policy.p75_on || *mcp != Observed::Refused(Some("P-75".to_owned())) {
        return false;
    }
    let mut on = *cell;
    on.policy.p75_on = true;
    reference.expected(&on) == Some(Expected::Allow)
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
                && !p75_alone(&self.reference, cell, &got)
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
    // `FSTP_MATRIX_OPS` narrows a local run to some operations, as the
    // direct and HTTP matrices do (lane m4/coordinator-unmask).
    let ops = matrix::OpFilter::from_env().unwrap_or_else(|e| panic!("{e}"));
    let m = m.narrowed(&ops).unwrap_or_else(|e| panic!("{e}"));
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

/// I-84, R-MC-04, I-87: the focused reproduction of CI run 43773491368,
/// where the MCP cells of the public research tools broke parity. These
/// three tools have no page under `/p` (M4 design section 3.10,
/// "Routes"), so the matrix gives them MCP cells only. Their web twin is
/// the same operation through the API core as the web decodes and
/// dispatches it, with no tool and the credential the `/p` router passes,
/// none. Every MCP cell must give exactly that outcome. The run takes the
/// first policy row of each state, and is not vacuous: some cells
/// complete and some are refused.
#[test]
fn i84_r_mc_04_public_research_tools_keep_parity_with_their_web_twin() {
    let filter =
        matrix::OpFilter::parse("public.deadlines,public.eligibility,public.list_open_calls")
            .unwrap();
    let m = matrix::matrix().unwrap().narrowed(&filter).unwrap();
    let mut states = Vec::new();
    let groups: Vec<_> = m
        .groups()
        .into_iter()
        .filter(|(s, _)| {
            let first = !states.contains(s);
            states.push(*s);
            first
        })
        .collect();
    let failures = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut channel = Parity {
        inner: matrix::mcp_channel().unwrap(),
        reference: fstp_api_testkit::reference::authz::authz_reference().unwrap(),
        failures: std::sync::Arc::clone(&failures),
    };
    let (mut completed, mut other) = (0usize, 0usize);
    for (state, policy) in groups {
        for cell in m.group_cells(state, policy) {
            assert!(matches!(cell.session.channel, Via::Mcp { .. }), "{cell:?}");
            match channel.observe(&cell).unwrap() {
                Observed::Completed => completed += 1,
                _ => other += 1,
            }
        }
    }
    assert!(
        completed > 0 && other > 0,
        "{completed} completed, {other} other"
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

/// I-84, M4 design change D6, TH-62: the focused reproduction of CI run
/// 43853477946, where the MCP cells of `review.read_content` broke parity
/// with P-75 off. For each state, the run takes the first policy row with
/// P-75 off and the first with P-75 on. With P-75 off, a reviewer's agent
/// is refused under P-75 while the web twin reads. With P-75 on, the MCP
/// outcome is the web outcome. It is not vacuous: some cells are refused
/// under P-75, and some complete.
#[test]
fn i84_d6_p75_off_refuses_content_through_mcp_only() {
    let filter = matrix::OpFilter::parse("review.read_content").unwrap();
    let m = matrix::matrix().unwrap().narrowed(&filter).unwrap();
    let mut seen = Vec::new();
    let groups: Vec<_> = m
        .groups()
        .into_iter()
        .filter(|(s, p)| {
            let first = !seen.contains(&(*s, p.p75_on));
            seen.push((*s, p.p75_on));
            first
        })
        .collect();
    let failures = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut channel = Parity {
        inner: matrix::mcp_channel().unwrap(),
        reference: fstp_api_testkit::reference::authz::authz_reference().unwrap(),
        failures: std::sync::Arc::clone(&failures),
    };
    let p75 = Observed::Refused(Some("P-75".to_owned()));
    let (mut refused, mut completed) = (0usize, 0usize);
    for (state, policy) in groups {
        for cell in m.group_cells(state, policy) {
            if !matches!(cell.session.channel, Via::Mcp { .. }) {
                continue;
            }
            let got = channel.observe(&cell).unwrap();
            if got == p75 {
                assert!(
                    !policy.p75_on,
                    "refused under P-75 while it is on: {cell:?}"
                );
                refused += 1;
            } else if got == Observed::Completed {
                completed += 1;
            }
        }
    }
    assert!(
        refused > 0 && completed > 0,
        "{refused} refused under P-75, {completed} completed"
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
