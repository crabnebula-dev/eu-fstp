//! The page gate of SA-09: whether the server may serve an `/app/` page.
//!
//! The page table is `fstp_access::PAGES`. Each row names the read the
//! page cannot render without. This module judges that read for the
//! session's principal as dispatch judges it (design section 3.7): the
//! session strength of I-77, the web channel policy, the setup gate of
//! ADR-021 and the read rule of `authorize_read`, with the same tenant
//! fold checks the read keeps beside it. So a page and its API never
//! disagree. Unlike a dispatch, it runs no read model, counts no rate
//! and writes no audit entry: nothing is read, so nothing is recorded.

use fstp_access::{Listed, OpKind, PageNeed, ReadKind, ReadOp, ReadTarget};
use fstp_domain::id::{AccountId, DecisionId, ProgrammeId};
use fstp_domain::time::Timestamp;
use fstp_engine::EngineState;
use std::sync::Arc;

use fstp_json::{Object, Value};

use super::{Caller, Seams, State, journal_of, own_assignments, read_target, resolve, tenant};
use crate::port::{AsyncEngine, Clock, PendingId};
use crate::{Credential, ErrorCode, Op, PageAdmission, RequestHead};

/// What judging one read for a page gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Admitted,
    /// The session's login method is too weak (I-77).
    Weak,
    Refused,
}

/// Judges the page at `path` for `cred` (module documentation).
pub(crate) async fn admit<P: Seams>(
    ports: &P,
    st: &State,
    cred: &Credential,
    head: &RequestHead,
    path: &str,
) -> PageAdmission {
    let Some((row, params)) = fstp_access::page_of(path) else {
        return PageAdmission::NotFound;
    };
    if row.need == PageNeed::Anyone {
        return PageAdmission::Open;
    }
    let now = ports.clock().now();
    let state = ports.engine().snapshot();
    let caller = match resolve(ports, cred, head, false, &state, now).await {
        Ok(c) => c,
        Err(crate::ApiError::Refused {
            code: ErrorCode::Unavailable,
            ..
        }) => return PageAdmission::Unavailable,
        Err(_) => return PageAdmission::SignIn,
    };
    // SA-09 rule 2: a visitor with no session signs in, unless the page's
    // read admits anyone (the open calls and their Guides).
    let account = caller.p.account();
    let reads = match row.need {
        PageNeed::Anyone => return PageAdmission::Open,
        PageNeed::Account if account.is_some() => return PageAdmission::Open,
        PageNeed::Account => return PageAdmission::SignIn,
        PageNeed::Reads(r) => r,
    };
    let mut weak = false;
    for name in reads {
        let Some(op) = page_op(name, &params) else {
            continue;
        };
        match judge(ports, st, &caller, &state, now, &op) {
            Verdict::Admitted => {
                let listed = match (row.listed, account) {
                    (None, _) => true,
                    (Some(_), None) => false,
                    // I-85: a pending action page lists the caller's own
                    // actions, read from the cell's store (ADR-026).
                    (Some((param, Listed::PendingAction)), Some(a)) => {
                        pending_listed(ports, st, a, now, &params, param).await
                    }
                    (Some((param, how)), Some(a)) => lists(&state, a, &params, param, how),
                };
                return if listed {
                    PageAdmission::Open
                } else {
                    PageAdmission::NotFound
                };
            }
            Verdict::Weak => weak = true,
            Verdict::Refused => {}
        }
    }
    if account.is_none() {
        PageAdmission::SignIn
    } else if weak {
        PageAdmission::PasskeySignIn
    } else {
        PageAdmission::NotFound
    }
}

/// The read `name` with its path parameters from the page's `params`,
/// checked as the route decoder checks a request. `None` when the read
/// is not a page read or a value does not pass.
fn page_op(name: &str, params: &[(&'static str, String)]) -> Option<Op> {
    let spec = fstp_access::page_read(name)?;
    let mut request = Object::new();
    for p in fstp_access::read_params(spec) {
        let (_, v) = params.iter().find(|(n, _)| *n == p)?;
        let _ = request.insert(p, Value::String(v.clone()));
    }
    crate::decode::finish(spec, request, false).ok()
}

/// Steps 2 and 3 of design section 3.7 and the read rule, for one read
/// on the web channel.
fn judge<P: Seams>(
    ports: &P,
    st: &State,
    caller: &Caller,
    state: &Arc<EngineState>,
    now: Timestamp,
    op: &Op,
) -> Verdict {
    let spec = op.spec;
    if !fstp_access::session_admits(spec, &caller.p) {
        return Verdict::Weak;
    }
    let settings = tenant::mcp_settings(ports, state);
    let verdict = fstp_access::channel_policy(
        spec,
        &caller.p,
        fstp_domain::policy::McpBindingActions::DraftOnly,
        &settings,
    );
    if !matches!(verdict, fstp_access::ChannelVerdict::Execute) {
        return Verdict::Refused;
    }
    if !fstp_access::setup_admits(spec, &caller.p) && !tenant::organisation_active(ports, state) {
        return Verdict::Refused;
    }
    let OpKind::Read(kind) = spec.kind else {
        return Verdict::Refused;
    };
    if read_admits(ports, st, caller, state, now, op, kind) {
        Verdict::Admitted
    } else {
        Verdict::Refused
    }
}

/// The read rule of `read` in `dispatch.rs`, without the read model: the
/// tenant fold checks of the funder reports beside `authorize_read`, and
/// the round of a cut-off round resolved through the journal.
fn read_admits<P: Seams>(
    ports: &P,
    st: &State,
    caller: &Caller,
    state: &Arc<EngineState>,
    now: Timestamp,
    op: &Op,
    kind: ReadKind,
) -> bool {
    let authorize = |target: ReadTarget| {
        fstp_access::authorize_read(&ReadOp { kind, target }, &caller.p, state, now).is_ok()
    };
    let signatory = || {
        caller
            .p
            .account()
            .is_some_and(|a| fstp_engine::report::financial_signatory(state, a))
    };
    let programme = || {
        crate::forms::id_param(&op.request, "programme")
            .map(|p| ReadTarget::Programme(ProgrammeId::from_raw(p)))
    };
    match kind {
        ReadKind::ListReports => {
            let Some(target) = programme() else {
                return false;
            };
            signatory() || authorize(target)
        }
        // Daniel, 2026-11-15 (late): both tenant-wide signatories read the
        // funder profile, as `grant::funder_profile` judges it.
        ReadKind::GetFunderProfile => {
            let Some(target) = programme() else {
                return false;
            };
            // The read answers not found for a programme with no head
            // policy, whoever asks, so the page is closed there too.
            let ReadTarget::Programme(p) = target else {
                return false;
            };
            if fstp_engine::report::pinned_p53(state, fstp_report::Scope::Programme(p)).is_none() {
                return false;
            }
            let tenant_signatory = caller
                .p
                .account()
                .is_some_and(|a| fstp_engine::report::tenant_signatory(state, a));
            tenant_signatory || authorize(target)
        }
        ReadKind::ListReportProgrammes => signatory() || authorize(ReadTarget::None),
        ReadKind::GetCutOffRound => {
            let Some(r) = crate::forms::id_param(&op.request, "round") else {
                return false;
            };
            let known = journal_of(ports, st)
                .round(DecisionId::from_raw(r))
                .map(|x| x.call);
            match known {
                Some(c) => authorize(ReadTarget::Call(c)),
                None => false,
            }
        }
        _ => {
            let target = read_target(op);
            let Ok(clearance) =
                fstp_access::authorize_read(&ReadOp { kind, target }, &caller.p, state, now)
            else {
                return false;
            };
            body_admits(ports, st, caller, state, now, op, kind, clearance.rule())
        }
    }
}

/// Whether the pending action named by `param` is one of `account`'s
/// listed actions (I-85).
async fn pending_listed<P: Seams>(
    ports: &P,
    st: &State,
    account: AccountId,
    now: Timestamp,
    params: &[(&'static str, String)],
    param: &str,
) -> bool {
    let Some(want) = params
        .iter()
        .find(|(n, _)| *n == param)
        .and_then(|(_, v)| v.parse::<u128>().ok())
    else {
        return false;
    };
    super::pendings(ports, st)
        .list(account, now)
        .await
        .is_ok_and(|l| l.iter().any(|p| p.id == PendingId::from_raw(want)))
}

/// Whether the page id `param` is one the page's read lists for
/// `account` ([`Listed`]).
fn lists(
    state: &EngineState,
    account: AccountId,
    params: &[(&'static str, String)],
    param: &str,
    how: Listed,
) -> bool {
    let id = |name: &str| {
        params
            .iter()
            .find(|(n, _)| *n == name)
            .and_then(|(_, v)| v.parse::<u128>().ok())
    };
    let Some(want) = id(param) else {
        return false;
    };
    match how {
        Listed::ReviewerAssignment => own_assignments(state, account)
            .iter()
            .any(|a| a.assignment.raw() == want),
        Listed::IrcAssignment => own_assignments(state, account)
            .iter()
            .any(|a| a.kind == "irc" && a.assignment.raw() == want),
        Listed::PaymentRequest => {
            let Some(grant) = id("proposal") else {
                return false;
            };
            state
                .core
                .payments()
                .summaries()
                .any(|s| s.grant.raw() == grant && s.request.raw() == want)
        }
        // Judged by `pending_listed`, which reads the store.
        Listed::PendingAction => false,
    }
}

/// The refusals a read's model raises beside `authorize_read`, judged
/// without running the model: a creator read needs the programme's
/// draft, the intake queue a published call, and the voyager reads the
/// route visibility of section 10 (I-21, I-93), which their own pure
/// functions judge on a call that writes no audit entry.
#[allow(
    clippy::too_many_arguments,
    reason = "the parts of one call the gate holds"
)]
fn body_admits<P: Seams>(
    ports: &P,
    st: &State,
    caller: &Caller,
    state: &Arc<EngineState>,
    now: Timestamp,
    op: &Op,
    kind: ReadKind,
    rule: fstp_access::ReadRule,
) -> bool {
    let id = |name: &str| crate::forms::id_param(&op.request, name);
    match kind {
        ReadKind::GetDraft
        | ReadKind::GetReport
        | ReadKind::GetPreview
        | ReadKind::ListInvitations
        | ReadKind::ListImportProposals => {
            id("programme").is_some_and(|p| state.creator.draft(ProgrammeId::from_raw(p)).is_some())
        }
        // SA-11: the team page of a programme that exists, as a draft or
        // an active programme.
        ReadKind::ListTeam => id("programme").map(ProgrammeId::from_raw).is_some_and(|p| {
            state.creator.draft(p).is_some() || state.core.policy().programme(p).is_some()
        }),
        ReadKind::GetIntakeQueue => id("call").is_some_and(|c| {
            state
                .core
                .calls()
                .get(fstp_domain::id::CallId::from_raw(c))
                .and_then(|v| v.frozen())
                .is_some()
        }),
        ReadKind::GetJourney | ReadKind::GetDiary => {
            let Some(p) = id("proposal").map(fstp_domain::id::ProposalId::from_raw) else {
                return false;
            };
            let call = super::Call {
                ports,
                st,
                caller: Caller {
                    p: caller.p.clone(),
                    session: caller.session,
                    agent: caller.agent,
                    token: caller.token,
                },
                spec: op.spec,
                digest: super::uncanonical_digest(),
                now,
                state: Arc::clone(state),
                quiet: true,
                peer: crate::PeerKey::shared(),
            };
            if kind == ReadKind::GetJourney {
                super::journey::journey(&call, p, rule).is_ok()
            } else {
                super::journey::diary(&call, p, rule).is_ok()
            }
        }
        _ => true,
    }
}
