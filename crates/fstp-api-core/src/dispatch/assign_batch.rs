//! `review.assign_batch` (Q38, decided by Daniel on 2026-11-22: "Step-up,
//! batched"; ADR-008).
//!
//! The FSTP coordinator assigns and unassigns many reviewers of one
//! proposal in one request, confirmed with one step-up:
//!
//! - Each item is built exactly as `review.assign` or `review.unassign`
//!   builds its single command, from the same request form, so every item
//!   meets every rule a single command meets (I-03, I-06, SoD, P-11).
//! - The engine's `AssignmentBatch` decides the commands in order in one
//!   entry. One bad item refuses the whole batch with that item's rule,
//!   and nothing is recorded.
//! - The batch is high-risk (I-78): one step-up binds the digest of the
//!   whole request, and the gate consumes it once, so a step-up covers
//!   exactly one batch. The operation has no tool, so no agent completes
//!   it (I-85).

use std::collections::BTreeMap;

use fstp_domain::command::Via;
use fstp_domain::id::{AssignmentId, CommandId};
use fstp_engine::{AssignmentBatch, Command, MAX_ASSIGNMENT_BATCH};
use fstp_json::{Object, Value};

use super::{
    Call, Outcome, Seams, build, check_target, dry_run, exec_failed, executed, proposal_param,
    step_up,
};
use crate::port::{AsyncEngine, ExecMeta, OpName};
use crate::{ApiError, ErrorCode, Op, OpResult, ReadModel, forms};

/// The members of one assignment item: the reviewer and the kind, as
/// `review.assign` takes them.
const ASSIGN_MEMBERS: [&str; 2] = ["kind", "reviewer"];

/// The item list `key` of the request, or `None` when it is not a list
/// of objects.
fn items<'a>(request: &'a Object, key: &str) -> Option<Vec<&'a Object>> {
    request
        .get(key)?
        .as_array()?
        .iter()
        .map(Value::as_object)
        .collect()
}

/// `review.assign_batch` (module documentation).
pub(super) async fn command<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    verdict: fstp_access::ChannelVerdict,
) -> Result<OpResult, ApiError> {
    let Some(account) = call.account() else {
        return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
    };
    if verdict == fstp_access::ChannelVerdict::Prepare {
        // No tool exists, so no agent prepares a batch (I-85).
        return Err(call.refuse(ApiError::refused(ErrorCode::Refused, "I-85")));
    }
    let p = proposal_param(call, op)?;
    if !check_target(&call.state, &op.request) {
        return Err(call.refuse(ApiError::refused(ErrorCode::NotFound, "Input")));
    }
    let bad = || call.refuse(ApiError::bad_request(forms::REQUEST_RULE));
    let assigns = items(&op.request, "assign").ok_or_else(bad)?;
    let unassigns = items(&op.request, "unassign").ok_or_else(bad)?;
    let total = assigns.len().saturating_add(unassigns.len());
    if total == 0 || total > MAX_ASSIGNMENT_BATCH {
        return Err(bad());
    }
    let (Some(assign_spec), Some(unassign_spec)) = (
        fstp_access::op("review.assign"),
        fstp_access::op("review.unassign"),
    ) else {
        return Err(call.refuse(ApiError::NotImplemented("the assignment operations")));
    };
    let mut commands = Vec::with_capacity(total);
    // Unassignments first: a batch that replaces a reviewer frees the
    // slot before the new assignment.
    for item in &unassigns {
        if item.len() != 1 {
            return Err(bad());
        }
        let a = forms::id_param(item, "assignment").ok_or_else(bad)?;
        // Only an assignment of this proposal is in its batch.
        let mine = call
            .state
            .core
            .review()
            .get(AssignmentId::from_raw(a))
            .is_some_and(|x| x.proposal == p);
        if !mine {
            return Err(call.refuse(ApiError::refused(ErrorCode::NotFound, "Input")));
        }
        let mut request = Object::new();
        let _ = request.insert("assignment", Value::String(a.to_string()));
        commands.push(one(call, unassign_spec, request, op.from_tool)?);
    }
    for item in &assigns {
        if item.keys().any(|k| !ASSIGN_MEMBERS.contains(&k)) {
            return Err(bad());
        }
        let mut request = (*item).clone();
        let _ = request.insert("proposal", Value::String(p.raw().to_string()));
        commands.push(one(call, assign_spec, request, op.from_tool)?);
    }
    let batch = AssignmentBatch::new(commands).ok_or_else(bad)?;
    let cmd = Command::AssignmentBatch(batch);
    let command_id = CommandId::from_bytes(call.draw().map_err(|e| call.refuse(e))?.to_be_bytes());
    let ctx = call.ctx(account, &cmd, call.caller.via(), command_id);
    // Step 5: the engine judges every item; one refusal refuses all.
    dry_run(call, account, &cmd, ctx)
        .await
        .map_err(|e| call.refuse(e))?;
    // Step 7: one step-up for the whole batch (I-78, Q38).
    let proof = if call.spec.high_risk && call.caller.via() == Via::Web {
        match step_up(call, call.digest)
            .await
            .map_err(|e| call.refuse(e))?
        {
            Ok(p) => Some(p),
            Err(ask) => {
                let _ = call.audit(Outcome::Refused("I-78"), None);
                return Ok(ask);
            }
        }
    } else {
        None
    };
    let meta = ExecMeta {
        via: call.caller.via(),
        session: call.caller.session,
        agent: call.caller.agent,
        op: OpName(call.spec.name),
        request: call.digest,
        step_up: proof,
        pending: None,
        second_tenant_admin: None,
    };
    let appended = cmd.clone();
    let seq = call
        .ports
        .engine()
        .execute(cmd, ctx, meta)
        .await
        .map_err(|e| call.refuse(exec_failed(e)))?;
    executed(call, account, &appended).await;
    Ok(OpResult::Done {
        body: ReadModel::Accepted,
        seq: Some(seq),
    })
}

/// The core command of one item, built by the request form of `spec` as
/// the single operation builds it.
fn one<P: Seams>(
    call: &Call<'_, P>,
    spec: &'static fstp_access::OpSpec,
    request: Object,
    from_tool: bool,
) -> Result<fstp_domain::command::Command, ApiError> {
    // Each item draws its own ids: `build` reuses a list's ids by position.
    let mut ids = Vec::new();
    if !check_target(&call.state, &request) {
        return Err(call.refuse(ApiError::refused(ErrorCode::NotFound, "Input")));
    }
    let item = Op {
        spec,
        request,
        from_tool,
    };
    let form = forms::request_form(spec, &item.request).ok_or_else(|| {
        call.refuse(ApiError::NotImplemented(
            "an assignment operation with no request form",
        ))
    })?;
    match build(call, &form, &item, &BTreeMap::new(), &mut ids).map_err(|e| call.refuse(e))? {
        Command::Core(c) => Ok(c),
        _ => Err(call.refuse(ApiError::bad_request(forms::REQUEST_RULE))),
    }
}
