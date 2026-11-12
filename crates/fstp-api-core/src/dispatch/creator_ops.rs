//! Dispatch of the creator, bridge and import operations, and the
//! creator read models (M4 design sections 2.2 J1, 3.2, 3.3 and 3.7;
//! lane m4wire).
//!
//! A command runs through the steps of design section 3.7, as a core
//! command does in the parent module: the strict form (`creator.rs`), the
//! dry run with web semantics and its vault answers recorded, the step-up
//! of a high-risk operation through the web, then the execution. A
//! refused dry run returns before any step-up prompt, so a builder's
//! approval is refused with I-67 before a ceremony starts.
//!
//! Free text and uploads are stored only once the call is about to
//! execute, so a refused call stores nothing: the invitation's email in
//! the text store and the uploaded document in the blob store.
//!
//! The reads take their shell facts from the engine port's
//! `AsyncEngine::creator_inputs`, the facts its `CreatorEnvironment`
//! gives a decision. The parts the engine owns are replaced here as the
//! engine replaces them: the count of unresolved imports from the import
//! store, and the builders' `IsVerified` answers from the vault, each
//! recorded as a query digest and its bit (`overview.md` NOTE 5).
//!
//! # Interim readings, pending Daniel (design section 15.0)
//!
//! - A request for activation is refused with I-66 unless the report the
//!   requester would see is clean: no failure, and every warning
//!   acknowledged at a live revision. The creator records the request
//!   whatever the report holds. The shell refuses it first, as the
//!   creator review page promises ("the server decides again at the
//!   request and at the approval").
//! - The salt of an invitation contact's digest and of an upload's text
//!   digest is drawn per text and stored inside the stored bytes, before
//!   the text (`salted.rs`, ADR-007). The digest is HMAC-SHA256 under
//!   the salt, so it checks against the stored text, and no one can
//!   confirm a guessed text from it once the text is erased.
//! - The approval inbox lists one activation row per draft with a live
//!   request, at the draft's head revision, which the approval must
//!   name. A tenant admin outside the builder set may approve it (I-67).
//!   No port lists the pending self-grant approvals yet, so the reply
//!   names them as `unlisted` (`creator.rs`, `UNLISTED_APPROVALS`), and
//!   the inbox says so instead of reading as complete.
//! - `creator.invite` draws a 32-byte link token through `fstp-crypto`.
//!   The invitation id is the token's labelled digest
//!   (`creator::link_invitation`), so the ledger never holds the token.
//!   Once the invitation is appended, the token and the email go to M3
//!   through the accounts port, and to no one else (J2, I-86, ADR-007,
//!   lane inv).
//! - An invitation reads `granted` once the core holds a binding of its
//!   account in its role on the programme, `verified` once the vault
//!   verifies the account that accepted it, and `accepted` before that.
//!
//! # Seams, each failing closed
//!
//! - `creator.get_draft` reads the draft spec and its pending template
//!   narratives through `fstp_creator::draft_view`, so this crate needs
//!   no edge to `fstp-programme`. A saved value the engine does not hold
//!   reads as a gap there, never as a made-up value.
//! - `creator.preview` answers the Guide and the public page previews
//!   from `fstp-guide` and `fstp-public`. The contract placeholder
//!   preview stays a seam until a contract renderer exists (M8).
//! - `creator.impact` lists the calls a change reaches, through
//!   `fstp_creator::affected_calls` over `fstp_programme::impact`
//!   (R-PG-04). A draft has no call (change D3), so its list is empty.

use std::collections::{BTreeMap, BTreeSet};

use fstp_creator::{AckSet, CreatorCommand, Invitee};
use fstp_domain::id::{ContentDigest, TextId};
use fstp_import::{BlobAddress, ProgrammeRef, TextDigest};

use super::*;
use crate::creator::{
    ApprovalRow, CreatorModel, Form, ImpactRow, InvitationRow, ProposalView, Supplied,
};
use crate::port::{BlobOwner, BlobStore};

/// The refusal of a draft the state does not hold.
fn no_draft() -> ApiError {
    ApiError::refused(ErrorCode::NotFound, "Input")
}

/// The `programme` path parameter.
fn programme_param<P: Seams>(call: &Call<'_, P>, op: &Op) -> Result<ProgrammeId, ApiError> {
    forms::id_param(&op.request, "programme")
        .map(ProgrammeId::from_raw)
        .ok_or_else(|| call.refuse(ApiError::bad_request(forms::REQUEST_RULE)))
}

/// The template P-09 wording that `op` accepts, when `op` is
/// `creator.accept_narrative` of P-09 and the wording waits (Daniel's
/// answer of 2026-11-07, M4 design section 15.0).
fn pending_wording<P: Seams>(
    call: &Call<'_, P>,
    form: Form,
    op: &Op,
) -> Option<fstp_creator::PendingWording> {
    if form != Form::AcceptNarrative {
        return None;
    }
    let p = ProgrammeId::from_raw(forms::id_param(&op.request, "programme")?);
    let w = fstp_creator::pending_wording(&call.state.creator, p)?;
    (op.request.get("field").and_then(Value::as_str) == Some(w.field_key().as_str())).then_some(w)
}

/// The `SaveFields` that accepts the template P-09 wording `w`, with each
/// text named by `refs`. The dry run names each text by a stand-in
/// reference, since a refused call stores nothing.
fn accept_wording(
    w: &fstp_creator::PendingWording,
    op: &Op,
    refs: Option<&[TextRef]>,
) -> Result<Command, ApiError> {
    let stand_in: Vec<TextRef>;
    let refs = match refs {
        Some(r) => r,
        None => {
            stand_in = w
                .texts()
                .iter()
                .zip(1_u128..)
                .map(|(t, i)| forms::text_ref(i, t))
                .collect();
            &stand_in
        }
    };
    let edit = w
        .accept(refs, fstp_crypto::sha256)
        .ok_or(ApiError::bad_request(forms::REQUEST_RULE))?;
    let programme = forms::id_param(&op.request, "programme")
        .map(ProgrammeId::from_raw)
        .ok_or(ApiError::bad_request(forms::REQUEST_RULE))?;
    Ok(Command::Creator(CreatorCommand::SaveFields {
        programme,
        base: crate::creator::revision_at(&op.request, "base")?,
        fields: vec![edit],
    }))
}

/// Builds the command of `op`. `ids` replays the ids an earlier build
/// drew, and records each new draw, as the parent's `build` does. The
/// acceptance of template P-09 wording builds the `SaveFields` of
/// [`accept_wording`], with `wording` once its texts are stored.
fn build<P: Seams>(
    call: &Call<'_, P>,
    form: Form,
    op: &Op,
    supplied: &Supplied,
    wording: Option<&[TextRef]>,
    ids: &mut Vec<u128>,
) -> Result<Command, ApiError> {
    if let Some(w) = pending_wording(call, form, op) {
        return accept_wording(&w, op, wording);
    }
    let mut next = 0usize;
    let mut draw = || -> Result<u128, ApiError> {
        let id = match ids.get(next) {
            Some(id) => *id,
            None => {
                let id = call.draw()?;
                ids.push(id);
                id
            }
        };
        next = next.saturating_add(1);
        Ok(id)
    };
    let cmd = crate::creator::build(form, &op.request, supplied, &mut draw)?;
    store_manual_wording(cmd, wording)
}

/// The P-09 wording a person typed into `creator.save_fields`, from the
/// command the strict form built (lane m4/fast-flow).
fn typed_wording(cmd: &Command) -> Option<fstp_creator::PendingWording> {
    match cmd {
        Command::Creator(CreatorCommand::SaveFields { fields, .. }) => {
            fields.iter().find_map(fstp_creator::manual_wording)
        }
        _ => None,
    }
}

/// `cmd` with typed P-09 wording named by stored texts: `refs` once the
/// texts are stored, else a stand-in reference per text for the dry run,
/// as [`accept_wording`] does (ADR-007, Daniel's answer of 2026-11-07).
/// Any other command is returned as it is.
fn store_manual_wording(cmd: Command, refs: Option<&[TextRef]>) -> Result<Command, ApiError> {
    let Command::Creator(CreatorCommand::SaveFields {
        programme,
        base,
        mut fields,
    }) = cmd
    else {
        return Ok(cmd);
    };
    for f in &mut fields {
        let Some(w) = fstp_creator::manual_wording(f) else {
            continue;
        };
        let stand_in: Vec<TextRef>;
        let named = match refs {
            Some(r) => r,
            None => {
                stand_in = w
                    .texts()
                    .iter()
                    .zip(1_u128..)
                    .map(|(t, i)| forms::text_ref(i, t))
                    .collect();
                &stand_in
            }
        };
        *f = w
            .accept(named, fstp_crypto::sha256)
            .ok_or(ApiError::bad_request(forms::REQUEST_RULE))?;
    }
    Ok(Command::Creator(CreatorCommand::SaveFields {
        programme,
        base,
        fields,
    }))
}

/// What the execution stores before it runs: the stored values, and the
/// upload's normalised text, which this core remembers once the command
/// appends.
struct Stored {
    supplied: Supplied,
    text: Option<fstp_import::ExtractedText>,
    /// The stored texts of accepted P-09 wording, in criterion order.
    wording: Option<Vec<TextRef>>,
}

/// Step 8, before the execution: stores the invitation's email in the
/// text store and the uploaded document in the blob store.
async fn store<P: Seams>(
    call: &Call<'_, P>,
    form: Form,
    op: &Op,
    account: AccountId,
) -> Result<Stored, ApiError> {
    let mut supplied = Supplied::placeholder(account);
    let mut text = None;
    // Daniel's answer of 2026-11-07: each text of accepted P-09 wording
    // is stored as a public text (ADR-007), and the save names it by
    // reference.
    if let Some(w) = pending_wording(call, form, op) {
        let p = forms::id_param(&op.request, "programme")
            .map(ProgrammeId::from_raw)
            .ok_or(ApiError::bad_request(forms::REQUEST_RULE))?;
        let mut refs = Vec::new();
        for s in w.texts() {
            let r = call
                .ports
                .texts()
                .put(TextClass::Public, TextOwner::Programme(p), s.as_bytes())
                .await
                .map_err(|e| port_failed(e, "text"))?;
            let r = forms::text_ref(r.0, &s);
            lock(&call.st.content).remember(r, &s);
            refs.push(r);
        }
        return Ok(Stored {
            supplied,
            text,
            wording: Some(refs),
        });
    }
    // Lane m4/fast-flow: P-09 wording typed into a save is stored the same
    // way, each text as a public text of the programme (ADR-007).
    if form == Form::SaveFields {
        let mut no_ids =
            || -> Result<u128, ApiError> { Err(ApiError::bad_request(forms::REQUEST_RULE)) };
        let typed = crate::creator::build(form, &op.request, &supplied, &mut no_ids)
            .ok()
            .and_then(|c| typed_wording(&c));
        if let Some(w) = typed {
            let p = forms::id_param(&op.request, "programme")
                .map(ProgrammeId::from_raw)
                .ok_or(ApiError::bad_request(forms::REQUEST_RULE))?;
            let mut refs = Vec::new();
            for s in w.texts() {
                let r = call
                    .ports
                    .texts()
                    .put(TextClass::Public, TextOwner::Programme(p), s.as_bytes())
                    .await
                    .map_err(|e| port_failed(e, "text"))?;
                let r = forms::text_ref(r.0, &s);
                lock(&call.st.content).remember(r, &s);
                refs.push(r);
            }
            return Ok(Stored {
                supplied,
                text,
                wording: Some(refs),
            });
        }
    }
    match form {
        Form::Invite => {
            let p = forms::id_param(&op.request, "programme")
                .map(ProgrammeId::from_raw)
                .ok_or(ApiError::bad_request(forms::REQUEST_RULE))?;
            let email = op
                .request
                .get("email")
                .and_then(Value::as_str)
                .ok_or(ApiError::bad_request(forms::REQUEST_RULE))?;
            // ADR-007: the contact's digest is keyed with a salt stored
            // inside the text and erased with it (`salted.rs`), so the
            // ledger cannot confirm a guessed address after erasure.
            let salt = crate::salted::draw()?;
            let r = call
                .ports
                .texts()
                .put(
                    TextClass::Confidential,
                    TextOwner::Programme(p),
                    &crate::salted::stored(&salt, email.as_bytes()),
                )
                .await
                .map_err(|e| port_failed(e, "text"))?;
            let r = TextRef::new(
                TextId::from_raw(r.0),
                ContentDigest::from_bytes(crate::salted::digest(&salt, email.as_bytes())),
            );
            lock(&call.st.content).remember(r, email);
            supplied.contact = Some(r);
        }
        Form::Upload => {
            let p = forms::id_param(&op.request, "programme")
                .map(ProgrammeId::from_raw)
                .ok_or(ApiError::bad_request(forms::REQUEST_RULE))?;
            let raw = op
                .request
                .get("text")
                .and_then(Value::as_str)
                .ok_or(ApiError::bad_request(forms::REQUEST_RULE))?;
            let extracted = crate::creator::extracted(&op.request)?;
            // ADR-007: the salt of the text digest is stored inside the
            // blob, before the uploaded bytes, and erased with them
            // (`salted.rs`). The digest is over the normalised text.
            let salt = crate::salted::draw()?;
            let blob = call
                .ports
                .blobs()
                .put(
                    BlobOwner::Programme(p),
                    &crate::salted::stored(&salt, raw.as_bytes()),
                )
                .await
                .map_err(|e| port_failed(e, "blob"))?;
            let digest = crate::salted::digest(&salt, extracted.untrusted().as_data().as_bytes());
            supplied.upload = Some((
                BlobAddress::from_bytes(blob.0),
                TextDigest::from_bytes(digest),
            ));
            text = Some(extracted);
        }
        _ => {}
    }
    Ok(Stored {
        supplied,
        text,
        wording: None,
    })
}

/// A creator, bridge or import command: steps 5 to 9 of design section
/// 3.7.
pub(super) async fn command<P: Seams>(call: &Call<'_, P>, op: &Op) -> Result<OpResult, ApiError> {
    let Some(account) = call.account() else {
        return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
    };
    let Some(form) = crate::creator::form_of(call.spec) else {
        return Err(call.refuse(ApiError::NotImplemented(
            "an import operation that only the system issues",
        )));
    };
    // J2, ADR-007: the link token of an invitation is drawn once, so the
    // dry run and the execution name the invitation its digest names.
    let link = if form == Form::Invite {
        Some(
            fstp_crypto::random_array::<32>()
                .map_err(|_| call.refuse(ApiError::refused(ErrorCode::Unavailable, "ids")))?,
        )
    } else {
        None
    };
    let mut ids = Vec::new();
    let placeholder = Supplied {
        link,
        ..Supplied::placeholder(account)
    };
    let cmd = build(call, form, op, &placeholder, None, &mut ids).map_err(|e| call.refuse(e))?;
    let command_id = CommandId::from_bytes(call.draw().map_err(|e| call.refuse(e))?.to_be_bytes());
    let ctx = call.ctx(account, &cmd, call.caller.via(), command_id);
    // Step 5.
    dry_run(call, account, &cmd, ctx)
        .await
        .map_err(|e| call.refuse(e))?;
    if let Command::Creator(CreatorCommand::RequestActivation { programme, .. }) = &cmd {
        activation_gate(call, *programme, account).await?;
    }
    // Step 7.
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
    // Step 8.
    let mut stored = store(call, form, op, account)
        .await
        .map_err(|e| call.refuse(e))?;
    stored.supplied.link = link;
    let cmd = build(
        call,
        form,
        op,
        &stored.supplied,
        stored.wording.as_deref(),
        &mut ids,
    )
    .map_err(|e| call.refuse(e))?;
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
    match call.ports.engine().execute(cmd, ctx, meta).await {
        Ok(seq) => {
            remember(call, &appended, stored.text);
            if let Some(t) = link {
                mail_invitation(call, op, &appended, t)
                    .await
                    .map_err(|e| call.refuse(e))?;
            }
            Ok(OpResult::Done {
                body: reply(&appended),
                seq: Some(seq),
            })
        }
        Err(e) => Err(call.refuse(exec_failed(e))),
    }
}

/// Hands the link token and the email of an appended invitation to M3
/// through the accounts port, which mails the link and binds the address
/// to the account that enrols (J2, I-86, ADR-007, lane inv). Nothing else
/// receives the token: the reply, the ledger and the audit log name only
/// its digest, the invitation id.
///
/// Interim, pending Daniel: the port is called once the invitation is
/// appended, so a refused call mails nothing. A port failure refuses the
/// call with the invitation recorded and no link mailed. The admin then
/// withdraws it and invites again.
async fn mail_invitation<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    cmd: &Command,
    token: [u8; 32],
) -> Result<(), ApiError> {
    let Command::Creator(CreatorCommand::Invite {
        programme,
        invitation,
        role,
        ..
    }) = cmd
    else {
        return Ok(());
    };
    let email = op
        .request
        .get("email")
        .and_then(Value::as_str)
        .ok_or(ApiError::bad_request(forms::REQUEST_RULE))?;
    let kind = crate::port::InviteKind::ProgrammeRole {
        programme: *programme,
        invitation: *invitation,
        role: *role,
        email: email.to_owned(),
        token: crate::port::LinkToken::from_bytes(token),
    };
    call.ports
        .accounts()
        .invite(kind)
        .await
        .map(|_| ())
        .map_err(|e| port_failed(e, "accounts"))
}

/// Remembers what an appended command leaves for the reads of this core.
fn remember<P: Seams>(call: &Call<'_, P>, cmd: &Command, text: Option<fstp_import::ExtractedText>) {
    match cmd {
        Command::Creator(CreatorCommand::SaveAsTenantTemplate { template, .. }) => {
            lock(&call.st.creator).saved(*template);
        }
        Command::Import(fstp_import::ImportCommand::RegisterDocument(doc)) => {
            if let Some(t) = text {
                lock(&call.st.creator).uploaded(doc.id, t);
            }
        }
        _ => {}
    }
}

/// The body of an appended command: the drawn programme of an opened
/// draft, which the creator pages open next, and `{"accepted": true}`
/// otherwise.
fn reply(cmd: &Command) -> ReadModel {
    match cmd {
        Command::Creator(CreatorCommand::OpenDraft { programme, .. }) => {
            ReadModel::Creator(CreatorModel::Opened {
                programme: *programme,
            })
        }
        _ => ReadModel::Accepted,
    }
}

/// The I-66 gate of a request for activation (module documentation).
async fn activation_gate<P: Seams>(
    call: &Call<'_, P>,
    programme: ProgrammeId,
    account: AccountId,
) -> Result<(), ApiError> {
    let i66 = || call.refuse(ApiError::refused(ErrorCode::Refused, "I-66"));
    let Some(report) = report_now(call, programme, account).await? else {
        return Err(i66());
    };
    match fstp_creator::clean(&report, &AckSet::live(&call.state.creator, programme)) {
        Ok(_) => Ok(()),
        Err(_) => Err(i66()),
    }
}

/// The validation report of `programme` now, as a decision by `viewer`
/// would see it (module documentation). `None` when the shell supplies
/// no funder profile, so no report can clear. A refusal is audited.
async fn report_now<P: Seams>(
    call: &Call<'_, P>,
    programme: ProgrammeId,
    viewer: AccountId,
) -> Result<Option<fstp_creator::ValidationReport>, ApiError> {
    let state = &call.state;
    let d = state
        .creator
        .draft(programme)
        .ok_or_else(|| call.refuse(no_draft()))?;
    let questions = fstp_creator::vault_questions(&state.creator, programme, None);
    // H-07 before the first question: the SoD previews of the shell
    // facts ask the vault about the invitees, and the builders'
    // answers follow.
    if asks_about_people(state, programme) || !questions.is_verified.is_empty() {
        vault_read_admitted(call, viewer)?;
    }
    let mut inputs = shell_inputs(call, programme, d.head(), viewer);
    inputs.unresolved_imports = state
        .import
        .unresolved(ProgrammeRef::from_raw(programme.raw()));
    let mut is_verified = BTreeMap::new();
    for a in &questions.is_verified {
        let ans = ask_vault(call, &Query::IsVerified { account: *a }).await?;
        let _ = is_verified.insert(*a, ans.holds);
    }
    inputs.vault.is_verified = is_verified;
    inputs.vault.same_identity = BTreeMap::new();
    let Some(profile) = inputs.profile.clone() else {
        return Ok(None);
    };
    Ok(Some(fstp_creator::validate(
        &state.core,
        &state.creator,
        programme,
        &profile,
        &inputs,
    )))
}

/// Whether the shell facts of a read on `programme` ask the vault about
/// people: the SoD preview of each invitation with an account. Such a
/// read is admitted under H-07 before the facts are taken.
fn asks_about_people(state: &EngineState, programme: ProgrammeId) -> bool {
    !fstp_creator::preview_targets(&state.creator, programme).is_empty()
}

/// The engine port's creator facts for a report on `programme` at
/// `head`, as a request for activation by `viewer` reads them.
fn shell_inputs<P: Seams>(
    call: &Call<'_, P>,
    programme: ProgrammeId,
    head: fstp_creator::DraftRevision,
    viewer: AccountId,
) -> fstp_creator::CreatorInputs {
    let stand_in = CreatorCommand::RequestActivation {
        programme,
        revision: head,
    };
    let cmd = Command::Creator(stand_in.clone());
    let ctx = call.ctx(viewer, &cmd, Via::Web, CommandId::from_bytes([0; 16]));
    call.ports
        .engine()
        .creator_inputs(&call.state, &stand_in, &ctx)
}

/// A creator read (module documentation). Its rule was judged by
/// `authorize_read` in the parent. A refusal is audited, and an answer
/// is audited by the parent.
pub(super) async fn read<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    kind: ReadKind,
) -> Result<CreatorModel, ApiError> {
    let Some(viewer) = call.account() else {
        return Err(call.refuse(ApiError::refused(ErrorCode::Unauthenticated, "actor")));
    };
    // I-86: the invitation list names emails, so it is served to the web
    // only, refused before it asks the vault anything.
    if kind == ReadKind::ListInvitations && call.caller.via() != Via::Web {
        return Err(call.refuse(ApiError::refused(ErrorCode::NotExposed, "I-86")));
    }
    let state = &call.state;
    match kind {
        ReadKind::ListProgrammes => Ok(CreatorModel::Programmes(programmes(state))),
        ReadKind::ListTemplates => {
            let mut out: Vec<(u128, u32, String)> = crate::creator::SHIPPED_TEMPLATES
                .iter()
                .map(|(id, v, name)| (*id, *v, (*name).to_owned()))
                .collect();
            // A tenant template this core saw saved, and the state still
            // holds, is listed at version 1 with a name made of its id.
            // Interim, pending a template listing of `CreatorState` and the
            // template spec's name (lane m4creator).
            let saved: Vec<_> = lock(&call.st.creator).templates().collect();
            for t in saved {
                if state.creator.template_taken(t) {
                    out.push((t.raw(), 1, format!("Tenant template {}", t.raw())));
                }
            }
            Ok(CreatorModel::Templates(out))
        }
        ReadKind::ListApprovals => {
            let admin = call.caller.p.tenant_admin();
            let rows = state
                .creator
                .drafts()
                .filter(|(_, d)| d.active().is_none() && d.request_live())
                .map(|(programme, d)| ApprovalRow {
                    programme,
                    revision: d.head(),
                    approvable: admin && !d.builders().contains(&viewer),
                })
                .collect();
            Ok(CreatorModel::Approvals(rows))
        }
        _ => {
            let p = programme_param(call, op)?;
            programme_read(call, op, kind, p, viewer).await
        }
    }
}

/// A read of one programme's draft.
async fn programme_read<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    kind: ReadKind,
    p: ProgrammeId,
    viewer: AccountId,
) -> Result<CreatorModel, ApiError> {
    let state = &call.state;
    if kind == ReadKind::GetImpact {
        if state.core.policy().programme(p).is_none() {
            return Err(call.refuse(no_draft()));
        }
        let calls: Vec<fstp_domain::id::CallId> = state
            .core
            .calls()
            .iter()
            .filter(|(_, v)| v.programme() == p)
            .map(|(c, _)| c)
            .collect();
        // A published call whose limits do not read fails closed: leaving
        // it out would under-report the change (R-PG-04).
        let affected = fstp_creator::affected_calls(&state.core, p, &calls)
            .map_err(|_| call.refuse(ApiError::refused(ErrorCode::Unavailable, "R-PG-04")))?;
        return Ok(CreatorModel::Impact(
            affected
                .into_iter()
                .map(|call| ImpactRow { call })
                .collect(),
        ));
    }
    let d = state
        .creator
        .draft(p)
        .ok_or_else(|| call.refuse(no_draft()))?;
    match kind {
        ReadKind::GetDraft => {
            let mut view = fstp_creator::draft_view(&state.core, &state.creator, p)
                .ok_or_else(|| call.refuse(no_draft()))?;
            view.show_wording(&wording_texts(call, &view.wording_refs()).await);
            Ok(CreatorModel::Draft {
                spec: view.spec,
                revision: d.head(),
                active: d.active().is_some(),
                pending_narratives: view.pending_narratives,
                requested: d.request_live(),
            })
        }
        ReadKind::GetPreview => preview(call, op, p, d, viewer).await,
        ReadKind::GetReport => {
            let Some(report) = report_now(call, p, viewer).await? else {
                return Err(call.refuse(ApiError::NotImplemented(
                    "the cell's funder profile source for the draft's profile",
                )));
            };
            let results =
                crate::creator::report_rows(&report, &d.live_acks()).map_err(|e| call.refuse(e))?;
            Ok(CreatorModel::Report {
                revision: report.revision(),
                results,
            })
        }
        ReadKind::ListInvitations => invitations(call, p, d, viewer).await,
        ReadKind::ListImportProposals => proposals(call, p),
        _ => {
            let _ = op;
            Err(call.refuse(ApiError::NotImplemented("this creator read")))
        }
    }
}

/// The stored texts a draft preview could read: the public texts of the
/// head policy's P-09 wording (ADR-007). Any other stored text has no
/// value, so the preview shows its marker.
struct PreviewTexts(BTreeMap<u128, String>);

impl fstp_guide::StoredTexts for PreviewTexts {
    fn text(&self, text: fstp_domain::id::TextRef) -> Option<&str> {
        self.0.get(&text.id().raw()).map(String::as_str)
    }
}

/// The stored P-09 texts of `refs` that this core or the text store holds
/// and whose digest matches (Daniel's answer of 2026-11-07). A text
/// neither holds stays a reference in the draft view.
async fn wording_texts<P: Seams>(call: &Call<'_, P>, refs: &[TextRef]) -> PreviewTexts {
    let mut texts = BTreeMap::new();
    for r in refs {
        let held = lock(&call.st.content).text(*r).map(str::to_owned);
        let text = match held {
            Some(t) => Some(t),
            None => call
                .ports
                .texts()
                .get_public(crate::port::PublicTextRef(r.id().raw()))
                .await
                .ok()
                .and_then(|b| String::from_utf8(b).ok()),
        };
        if let Some(t) = text.filter(|t| forms::text_digest(t) == r.digest()) {
            let _ = texts.insert(r.id().raw(), t);
        }
    }
    PreviewTexts(texts)
}

/// The marker of a value each grant sets and a draft cannot know.
fn per_grant(what: &str) -> String {
    format!("[{what}: set for each grant]")
}

/// The marker of a draft field with no value, as the Guide preview
/// spells it.
fn unset(key: &str) -> String {
    format!("[{key}: not set in the draft]")
}

/// The string or number at `path` of a spec, if set and non-empty.
fn spec_scalar(spec: &Value, path: &[&str]) -> Option<String> {
    let mut v = spec;
    for k in path {
        v = v.get(k)?;
    }
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.as_str().to_owned()),
        _ => None,
    }
}

/// A token of the spec as a label: `record_keeping` reads `Record keeping`.
/// The instrument and signature route tokens read as the contract pages
/// name them.
fn token_label(token: &str) -> String {
    match token {
        "mou" => return "Memorandum of understanding".to_owned(),
        "wallet_qes" => return "EUDI Wallet qualified signature".to_owned(),
        "qtsp_remote_qes" => return "Remote qualified signature".to_owned(),
        "approved_advanced" => {
            return "Advanced signature with programme manager approval".to_owned();
        }
        _ => {}
    }
    let spaced = token.replace('_', " ");
    let mut chars = spaced.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => spaced,
    }
}

/// The tokens of the array at `path` of a spec, as labels. `None` when
/// the field is a gap or empty.
fn spec_labels(spec: &Value, path: &[&str]) -> Option<Vec<String>> {
    let mut v = spec;
    for k in path {
        v = v.get(k)?;
    }
    let labels: Vec<String> = v
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .map(token_label)
        .collect();
    (!labels.is_empty()).then_some(labels)
}

/// The contract placeholder preview of a draft spec (R-PG-01, R-CT-01;
/// `programme-creator.md` step 11).
///
/// It lays out the sub-grant agreement of `fstp-contract`
/// ([`fstp_contract::render::agreement_blocks`]), the layout the contract
/// PDF uses, as text blocks. The draft supplies the programme, the
/// currency, the instrument and template (P-29), the grant range (P-04),
/// the flow-down obligations (I-49) and the signature cascade (P-30).
/// Each value that only a grant sets shows one visible marker: the
/// proposal, the amount, the plan version, the dates and the parties.
/// The clause texts stay the pending-review clause of the contract.
/// `TODO(legal)`: the clause texts come from the signed grant agreement
/// and legal review (`contracts.md`, I-49).
fn contract_preview(spec: &Value) -> Vec<fstp_guide::PreviewBlock> {
    use fstp_contract::TermsBlock;
    use fstp_guide::{PreviewBlock, PreviewKind};
    let block = |kind, text: String| PreviewBlock { kind, text };
    let inner = spec.get("spec").unwrap_or(spec);
    let currency = spec_scalar(inner, &["currency"]).unwrap_or_else(|| unset("currency"));
    let proposal = per_grant("proposal");
    let amount = per_grant("granted amount");
    let plan = per_grant("agreed plan version");
    let terms = fstp_contract::render::agreement_blocks(&fstp_contract::AgreementValues {
        proposal: &proposal,
        currency: &currency,
        amount: &amount,
        plan: &plan,
    });
    let mut terms = terms.into_iter().map(|b| match b {
        TermsBlock::Heading(t) => block(PreviewKind::Heading, t),
        TermsBlock::Clause(t) => block(PreviewKind::Paragraph, t),
    });
    let mut out: Vec<PreviewBlock> = terms.next().into_iter().collect();
    out.push(block(
        PreviewKind::Paragraph,
        format!(
            "Programme: {}",
            spec_scalar(inner, &["identity", "name"]).unwrap_or_else(|| unset("identity.name"))
        ),
    ));
    let instrument = spec_scalar(inner, &["contract", "p29_instrument", "instrument"]);
    let template = spec_scalar(inner, &["contract", "p29_instrument", "template", "id"]);
    let version = spec_scalar(
        inner,
        &["contract", "p29_instrument", "template", "version"],
    );
    out.push(block(
        PreviewKind::Paragraph,
        match (instrument, template, version) {
            (Some(i), Some(t), Some(v)) => {
                format!("Instrument: {}, template {t} version {v}.", token_label(&i))
            }
            _ => format!("Instrument: {}.", unset("contract.p29_instrument")),
        },
    ));
    out.extend(terms);
    out.push(block(
        PreviewKind::Paragraph,
        match (
            spec_scalar(inner, &["money", "p04_grant_range", "min"]),
            spec_scalar(inner, &["money", "p04_grant_range", "max"]),
        ) {
            (Some(min), Some(max)) => {
                format!("Grant range per proposal: {currency} {min} to {currency} {max}.")
            }
            _ => format!(
                "Grant range per proposal: {}.",
                unset("money.p04_grant_range")
            ),
        },
    ));
    out.push(block(
        PreviewKind::Paragraph,
        format!(
            "Tasks, milestones, start dates and due dates: {}.",
            per_grant("agreed plan")
        ),
    ));
    out.push(block(
        PreviewKind::Heading,
        "Flow-down obligations".to_owned(),
    ));
    match spec_labels(inner, &["contract", "flow_down"]) {
        Some(labels) => out.extend(labels.into_iter().map(|l| block(PreviewKind::Item, l))),
        None => out.push(block(PreviewKind::Item, unset("contract.flow_down"))),
    }
    out.push(block(PreviewKind::Heading, "Signatures".to_owned()));
    out.push(block(
        PreviewKind::Paragraph,
        format!(
            "Signature cascade: {}.",
            spec_labels(inner, &["contract", "p30_signature_cascade"])
                .map_or_else(|| unset("contract.p30_signature_cascade"), |l| l.join(", "))
        ),
    ));
    for role in [
        fstp_contract::PartyRole::Lead,
        fstp_contract::PartyRole::Signatory,
    ] {
        out.push(block(
            PreviewKind::Item,
            format!(
                "{}: {}",
                super::grant::party_label(role),
                per_grant("party")
            ),
        ));
    }
    out
}

/// `creator.preview` (R-PG-01, I-51; design sections 2.2 J1 and 3.2):
/// the Guide preview from `fstp-guide`, the public page preview from
/// `fstp-public` and the contract placeholder preview over the
/// `fstp-contract` agreement layout ([`contract_preview`]), as text
/// blocks over the draft's values.
async fn preview<P: Seams>(
    call: &Call<'_, P>,
    op: &Op,
    p: ProgrammeId,
    d: &fstp_creator::Draft,
    viewer: AccountId,
) -> Result<CreatorModel, ApiError> {
    let state = &call.state;
    let kind = match op.request.get("preview").and_then(Value::as_str) {
        Some("guide") => "guide",
        Some("public") => "public",
        Some("contract") => "contract",
        _ => return Err(call.refuse(ApiError::bad_request(forms::REQUEST_RULE))),
    };
    let view = fstp_creator::draft_view(&state.core, &state.creator, p)
        .ok_or_else(|| call.refuse(no_draft()))?;
    if kind == "contract" {
        return Ok(CreatorModel::Preview {
            kind,
            blocks: contract_preview(&view.spec),
        });
    }
    if kind == "public" {
        return Ok(CreatorModel::Preview {
            kind,
            blocks: fstp_public::draft_public_preview(&view.spec),
        });
    }
    // H-07 before the first question, as the report does.
    if asks_about_people(state, p) {
        vault_read_admitted(call, viewer)?;
    }
    let inputs = shell_inputs(call, p, d.head(), viewer);
    let Some(profile) = inputs.profile else {
        return Err(call.refuse(ApiError::NotImplemented(
            "the cell's funder profile source for the draft's profile",
        )));
    };
    let template = fstp_guide::parse_template(profile.guide_template().as_bytes())
        .map_err(|_| call.refuse(ApiError::refused(ErrorCode::Unavailable, "I-51")))?;
    let mut texts = BTreeMap::new();
    if let Some(head) = fstp_domain::policy::head(&state.core, p) {
        for k in &head.frozen.p09.0 {
            let id = k.text.id().raw();
            if texts.contains_key(&id) {
                continue;
            }
            if let Ok(bytes) = call
                .ports
                .texts()
                .get_public(crate::port::PublicTextRef(id))
                .await
                && let Ok(t) = String::from_utf8(bytes)
            {
                let _ = texts.insert(id, t);
            }
        }
    }
    let blocks = fstp_public::draft_guide_preview(
        &state.core,
        p,
        &view.spec,
        d.profile(),
        &template,
        &PreviewTexts(texts),
    )
    .map_err(|_| call.refuse(ApiError::refused(ErrorCode::Unavailable, "I-51")))?;
    Ok(CreatorModel::Preview { kind, blocks })
}

/// Every programme of the state, in id order: those with a call, a
/// binding or a draft, each one the core holds.
///
/// Interim, pending a programme listing of the domain (lane W1b): a
/// programme with no call, no binding and no draft is not listed. A cell
/// serves one tenant, so each listed programme is the tenant's (I-19).
fn programmes(state: &EngineState) -> Vec<ProgrammeId> {
    let mut out: BTreeSet<ProgrammeId> = BTreeSet::new();
    for (_, c) in state.core.calls().iter() {
        let _ = out.insert(c.programme());
    }
    for (_, b) in state.core.roster().bindings() {
        let _ = out.insert(b.programme);
    }
    for (p, _) in state.creator.drafts() {
        let _ = out.insert(p);
    }
    out.into_iter()
        .filter(|p| state.core.policy().programme(*p).is_some())
        .collect()
}

/// The live invitations of a draft (module documentation).
async fn invitations<P: Seams>(
    call: &Call<'_, P>,
    p: ProgrammeId,
    d: &fstp_creator::Draft,
    viewer: AccountId,
) -> Result<CreatorModel, ApiError> {
    let accepted: Vec<AccountId> = d
        .live_invitations()
        .filter_map(|(_, i)| i.accepted)
        .collect();
    // H-07 before the first question: the SoD previews of the shell
    // facts and the `IsVerified` answers below.
    if asks_about_people(&call.state, p) || !accepted.is_empty() {
        vault_read_admitted(call, viewer)?;
    }
    let inputs = shell_inputs(call, p, d.head(), viewer);
    let mut verified = BTreeMap::new();
    for a in accepted {
        if let std::collections::btree_map::Entry::Vacant(e) = verified.entry(a) {
            let ans = ask_vault(call, &Query::IsVerified { account: a }).await?;
            let _ = e.insert(ans.holds);
        }
    }
    let mut rows = Vec::new();
    for (id, i) in d.live_invitations() {
        let email = match i.invitee {
            Invitee::Pending { contact } => lock(&call.st.content)
                .text(contact)
                .map(str::to_owned)
                .ok_or_else(|| call.refuse(text_unknown()))?,
            Invitee::Account(a) => label_of(call, a).await?,
        };
        let granted =
            i.account().is_some_and(|a| {
                call.state.core.roster().bindings().any(|(_, b)| {
                    b.account == a && b.programme == p && b.role == i.role && b.held()
                })
            });
        let state = if granted {
            "granted"
        } else if i.accepted.is_some_and(|a| verified.get(&a) == Some(&true)) {
            "verified"
        } else if i.accepted.is_some() {
            "accepted"
        } else {
            "invited"
        };
        let (sod, rule) = match (i.account(), inputs.sod.outcomes.get(&id)) {
            (Some(_), Some(fstp_creator::PreviewOutcome::Admitted)) => ("pass", None),
            (Some(_), Some(fstp_creator::PreviewOutcome::Refused(r))) => {
                ("fail", Some(rule_text(*r)))
            }
            _ => ("unchecked", None),
        };
        rows.push(InvitationRow {
            id,
            email,
            role: fstp_access::role_wire_name(i.role),
            state,
            sod,
            rule,
        });
    }
    Ok(CreatorModel::Invitations(rows))
}

/// The import proposals of a draft, each with its held value and its
/// evidence texts. A value the engine does not hold, or a document this
/// core did not take, fails the read closed (`creator.rs`).
fn proposals<P: Seams>(call: &Call<'_, P>, p: ProgrammeId) -> Result<CreatorModel, ApiError> {
    let import = &call.state.import;
    let memory = lock(&call.st.creator);
    let mut rows = Vec::new();
    for s in import.proposals_of(ProgrammeRef::from_raw(p.raw())) {
        let r = s.proposal();
        let value = import.value_of(r.id).ok_or_else(|| {
            call.refuse(ApiError::NotImplemented(
                "a proposed value the engine does not hold: the shell's hold after a replay (the lead)",
            ))
        })?;
        let text = memory.upload(r.document).ok_or_else(|| {
            call.refuse(ApiError::NotImplemented(
                "the text of a document uploaded outside this API core: a blob read with a clearance (port.rs, the lead)",
            ))
        })?;
        let evidence = r
            .evidence
            .iter()
            .filter_map(|span| text.evidence(*span))
            .map(|t| t.as_data().to_owned())
            .collect();
        rows.push(ProposalView {
            id: r.id,
            field: r.field.key(),
            value: value.data_value(),
            digest: r.text.digest().bytes(),
            evidence,
            flagged: !r.conflicts_with_profile.is_empty(),
            resolution: s.resolution().map(|x| x.as_str()),
        });
    }
    Ok(CreatorModel::Proposals(rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R-PG-01, R-CT-01: the contract preview of a spec lays out the
    /// `fstp-contract` agreement over the draft's values, with one marker
    /// for each value only a grant sets, and never a made-up amount.
    #[test]
    fn r_pg_01_contract_preview_marks_per_grant_values() {
        let spec = fstp_json::parse(
            br#"{"currency":"EUR","identity":{"name":"Synthetic programme"},
            "money":{"p04_grant_range":{"max":"100000.00","min":"5000.00"}},
            "contract":{"flow_down":["record_keeping"],
            "p29_instrument":{"instrument":"mou","template":{"id":"t-1","version":1}},
            "p30_signature_cascade":["wallet_qes"]}}"#,
        )
        .unwrap_or(Value::Null);
        let blocks = contract_preview(&spec);
        let texts: Vec<&str> = blocks.iter().map(|b| b.text.as_str()).collect();
        let heading = fstp_contract::render::agreement_heading(&per_grant("proposal"));
        assert_eq!(texts.first(), Some(&heading.as_str()), "{texts:?}");
        for want in [
            "Programme: Synthetic programme",
            "Granted amount: EUR [granted amount: set for each grant].",
            "Agreed plan version: [agreed plan version: set for each grant].",
            fstp_contract::render::CLAUSES_PENDING,
            "Grant range per proposal: EUR 5000.00 to EUR 100000.00.",
            "Record keeping",
            "Lead applicant: [party: set for each grant]",
        ] {
            assert!(texts.contains(&want), "{want}: {texts:?}");
        }
        let gap = contract_preview(&Value::Null);
        assert!(
            gap.iter()
                .any(|b| b.text == "Programme: [identity.name: not set in the draft]"),
            "{gap:?}"
        );
    }
}
