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
//! - `creator.impact` answers the empty list for a programme with no
//!   call, which is every draft (change D3). A programme with calls needs
//!   `fstp_programme::impact` (an `fstp-programme` edge, the lead).

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

/// Builds the command of `op`. `ids` replays the ids an earlier build
/// drew, and records each new draw, as the parent's `build` does.
fn build<P: Seams>(
    call: &Call<'_, P>,
    form: Form,
    op: &Op,
    supplied: &Supplied,
    ids: &mut Vec<u128>,
) -> Result<Command, ApiError> {
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
    crate::creator::build(form, &op.request, supplied, &mut draw)
}

/// What the execution stores before it runs: the stored values, and the
/// upload's normalised text, which this core remembers once the command
/// appends.
struct Stored {
    supplied: Supplied,
    text: Option<fstp_import::ExtractedText>,
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
    Ok(Stored { supplied, text })
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
    let cmd = build(call, form, op, &placeholder, &mut ids).map_err(|e| call.refuse(e))?;
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
    let cmd = build(call, form, op, &stored.supplied, &mut ids).map_err(|e| call.refuse(e))?;
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
        let calls: Vec<ImpactRow> = state
            .core
            .calls()
            .iter()
            .filter(|(_, v)| v.programme() == p)
            .map(|(call, _)| ImpactRow { call })
            .collect();
        if !calls.is_empty() {
            return Err(call.refuse(ApiError::NotImplemented(
                "the impact of a change on a programme's calls: fstp_programme::impact (an fstp-programme edge of fstp-api-core, the lead)",
            )));
        }
        return Ok(CreatorModel::Impact(calls));
    }
    let d = state
        .creator
        .draft(p)
        .ok_or_else(|| call.refuse(no_draft()))?;
    match kind {
        ReadKind::GetDraft => {
            let view = fstp_creator::draft_view(&state.core, &state.creator, p)
                .ok_or_else(|| call.refuse(no_draft()))?;
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

/// `creator.preview` (R-PG-01, I-51; design sections 2.2 J1 and 3.2):
/// the Guide preview from `fstp-guide` and the public page preview from
/// `fstp-public`, as text blocks over the draft's values. The contract
/// placeholder preview is a seam: no contract renderer exists before M8.
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
        Some("contract") => {
            return Err(call.refuse(ApiError::NotImplemented(
                "the contract placeholder preview: no contract renderer exists before M8",
            )));
        }
        _ => return Err(call.refuse(ApiError::bad_request(forms::REQUEST_RULE))),
    };
    let view = fstp_creator::draft_view(&state.core, &state.creator, p)
        .ok_or_else(|| call.refuse(no_draft()))?;
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
