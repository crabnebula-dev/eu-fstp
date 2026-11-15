//! The coordinator unmask of ADR-023 (I-17 as amended 2026-11-15).
//!
//! - `identity.unmask` runs as a core command through the command path:
//!   the strict form with its purpose, the dry run, the step-up (I-78),
//!   then `UnmaskParty`, which appends one `PartyUnmasked`. Only then does
//!   [`release`] ask the vault for an unmask ticket for the subject's
//!   account and answer with the vault origin's release page. The
//!   identity never passes through this core (ADR-023 reading 7).
//! - `identity.parties` lists the parties of one proposal and the staff of
//!   its programme, by id, after `authorize_read` cleared the caller as a
//!   coordinator of the programme.
//! - `audit.unmasks` lists the unmask records of a programme with their
//!   purposes, after `authorize_read` cleared the caller as its auditor or
//!   a tenant admin (ADR-023 reading 11).

use fstp_access::ReadClearance;
use fstp_domain::assignment::AssignmentKind;
use fstp_domain::id::{ProgrammeId, ProposalId, TextRef};
use fstp_domain::unmask::{PartyKind, UnmaskSubject, party_of};
use fstp_engine::Command;
use fstp_ledger::Seq;

use super::{Call, Seams, label_of, lock, port_failed};
use crate::port::{Vault, VerificationPurpose, VerificationRedirect};
use crate::unmask::{PartiesView, PartyRow, UnmaskModel, UnmaskRow};
use crate::{ApiError, ErrorCode, OpResult, ReadModel};

fn not_found() -> ApiError {
    ApiError::refused(ErrorCode::NotFound, "Input")
}

/// After `UnmaskParty` appended at `seq`: the vault ticket for the
/// subject, and the release page as the reply.
pub(super) async fn release<P: Seams>(
    call: &Call<'_, P>,
    account: fstp_domain::id::AccountId,
    cmd: &Command,
    seq: Seq,
) -> Result<OpResult, ApiError> {
    let Command::Core(fstp_domain::command::Command::UnmaskParty {
        programme, subject, ..
    }) = cmd
    else {
        return Err(call.refuse(not_found()));
    };
    let (party, who) =
        party_of(&call.state.core, *programme, *subject).ok_or_else(|| call.refuse(not_found()))?;
    let purpose = VerificationPurpose::Unmask {
        programme: *programme,
        subject: who,
        party,
    };
    match call
        .ports
        .vault()
        .begin_verification(purpose, account)
        .await
    {
        Ok(VerificationRedirect(to)) => Ok(OpResult::Done {
            body: ReadModel::Redirect(to),
            seq: Some(seq),
        }),
        Err(_) => Err(call.refuse(ApiError::refused(ErrorCode::Unavailable, "oracle"))),
    }
}

/// `identity.parties`: the parties of `p` and the staff of its
/// programme, by id. A held binding of the proposal, every reviewer and
/// IRC assignment of it that is not released, then every held staff and
/// Judging binding of the programme. A display handle labels an
/// assignment only.
pub(super) async fn parties<P: Seams>(
    call: &Call<'_, P>,
    p: ProposalId,
) -> Result<ReadModel, ApiError> {
    let core = &call.state.core;
    let programme =
        super::grant::programme_of(&call.state, p).ok_or_else(|| call.refuse(not_found()))?;
    let mut rows = Vec::new();
    let roster = core.roster();
    for (id, b) in roster.bindings() {
        if b.proposal() != Some(p) || !b.held() {
            continue;
        }
        if let Some(kind) = PartyKind::of_role(b.role) {
            rows.push(PartyRow {
                party: kind,
                subject: UnmaskSubject::Binding(id),
                role: fstp_access::role_wire_name(b.role),
                label: String::new(),
            });
        }
    }
    for (id, a) in core.review().assignments() {
        if a.proposal != p || !a.unreleased() {
            continue;
        }
        let (party, role) = match a.kind {
            AssignmentKind::Reviewer => (PartyKind::Reviewer, "committee_member"),
            AssignmentKind::Irc | AssignmentKind::Amendment(_) => (PartyKind::Irc, "irc_member"),
        };
        rows.push(PartyRow {
            party,
            subject: UnmaskSubject::Assignment(id),
            role,
            label: label_of(call, a.reviewer).await?,
        });
    }
    for (id, b) in roster.bindings() {
        if b.programme != programme || b.proposal().is_some() || !b.held() {
            continue;
        }
        if let Some(kind) = PartyKind::of_role(b.role) {
            // A committee or IRC member appears by the display handle the
            // assignment page already shows. Staff appear by role only.
            let label = match kind {
                PartyKind::Reviewer | PartyKind::Irc => label_of(call, b.account).await?,
                _ => String::new(),
            };
            rows.push(PartyRow {
                party: kind,
                subject: UnmaskSubject::Binding(id),
                role: fstp_access::role_wire_name(b.role),
                label,
            });
        }
    }
    Ok(ReadModel::Unmask(UnmaskModel::Parties(PartiesView {
        programme,
        proposal: p,
        parties: rows,
    })))
}

/// The purpose text `r`: from this core's memory of the texts it stored,
/// else from the text store under the read's clearance. A text that
/// cannot be read is refused, so the log never shows a wrong purpose.
async fn purpose_of<P: Seams>(
    call: &Call<'_, P>,
    r: TextRef,
    clearance: &ReadClearance,
) -> Result<String, ApiError> {
    use crate::port::TextStore as _;
    if let Some(t) = lock(&call.st.content).text(r) {
        return Ok(t.to_owned());
    }
    let bytes = call
        .ports
        .texts()
        .get(crate::port::TextRef(r.id().raw()), clearance)
        .await
        .map_err(|e| call.refuse(port_failed(e, "text")))?;
    String::from_utf8(bytes)
        .map_err(|_| call.refuse(ApiError::refused(ErrorCode::Unavailable, "text")))
}

/// `audit.unmasks`: the unmask records of `programme`, oldest first.
pub(super) async fn log<P: Seams>(
    call: &Call<'_, P>,
    programme: ProgrammeId,
    clearance: &ReadClearance,
) -> Result<ReadModel, ApiError> {
    let records: Vec<_> = call.state.core.unmasks().of(programme).copied().collect();
    let mut rows = Vec::with_capacity(records.len());
    for u in records {
        rows.push(UnmaskRow {
            party: u.party,
            subject: u.subject,
            by: u.by,
            purpose: purpose_of(call, u.purpose, clearance).await?,
            conflict: u.conflict,
            at: u.at.micros(),
        });
    }
    Ok(ReadModel::Unmask(UnmaskModel::Log(rows)))
}
