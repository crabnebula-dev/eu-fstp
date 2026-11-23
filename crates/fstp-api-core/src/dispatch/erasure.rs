//! `admin.erasures`, the checks of `admin.request_erasure` (P-41,
//! ADR-007, lane m5/retention; see `crate::erasure`), and
//! `admin.erase_document` (ADR-007, Daniel 2026-11-23, lane L39).

use std::collections::BTreeMap;

use fstp_domain::id::{AccountId, ProgrammeId, ProposalId};
use fstp_domain::retention::RetentionEnd;

use super::{Call, Seams, port_failed};
use crate::erasure::{DocumentLine, ErasuresView};
use crate::port::{BlobOwner, BlobRef, BlobStore as _, TextClass, TextOwner, TextStore as _};
use crate::{ApiError, ErrorCode, ReadModel};

/// The grants whose funder retention ended at the read instant, from the
/// confirmation instants the journal folded (P-41).
pub(super) fn retention_ended<P: Seams>(call: &Call<'_, P>) -> Vec<RetentionEnd> {
    let confirmed = super::journal(call).confirmations().clone();
    crate::erasure::ended(
        fstp_domain::retention::retention_ends(&call.state.core, &confirmed),
        call.now,
    )
}

/// `admin.erasures`: the erasure log, the grants whose retention ended,
/// and the import documents (lane L39). `authorize_read` admitted a
/// tenant admin. Each stated reason is resolved under `clearance`, and
/// one that does not open is left out (I-97). A document whose state the
/// blob store cannot tell fails the read closed.
pub(super) async fn read<P: Seams>(
    call: &Call<'_, P>,
    clearance: &fstp_access::ReadClearance,
) -> Result<ReadModel, ApiError> {
    let erasures = call
        .ports
        .texts()
        .erasures()
        .await
        .map_err(|e| call.refuse(port_failed(e, "ADR-007")))?;
    let mut reasons = BTreeMap::new();
    for r in &erasures {
        let Some(reason) = r.reason else { continue };
        if let Ok(bytes) = call.ports.texts().get(reason, clearance).await
            && let Ok(s) = String::from_utf8(bytes)
        {
            reasons.insert(r.text.0, s);
        }
    }
    let mut documents = Vec::new();
    for d in call.state.import.documents() {
        let erased = call
            .ports
            .blobs()
            .erased(BlobRef(d.blob.bytes()))
            .await
            .map_err(|e| call.refuse(port_failed(e, "ADR-007")))?;
        documents.push(DocumentLine {
            document: d.id.raw(),
            programme: d.programme.raw(),
            media: d.media.mime(),
            erased,
        });
    }
    documents.sort_by_key(|d| d.document);
    Ok(ReadModel::Erasures(ErasuresView {
        erasures,
        retention_ended: retention_ended(call),
        reasons,
        documents,
    }))
}

/// Whether the retention of `grant` ended: a request names only such a
/// grant, whatever its cause (`crate::erasure` readings). Otherwise the
/// refusal names P-41.
pub(super) fn check_grant<P: Seams>(call: &Call<'_, P>, grant: ProposalId) -> Result<(), ApiError> {
    if retention_ended(call).iter().any(|e| e.grant == grant) {
        Ok(())
    } else {
        Err(call.refuse(ApiError::refused(ErrorCode::Refused, "P-41")))
    }
}

/// The programme and blob of import document `document`, or a refusal
/// naming ADR-007 when no such document exists (lane L39).
pub(super) fn import_document<P: Seams>(
    call: &Call<'_, P>,
    document: u128,
) -> Result<(ProgrammeId, BlobRef), ApiError> {
    call.state
        .import
        .document(fstp_import::ImportDocumentId::from_raw(document))
        .map(|d| {
            (
                ProgrammeId::from_raw(d.programme.raw()),
                BlobRef(d.blob.bytes()),
            )
        })
        .ok_or_else(|| call.refuse(ApiError::refused(ErrorCode::NotFound, "ADR-007")))
}

/// `admin.erase_document` (ADR-007, Daniel 2026-11-23, decision 1c; lane
/// L39): stores the stated `reason` as a confidential text of the tenant,
/// under a key of its own, then asks the blob store to erase the import
/// document's blob as tenant admin `by` asked.
pub(super) async fn erase_document<P: Seams>(
    call: &Call<'_, P>,
    by: AccountId,
    programme: ProgrammeId,
    blob: BlobRef,
    reason: &str,
) -> Result<(), crate::port::PortError> {
    let reason = call
        .ports
        .texts()
        .put(
            TextClass::Confidential,
            TextOwner::Tenant,
            reason.as_bytes(),
        )
        .await?;
    call.ports
        .blobs()
        .erase(BlobOwner::Programme(programme), blob, by, reason)
        .await
}
