//! `admin.erasures` and the checks of `admin.request_erasure` (P-41,
//! ADR-007, lane m5/retention; see `crate::erasure`).

use fstp_domain::id::ProposalId;
use fstp_domain::retention::RetentionEnd;

use super::{Call, Seams, port_failed};
use crate::erasure::ErasuresView;
use crate::port::TextStore as _;
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

/// `admin.erasures`: the erasure log and the grants whose retention
/// ended. `authorize_read` admitted a tenant admin.
pub(super) async fn read<P: Seams>(call: &Call<'_, P>) -> Result<ReadModel, ApiError> {
    let erasures = call
        .ports
        .texts()
        .erasures()
        .await
        .map_err(|e| call.refuse(port_failed(e, "ADR-007")))?;
    Ok(ReadModel::Erasures(ErasuresView {
        erasures,
        retention_ended: retention_ended(call),
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
