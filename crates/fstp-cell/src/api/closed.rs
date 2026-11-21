//! The ports the production cell does not serve through the API core
//! yet. Each fails closed (ADR-026 "Fail-closed ports", "Tokens until
//! lane L2"; Q38; production design gap G13).
//!
//! - The vault answers the oracle's questions through the cell's vault
//!   client. Its intake (country, affiliations, birth date), the start of
//!   a verification and the two Q35 queries are not built, so each fails
//!   as `OracleDown`.
//! - No pre-check provider. The prober is `super::tenant`'s.
//! - No break-glass approval through the API core: the request's staff
//!   member, scope and end reach the cell only in the full
//!   `ApproveBreakGlass` of `POST /api/v1/commands`, and the port names
//!   the request by its id alone (ADR-026 record of lane L5, pending
//!   Daniel).

use std::collections::BTreeSet;
use std::sync::Arc;

use fstp_api_core::port::{
    Affiliations, AsyncIdentityOracle, BirthDate, BreakGlass, BreakGlassId, CountryCode,
    ExclusionClasses, PortError, Precheck, Receipt, StepUpProof, Vault, VaultBound,
    VerificationPurpose, VerificationRedirect,
};
use fstp_domain::id::{AccountId, OrganisationId, ProgrammeId, ProposalId};
use fstp_domain::oracle::{Answer, OracleDown, Query};
use fstp_rt::Runtime;

use super::Inner;
use crate::engine::VaultClient;

/// The vault port.
pub(crate) struct CellVault<R: Runtime, V>(pub(super) Arc<Inner<R, V>>);

impl<R: Runtime, V: VaultClient> AsyncIdentityOracle for CellVault<R, V> {
    async fn answer(&self, q: &Query) -> Result<Answer, OracleDown> {
        let now = self.0.now();
        let answers = self
            .0
            .vault
            .ask(std::slice::from_ref(q), None, now)
            .await
            .map_err(|_| OracleDown)?;
        answers.get(q).cloned().ok_or(OracleDown)
    }
}

impl<R: Runtime, V: VaultClient> Vault for CellVault<R, V> {
    async fn state_country(
        &self,
        a: AccountId,
        p: ProposalId,
        c: VaultBound<CountryCode>,
    ) -> Result<Receipt, OracleDown> {
        let _ = (a, p, c);
        Err(OracleDown)
    }

    async fn declare_affiliations(
        &self,
        a: AccountId,
        p: ProposalId,
        d: VaultBound<Affiliations>,
    ) -> Result<Receipt, OracleDown> {
        let _ = (a, p, d);
        Err(OracleDown)
    }

    async fn state_birth_date(
        &self,
        a: AccountId,
        p: ProposalId,
        d: VaultBound<BirthDate>,
    ) -> Result<Receipt, OracleDown> {
        let _ = (a, p, d);
        Err(OracleDown)
    }

    async fn begin_verification(
        &self,
        purpose: VerificationPurpose,
        a: AccountId,
    ) -> Result<VerificationRedirect, OracleDown> {
        let _ = (purpose, a);
        Err(OracleDown)
    }

    async fn classes_defined(
        &self,
        programme: ProgrammeId,
        classes: &ExclusionClasses,
    ) -> Result<Answer, OracleDown> {
        let _ = (programme, classes);
        Err(OracleDown)
    }

    async fn proximity_lists_declared(
        &self,
        programme: ProgrammeId,
        orgs: &BTreeSet<OrganisationId>,
    ) -> Result<Answer, OracleDown> {
        let _ = (programme, orgs);
        Err(OracleDown)
    }
}

/// No pre-check provider (Q38).
pub(crate) struct NoPrecheck;

impl Precheck for NoPrecheck {}

/// No break-glass approval through the API core.
pub(crate) struct ClosedBreakGlass;

impl BreakGlass for ClosedBreakGlass {
    async fn decide(
        &self,
        approver: AccountId,
        b: BreakGlassId,
        approve: bool,
        proof: StepUpProof,
    ) -> Result<(), PortError> {
        let _ = (approver, b, approve, proof);
        Err(PortError::Unavailable)
    }
}
