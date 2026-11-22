//! The ports the production cell does not serve through the API core
//! yet. Each fails closed (ADR-026 "Fail-closed ports", "Tokens until
//! lane L2"; Q38; production design gap G13).
//!
//! - The vault answers the oracle's questions through the cell's vault
//!   client. Its intake (country, affiliations, birth date) and the two
//!   Q35 queries are not built, so each fails as `OracleDown`. The start
//!   of an identity verification records a request that staff record on
//!   the vault origin (ADR-026 record of lane L24).

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

/// The person's own identity page, where a request reads "We will contact
/// you to check your ID" (ADR-026 record of lane L24).
pub(crate) const IDENTITY_PAGE: &str = "/app/me/identity";

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
        // ADR-008 and ADR-026 record of lane L24 (decided by Daniel on
        // 2026-11-22): "Request, staff record it". An identity purpose
        // records a request with no identity data (I-17), and staff record
        // the check on the vault origin. The guardian consent and bank
        // purposes keep their own write tickets.
        match purpose {
            VerificationPurpose::Applicant
            | VerificationPurpose::AdminIdentity
            | VerificationPurpose::ProgrammeRole => {}
            _ => return Err(OracleDown),
        }
        let state = self.0.engine.state();
        if !state.verification_requested(a) {
            // A system task's command id, in the namespace of the cell's own
            // tasks, with a random suffix.
            let suffix = fstp_crypto::random_array::<8>().map_err(|_| OracleDown)?;
            let id = fstp_cell_core::system_command_id(suffix);
            let command = fstp_cell_core::CellCommand::Release(
                fstp_cell_core::release::ReleaseCommand::RequestVerification { account: a },
            );
            let admitted = fstp_cell_core::gate::admit_system(
                &state,
                fstp_cell_core::gate::Action::Command(command),
                fstp_cell_core::SystemTask::IdentityPort,
                id,
                self.0.now(),
            )
            .map_err(|_| OracleDown)?;
            self.0
                .engine
                .execute(admitted)
                .await
                .map_err(|_| OracleDown)?;
        }
        Ok(VerificationRedirect(IDENTITY_PAGE.to_owned()))
    }

    async fn verification_requested(&self, a: AccountId) -> bool {
        self.0.engine.state().verification_requested(a)
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
