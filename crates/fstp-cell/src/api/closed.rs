//! The ports the production cell does not serve through the API core
//! yet. Each fails closed (ADR-026 "Fail-closed ports", "Tokens until
//! lane L2"; Q38; production design gap G13).
//!
//! - The vault answers the oracle's questions through the cell's vault
//!   client. Its intake (country, affiliations, birth date), the start of
//!   a verification and the two Q35 queries are not built, so each fails
//!   as `OracleDown`.
//! - No pre-check provider, prober, recovery or break-glass approval, and
//!   no session or passkey administration through the API core: the
//!   cell's own `/auth` routes serve those.
//! - Invitations are issued through the cell's command route. The API
//!   core reads display handles and login emails only.
//! - [`NoTokens`] refuses every bearer token, so `/mcp` answers 401 and no
//!   agent call is admitted, until lane L2 plugs in its token store.

use std::collections::BTreeSet;
use std::sync::Arc;

use fstp_access::ReadClearance;
use fstp_api_core::port::{
    Accounts, Affiliations, AgentClientId, AgentInfo, AsyncIdentityOracle, BirthDate, BlobOwner,
    BlobRef, BlobStore, BreakGlass, BreakGlassId, ConsentApproval, CountryCode, DisplayHandle,
    ExclusionClasses, InvitationLink, InviteKind, PasskeyRegistration, PortError, Precheck,
    ProbeKind, ProbeOutcome, Prober, Receipt, Recovery, RecoveryId, SessionId, SessionInfo,
    SessionsAdmin, StepUpProof, Tokens, Vault, VaultBound, VerificationPurpose,
    VerificationRedirect,
};
use fstp_cell_core::gate::AgentGrant;
use fstp_domain::id::{AccountId, OrganisationId, ProgrammeId, ProposalId};
use fstp_domain::oracle::{Answer, OracleDown, Query};
use fstp_domain::time::Timestamp;
use fstp_rt::Runtime;

use super::{CellTokens, Inner};
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

/// The accounts port: display handles and login emails only.
pub(crate) struct CellAccounts<R: Runtime, V>(pub(super) Arc<Inner<R, V>>);

impl<R: Runtime, V: Send + Sync> Accounts for CellAccounts<R, V> {
    async fn invite(&self, kind: InviteKind) -> Result<InvitationLink, PortError> {
        let _ = kind;
        Err(PortError::Unavailable)
    }

    /// A pseudonymous handle from the account id. Never an email.
    async fn display_handle(&self, a: AccountId) -> Result<DisplayHandle, PortError> {
        let h = fstp_crypto::sha256(&a.raw().to_be_bytes());
        let tail: String = h.iter().take(3).map(|b| format!("{b:02x}")).collect();
        Ok(DisplayHandle(format!("member-{tail}")))
    }

    /// The cell's login email index (SA-11, I-86).
    async fn login_email(&self, a: AccountId) -> Result<Option<String>, PortError> {
        self.0
            .erasure
            .login_email(a)
            .await
            .map_err(|_| PortError::Unavailable)
    }
}

/// No pre-check provider (Q38).
pub(crate) struct NoPrecheck;

impl Precheck for NoPrecheck {}

/// No prober: every probe fails (Q5).
pub(crate) struct ClosedProber;

impl Prober for ClosedProber {
    async fn probe(&self, p: ProbeKind) -> ProbeOutcome {
        let _ = p;
        ProbeOutcome::Fail
    }
}

/// No recovery approval through the API core: `/auth/recovery/approve`.
pub(crate) struct ClosedRecovery;

impl Recovery for ClosedRecovery {
    async fn approve(
        &self,
        approver: AccountId,
        r: RecoveryId,
        proof: StepUpProof,
    ) -> Result<(), PortError> {
        let _ = (approver, r, proof);
        Err(PortError::Unavailable)
    }
}

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

/// No session or passkey administration through the API core: the
/// cell's `/auth/sessions`, `/auth/devices` and `/auth/passkeys` routes.
pub(crate) struct ClosedSessionsAdmin;

impl SessionsAdmin for ClosedSessionsAdmin {
    async fn list(&self, a: AccountId) -> Result<Vec<SessionInfo>, PortError> {
        let _ = a;
        Err(PortError::Unavailable)
    }

    async fn end(&self, a: AccountId, s: SessionId) -> Result<(), PortError> {
        let _ = (a, s);
        Err(PortError::Unavailable)
    }

    async fn add_passkey(
        &self,
        a: AccountId,
        s: SessionId,
        reg: PasskeyRegistration,
        proof: StepUpProof,
    ) -> Result<(), PortError> {
        let _ = (a, s, reg, proof);
        Err(PortError::Unavailable)
    }
}

/// No blob store yet (R-PG-02 imports).
pub(crate) struct ClosedBlobs;

impl BlobStore for ClosedBlobs {
    async fn put(&self, owner: BlobOwner, bytes: &[u8]) -> Result<BlobRef, PortError> {
        let _ = (owner, bytes);
        Err(PortError::Unavailable)
    }

    async fn get(
        &self,
        owner: BlobOwner,
        r: BlobRef,
        clearance: &ReadClearance,
    ) -> Result<Vec<u8>, PortError> {
        let _ = (owner, r, clearance);
        Err(PortError::Unavailable)
    }
}

/// The token store until lane L2: every token is refused, and no agent
/// grant exists.
pub(crate) struct NoTokens;

impl Tokens for NoTokens {
    async fn grant(
        &self,
        token: &[u8],
        now: Timestamp,
    ) -> Result<fstp_access::GrantFacts, PortError> {
        let _ = (token, now);
        Err(PortError::Refused)
    }

    async fn revoke(&self, account: AccountId, client: AgentClientId) -> Result<(), PortError> {
        let _ = (account, client);
        Err(PortError::Unavailable)
    }

    async fn approve_consent(&self, c: ConsentApproval) -> Result<String, PortError> {
        drop(c);
        Err(PortError::Refused)
    }

    async fn agents(
        &self,
        account: AccountId,
        now: Timestamp,
    ) -> Result<Vec<AgentInfo>, PortError> {
        let _ = (account, now);
        Ok(Vec::new())
    }
}

impl CellTokens for NoTokens {
    async fn agent_grant(
        &self,
        account: AccountId,
        client: AgentClientId,
        now: Timestamp,
    ) -> Option<AgentGrant> {
        let _ = (account, client, now);
        None
    }
}
