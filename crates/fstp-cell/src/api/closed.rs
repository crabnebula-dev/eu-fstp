//! The ports the production cell does not serve through the API core
//! yet. Each fails closed (ADR-026 "Fail-closed ports", "Tokens until
//! lane L2"; Q38; production design gap G13).
//!
//! - The vault answers the oracle's questions through the cell's vault
//!   client. Its intake (country, affiliations, birth date) and the two
//!   Q35 queries are not built, so each fails as `OracleDown`. The start
//!   of an identity verification records a request that staff record on
//!   the vault origin (ADR-026 record of lane L24). The coordinator
//!   unmask opens the vault origin's release page with an `unmask` ticket
//!   that the cell's `Ticket` key signs (ADR-023, ADR-026 amendment of
//!   2026-11-23).

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

impl<R: Runtime, V> CellVault<R, V> {
    /// The vault origin's release page with a signed `unmask` ticket for
    /// the party `subject` of `programme` (ADR-023 readings 7 and 8, ADR-026
    /// amendment of 2026-11-23, M10 F-058). The ticket names the party's
    /// account and the programme scope, and no proposal, as the raw command
    /// route signed it. The ticket travels in the fragment, which the
    /// browser never sends to a server. A cell with no `Ticket` key answers
    /// `OracleDown`, and [`Vault::releases_unmask`] said so before the
    /// record.
    fn unmask_page(
        &self,
        programme: ProgrammeId,
        subject: AccountId,
    ) -> Result<VerificationRedirect, OracleDown> {
        use crate::routes::Backend as _;
        let key = self.0.backend.ticket_key().ok_or(OracleDown)?;
        let nonce = fstp_crypto::random_array::<16>().map_err(|_| OracleDown)?;
        let unmask = Unmask {
            cell: self.0.cell,
            host: &self.0.host,
            programme,
            subject,
        };
        unmask_redirect(&unmask, self.0.now().micros(), nonce, &key)
    }
}

/// One unmask the vault port opens a page for.
struct Unmask<'a> {
    cell: [u8; 16],
    host: &'a str,
    programme: ProgrammeId,
    subject: AccountId,
}

/// The release page of the vault origin `https://id.<host>` with the
/// `unmask` ticket of `u`, issued at `now` with `nonce` and signed with
/// `key`, in its fragment (ADR-009 "Vault origin", ADR-023 readings 7
/// and 8).
fn unmask_redirect(
    u: &Unmask<'_>,
    now: i64,
    nonce: [u8; 16],
    key: &fstp_crypto::sig::Ed25519SigningKey,
) -> Result<VerificationRedirect, OracleDown> {
    let claims = crate::routes::unmask_claims(u.cell, u.programme, u.subject, now, nonce)
        .ok_or(OracleDown)?;
    let ticket = crate::routes::sign_ticket(&claims, key).map_err(|_| OracleDown)?;
    Ok(VerificationRedirect(format!(
        "https://id.{}/r#{ticket}",
        u.host
    )))
}

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
            // ADR-023 readings 7 and 8, ADR-026 amendment of 2026-11-23
            // (M10 F-058): the API core recorded `PartyUnmasked` first.
            VerificationPurpose::Unmask {
                programme, subject, ..
            } => return self.unmask_page(programme, subject),
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

    /// The cell opens an unmask page only with its `Ticket` key (ADR-026
    /// amendment of 2026-11-23, M10 F-058).
    async fn releases_unmask(&self) -> bool {
        use crate::routes::Backend as _;
        self.0.backend.ticket_key().is_some()
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

    /// The vault name mask (M7 Q4, ADR-033 record of lane L31). A vault
    /// that cannot mask fails the read closed.
    async fn mask_names(
        &self,
        team: &[AccountId],
        texts: &[String],
    ) -> Result<Vec<Vec<fstp_api_core::port::NameMaskSpan>>, OracleDown> {
        let masks = self
            .0
            .vault
            .mask(team, texts)
            .await
            .map_err(|_| OracleDown)?;
        Ok(masks
            .into_iter()
            .map(|spans| {
                spans
                    .into_iter()
                    .map(|s| fstp_api_core::port::NameMaskSpan {
                        start: s.start,
                        end: s.end,
                        person: s.person,
                        birth_date: s.class == fstp_vault_proto::WireMaskClass::BirthDate,
                    })
                    .collect()
            })
            .collect())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// M10 F-058, ADR-023 readings 7 and 8, I-17 as amended: the vault
    /// port answers the vault origin's release page with an `unmask`
    /// ticket in its fragment. The cell's `Ticket` key signs it, and it
    /// names the party's account and the programme scope, and no
    /// proposal, within the ADR-009 lifetime bound.
    #[test]
    fn m10_f058_adr023_unmask_ticket_is_signed_for_the_vault_release_page() {
        use fstp_vault_proto::{TicketClaims, TicketKind, WireAccount, WireProgramme};
        let key = fstp_crypto::sig::Ed25519SigningKey::generate().expect("a key");
        let u = Unmask {
            cell: [0xB5; 16],
            host: "tenant-u.fstp.test",
            programme: ProgrammeId::from_raw(41),
            subject: AccountId::from_raw(4_242),
        };
        let now = 1_800_000_000_000_000;
        let VerificationRedirect(to) =
            unmask_redirect(&u, now, [7; 16], &key).expect("the release page");
        let ticket = to
            .strip_prefix("https://id.tenant-u.fstp.test/r#")
            .unwrap_or_else(|| panic!("I-17: not the vault origin's release page: {to}"));
        let bytes = crate::http::body::hex_vec(ticket, fstp_vault_proto::MAX_TICKET_LEN)
            .expect("a hex ticket");
        let framed = fstp_vault_proto::ticket::decode_ticket(&bytes).expect("a framed ticket");
        fstp_crypto::sig::ed25519_verify(&key.public_key(), framed.body(), framed.signature())
            .expect("the cell's Ticket key signed it");
        let claims = TicketClaims::parse(framed.body()).expect("the claims");
        assert_eq!(claims.kind, TicketKind::Unmask);
        assert_eq!(claims.cell, u.cell);
        assert_eq!(claims.account, WireAccount(4_242));
        assert_eq!(claims.proposal, None);
        assert_eq!(
            claims.scope,
            fstp_vault_proto::country_scope(WireProgramme(41))
        );
        assert_eq!(claims.issued_at, now);
        assert_eq!(
            claims.expires_at,
            now + fstp_vault_proto::TICKET_LIFETIME_MAX_US
        );
        assert_eq!(claims.nonce, [7; 16]);
    }
}
