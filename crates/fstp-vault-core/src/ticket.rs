//! The ticket checks of the vault origin (ADR-009 "Tickets", "Write
//! kinds" and "Releases", design section 6.5, I-17).
//!
//! [`check_ticket`] verifies the Ed25519 signature under a pinned key
//! before it reads any claim. Then it checks the cell, the route, the
//! validity window and the lifetime bound, in that order. Single use is
//! the service's part (`vault.ticket_used`), since this crate is pure.
//! [`origin_binding`] ties a write ticket to the one write it admits.

use fstp_vault_proto::{
    TICKET_LIFETIME_MAX_US, Ticket, TicketClaims, TicketKind, WireAccount, WireProposal, WriteKind,
    country_scope, decode_ticket,
};

use crate::VaultState;
use crate::eval::Facts;
use crate::fact::Fact;

/// Why the vault origin refused a ticket. The names follow lane W1c's
/// `reference::vault::TicketRefusal`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TicketRefusal {
    /// The vault holds no cell id and no pinned key yet.
    Unprovisioned,
    /// The bytes do not frame a canonical body and a signature.
    Malformed,
    /// No pinned key verifies the signature.
    BadSignature,
    /// The ticket names another cell.
    ForeignCell,
    /// The ticket's kind does not match the route, or the write.
    WrongKind,
    /// The ticket is issued after now.
    NotYetValid,
    /// The ticket expired.
    Expired,
    /// The ticket lives longer than [`TICKET_LIFETIME_MAX_US`].
    TooLong,
    /// The ticket was used before.
    Replayed,
    /// No negotiation fact lists the release subject.
    NoNegotiationFact,
}

/// The route group of the vault origin a ticket arrived on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Route {
    /// `POST /w`.
    Write,
    /// `POST /r`.
    Release,
}

/// The longest list of pinned ticket keys: current and next, with room
/// for an overlap during rotation.
pub const MAX_PINNED_KEYS: usize = 4;

/// Checks a signed ticket that arrived on `route` at `now`.
///
/// The signature is checked before any claim is read. Then the cell, the
/// route, the window (valid from `issued_at`, strictly before
/// `expires_at`) and the lifetime bound.
///
/// # Errors
///
/// The first [`TicketRefusal`] in that order.
pub fn check_ticket(
    s: &VaultState,
    bytes: &[u8],
    route: Route,
    now: i64,
) -> Result<TicketClaims, TicketRefusal> {
    let Some(cell) = s.cell() else {
        return Err(TicketRefusal::Unprovisioned);
    };
    let t: Ticket = decode_ticket(bytes).map_err(|_| TicketRefusal::Malformed)?;
    let verified = s
        .pinned()
        .iter()
        .any(|k| fstp_crypto::sig::ed25519_verify(k, t.body(), t.signature()).is_ok());
    if !verified {
        return Err(TicketRefusal::BadSignature);
    }
    let c = TicketClaims::parse(t.body()).map_err(|_| TicketRefusal::Malformed)?;
    if c.cell != cell {
        return Err(TicketRefusal::ForeignCell);
    }
    let route_ok = matches!(
        (route, c.kind),
        (Route::Release, TicketKind::Release | TicketKind::BankView)
            | (Route::Write, TicketKind::Write(_))
    );
    if !route_ok {
        return Err(TicketRefusal::WrongKind);
    }
    if now < c.issued_at {
        return Err(TicketRefusal::NotYetValid);
    }
    if now >= c.expires_at {
        return Err(TicketRefusal::Expired);
    }
    let life = c.expires_at.checked_sub(c.issued_at);
    if life.is_none_or(|l| l > TICKET_LIFETIME_MAX_US) {
        return Err(TicketRefusal::TooLong);
    }
    Ok(c)
}

/// The vault side of a release (the second guard of design section 6.5):
/// the claims are a release ticket for a proposal, and the vault's own
/// negotiation fact lists its subject.
///
/// # Errors
///
/// [`TicketRefusal::WrongKind`] or [`TicketRefusal::NoNegotiationFact`].
pub fn release_guard(s: &VaultState, c: &TicketClaims) -> Result<(), TicketRefusal> {
    if c.kind != TicketKind::Release {
        return Err(TicketRefusal::WrongKind);
    }
    match c.proposal {
        Some(p) if s.negotiation_lists(p, c.account) => Ok(()),
        _ => Err(TicketRefusal::NoNegotiationFact),
    }
}

/// What a write ticket must carry to admit one origin write (ADR-009
/// "Tickets" and "Write kinds").
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OriginBinding {
    /// The ticket kind.
    pub kind: WriteKind,
    /// The writer, which the ticket's `account` must name.
    pub writer: WireAccount,
    /// The proposal the ticket must name, if the write names one.
    pub proposal: Option<WireProposal>,
    /// The scope the ticket must carry, if the write needs one.
    pub scope: Option<String>,
}

impl OriginBinding {
    /// Whether the claims `c` admit the write this binding is for.
    pub fn admits(&self, c: &TicketClaims) -> bool {
        c.kind == TicketKind::Write(self.kind)
            && c.account == self.writer
            && self.proposal.is_none_or(|p| c.proposal == Some(p))
            && self.scope.as_ref().is_none_or(|s| *s == c.scope)
    }
}

/// The binding a write ticket needs for `f` over `facts`, the vault's
/// newest facts, or none when no ticket admits `f`.
///
/// Readings of lane W1c, reported to Daniel:
///
/// - The guardian writes a consent, and the ticket names its proposal.
/// - A withdrawal or an ended affiliation travels under the kind of the
///   fact it ends, and only that fact's writer may end it. With no such
///   fact there is nothing to end, so no ticket admits the write.
/// - A declaration that rewrites a partner staff affiliation needs a
///   partner staff ticket, with or without a class (I-04).
/// - A country names its programme through the scope `programme:<id>`.
/// - A proximity list and a verification have writers who are not the
///   fact's subject. No rule for them exists yet, so none is returned.
///   `RecordRelationship` is not a browser write.
/// - Interim reading, pending Daniel: a reviewer declaration names its
///   relatives as vault identity ids. No reviewer knows those ids, so the
///   relatives part of I-03 cannot fire from the origin yet. The minimum
///   attribute set for relatives is the `TODO(legal)` of design section
///   6.8 and Q31. Once it is settled, the body takes attribute tuples, and
///   `fstp-vault` resolves each through `match_key`, never as an id from
///   the request.
pub fn origin_binding(facts: &Facts, f: &Fact) -> Option<OriginBinding> {
    let plain = |kind: WriteKind, writer: WireAccount| OriginBinding {
        kind,
        writer,
        proposal: None,
        scope: None,
    };
    match f {
        Fact::AdultAttestation { account, .. } => {
            Some(plain(WriteKind::AdultAttestation, *account))
        }
        Fact::AttestationWithdrawn { account } => facts
            .attestation_of(*account)
            .map(|_| plain(WriteKind::AdultAttestation, *account)),
        Fact::GuardianConsent { proposal, guardian } => Some(OriginBinding {
            proposal: Some(*proposal),
            ..plain(WriteKind::GuardianConsent, *guardian)
        }),
        Fact::ConsentWithdrawn { proposal } => {
            facts
                .consent_guardian(*proposal)
                .map(|guardian| OriginBinding {
                    proposal: Some(*proposal),
                    ..plain(WriteKind::GuardianConsent, guardian)
                })
        }
        Fact::AffiliationDeclared {
            account,
            org,
            class,
            ..
        } => {
            let stored = facts.affiliation(*account, *org).flatten();
            Some(if class.is_some() || stored.is_some() {
                plain(WriteKind::PartnerStaffDeclared, *account)
            } else {
                plain(WriteKind::AffiliationDeclared, *account)
            })
        }
        Fact::AffiliationEnded { account, org } => {
            facts.affiliation(*account, *org).map(|class| match class {
                Some(_) => plain(WriteKind::PartnerStaffDeclared, *account),
                None => plain(WriteKind::AffiliationDeclared, *account),
            })
        }
        Fact::ReviewerDeclaration { reviewer, .. } => {
            Some(plain(WriteKind::ReviewerDeclaration, *reviewer))
        }
        Fact::CountryStated {
            account, programme, ..
        } => Some(OriginBinding {
            scope: Some(country_scope(*programme)),
            ..plain(WriteKind::CountryStated, *account)
        }),
        Fact::VerificationRecorded { .. }
        | Fact::ProximityListDeclared { .. }
        | Fact::Relationship { .. } => None,
        // M5 design 12.1: the lead writes the bank details and opens a
        // dispute. Another account verifies the latest version, never the
        // writer, and resolves a dispute under the same ticket kind (I-33).
        Fact::BankDetails { grant, account, .. } => Some(OriginBinding {
            proposal: Some(*grant),
            ..plain(WriteKind::BankDetails, *account)
        }),
        Fact::BankVerified {
            grant,
            version,
            verifier,
            ..
        } => facts
            .bank_of(*grant)
            .filter(|b| b.version == *version && b.writer != *verifier)
            .map(|_| OriginBinding {
                proposal: Some(*grant),
                ..plain(WriteKind::BankVerification, *verifier)
            }),
        Fact::BankDispute {
            grant,
            account,
            open: true,
        } => Some(OriginBinding {
            proposal: Some(*grant),
            ..plain(WriteKind::BankDispute, *account)
        }),
        Fact::BankDispute {
            grant,
            account,
            open: false,
        } => {
            let writer = facts.bank_of(*grant).map(|b| b.writer);
            (facts.bank_disputed(*grant) && writer != Some(*account)).then(|| OriginBinding {
                proposal: Some(*grant),
                ..plain(WriteKind::BankVerification, *account)
            })
        }
        Fact::HardshipEvidence {
            grant,
            evidence,
            account,
            ..
        } => facts
            .hardship_of(*grant, *evidence)
            .is_none()
            .then(|| OriginBinding {
                proposal: Some(*grant),
                ..plain(WriteKind::HardshipEvidence, *account)
            }),
        Fact::HardshipVerified {
            grant,
            evidence,
            verifier,
            ..
        } => facts
            .hardship_of(*grant, *evidence)
            .filter(|h| h.submitter != *verifier)
            .map(|_| OriginBinding {
                proposal: Some(*grant),
                ..plain(WriteKind::HardshipVerification, *verifier)
            }),
    }
}

/// The fact kinds a write ticket of `kind` may carry: its own fact and the
/// fact that ends it.
///
/// A document upload and a verification carry none. A document is not a
/// fact. A verification's identity and verifier must never come from a
/// browser body (design section 6.4, Q17, ADR-008), so the origin never
/// decodes kind 6. The recorder route of ADR-008 will take its own body
/// through `fstp_vault::Vault::verification_fact`.
pub fn fact_kinds_of(kind: WriteKind) -> &'static [u16] {
    use crate::fact::kind as k;
    match kind {
        WriteKind::CountryStated => &[k::COUNTRY_STATED],
        WriteKind::AffiliationDeclared => &[k::AFFILIATION_DECLARED, k::AFFILIATION_ENDED],
        WriteKind::AdultAttestation => &[k::ADULT_ATTESTATION, k::ATTESTATION_WITHDRAWN],
        WriteKind::GuardianConsent => &[k::GUARDIAN_CONSENT, k::CONSENT_WITHDRAWN],
        WriteKind::DocumentUpload | WriteKind::VerificationRecorded => &[],
        WriteKind::ProximityListDeclared => &[k::PROXIMITY_LIST_DECLARED],
        WriteKind::ReviewerDeclaration => &[k::REVIEWER_DECLARATION],
        WriteKind::PartnerStaffDeclared => &[k::PARTNER_STAFF_DECLARED, k::AFFILIATION_ENDED],
        WriteKind::BankDetails => &[k::BANK_DETAILS],
        WriteKind::BankVerification => &[k::BANK_VERIFIED, k::BANK_DISPUTE],
        WriteKind::BankDispute => &[k::BANK_DISPUTE],
        WriteKind::HardshipEvidence => &[k::HARDSHIP_EVIDENCE],
        WriteKind::HardshipVerification => &[k::HARDSHIP_VERIFIED],
    }
}
