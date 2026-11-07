//! Tickets of the vault origin (ADR-009 "Tickets", design section 6.5).
//!
//! A signed ticket is the canonical claims body followed by the 64-byte
//! Ed25519 signature over it, the framing lane W1c proposed. This crate
//! holds no key. [`decode_ticket`] frames the bytes and reads no claim.
//! The vault checks the signature first and only then calls
//! [`TicketClaims::parse`] on the body (ADR-009: the signature is checked
//! before any other field is used).

use fstp_json::Value;

use crate::json::{self, limits, parse_canonical};
use crate::{ProtoError, WireAccount, WireProposal};

/// The length of the Ed25519 signature that ends a signed ticket.
pub const SIGNATURE_LEN: usize = 64;

/// The longest signed ticket the vault takes, in bytes. A canonical claims
/// body with the longest scope is far shorter.
pub const MAX_TICKET_LEN: usize = 2048;

/// The longest scope label, in bytes.
pub const MAX_SCOPE_LEN: usize = 256;

/// The longest lifetime of a ticket: 5 minutes, an ADR-009 constant with
/// no P- id (Q37, interim).
pub const TICKET_LIFETIME_MAX_US: i64 = 5 * 60 * 1_000_000;

/// A signed ticket, framed but not checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    /// The ticket bytes: the claims body, then the signature.
    pub bytes: Vec<u8>,
}

impl Ticket {
    /// The claims body, which the signature covers.
    pub fn body(&self) -> &[u8] {
        let end = self.bytes.len().saturating_sub(SIGNATURE_LEN);
        self.bytes.get(..end).unwrap_or_default()
    }

    /// The signature.
    pub fn signature(&self) -> &[u8] {
        let start = self.bytes.len().saturating_sub(SIGNATURE_LEN);
        self.bytes.get(start..).unwrap_or_default()
    }
}

/// Frames a signed ticket. Fuzzed (`ticket_decode`).
///
/// It reads no claim: any body of at least one byte, followed by a
/// signature, frames. The vault refuses the ticket later unless a pinned
/// key verifies the signature.
///
/// # Errors
///
/// [`ProtoError::Ticket`] for input with no room for a body and a
/// signature, or longer than [`MAX_TICKET_LEN`].
pub fn decode_ticket(bytes: &[u8]) -> Result<Ticket, ProtoError> {
    if bytes.len() <= SIGNATURE_LEN || bytes.len() > MAX_TICKET_LEN {
        return Err(ProtoError::Ticket);
    }
    Ok(Ticket {
        bytes: bytes.to_vec(),
    })
}

/// A kind of vault origin write (ADR-009 "Write kinds").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WriteKind {
    /// The P-17 country.
    CountryStated,
    /// A declared affiliation.
    AffiliationDeclared,
    /// An over-18 attestation.
    AdultAttestation,
    /// A guardian consent.
    GuardianConsent,
    /// A document upload.
    DocumentUpload,
    /// A manual verification outcome.
    VerificationRecorded,
    /// A P-38 proximity list.
    ProximityListDeclared,
    /// A reviewer's employer and relatives.
    ReviewerDeclaration,
    /// A partner staff declaration.
    PartnerStaffDeclared,
    /// The payee bank details of a grant (I-33, I-86).
    BankDetails,
    /// A verification of the latest bank details, or the resolution of a
    /// dispute (I-33).
    BankVerification,
    /// A dispute of the bank details by the lead (I-33).
    BankDispute,
    /// Hardship evidence for a grant (R-PR-04).
    HardshipEvidence,
    /// A verification of hardship evidence (R-PR-04).
    HardshipVerification,
}

impl WriteKind {
    /// Every kind.
    pub const ALL: [WriteKind; 14] = [
        WriteKind::CountryStated,
        WriteKind::AffiliationDeclared,
        WriteKind::AdultAttestation,
        WriteKind::GuardianConsent,
        WriteKind::DocumentUpload,
        WriteKind::VerificationRecorded,
        WriteKind::ProximityListDeclared,
        WriteKind::ReviewerDeclaration,
        WriteKind::PartnerStaffDeclared,
        WriteKind::BankDetails,
        WriteKind::BankVerification,
        WriteKind::BankDispute,
        WriteKind::HardshipEvidence,
        WriteKind::HardshipVerification,
    ];

    /// The ticket spelling of the kind.
    pub const fn label(self) -> &'static str {
        match self {
            WriteKind::CountryStated => "country_stated",
            WriteKind::AffiliationDeclared => "affiliation_declared",
            WriteKind::AdultAttestation => "adult_attestation",
            WriteKind::GuardianConsent => "guardian_consent",
            WriteKind::DocumentUpload => "document_upload",
            WriteKind::VerificationRecorded => "verification_recorded",
            WriteKind::ProximityListDeclared => "proximity_list_declared",
            WriteKind::ReviewerDeclaration => "reviewer_declaration",
            WriteKind::PartnerStaffDeclared => "partner_staff_declared",
            WriteKind::BankDetails => "bank_details",
            WriteKind::BankVerification => "bank_verification",
            WriteKind::BankDispute => "bank_dispute",
            WriteKind::HardshipEvidence => "hardship_evidence",
            WriteKind::HardshipVerification => "hardship_verification",
        }
    }

    /// The fact kind code of the kind's own fact (W1c proposal).
    pub const fn code(self) -> u16 {
        match self {
            WriteKind::CountryStated => 1,
            WriteKind::AffiliationDeclared => 2,
            WriteKind::AdultAttestation => 3,
            WriteKind::GuardianConsent => 4,
            WriteKind::DocumentUpload => 5,
            WriteKind::VerificationRecorded => 6,
            WriteKind::ProximityListDeclared => 7,
            WriteKind::ReviewerDeclaration => 8,
            WriteKind::PartnerStaffDeclared => 9,
            WriteKind::BankDetails => 14,
            WriteKind::BankVerification => 15,
            WriteKind::BankDispute => 16,
            WriteKind::HardshipEvidence => 17,
            WriteKind::HardshipVerification => 18,
        }
    }
}

/// What a ticket admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TicketKind {
    /// A release of identity attributes (`POST /r`).
    Release,
    /// A view of the bank details of the grant the ticket names, on the
    /// release route (`POST /r`). The finance approver reads them to
    /// verify, and the payment releaser for one released request (M5
    /// design reading 6). Nothing else ever shows them (I-86).
    BankView,
    /// One write of one kind (`POST /w`).
    Write(WriteKind),
}

impl TicketKind {
    /// The ticket spelling: `release`, `view:bank`, or `write:<kind label>`.
    pub fn label(self) -> String {
        match self {
            TicketKind::Release => "release".to_owned(),
            TicketKind::BankView => "view:bank".to_owned(),
            TicketKind::Write(k) => format!("write:{}", k.label()),
        }
    }

    /// The kind of spelling `s`, if any.
    pub fn from_label(s: &str) -> Option<TicketKind> {
        if s == "release" {
            return Some(TicketKind::Release);
        }
        if s == "view:bank" {
            return Some(TicketKind::BankView);
        }
        let k = s.strip_prefix("write:")?;
        WriteKind::ALL
            .iter()
            .find(|w| w.label() == k)
            .map(|w| TicketKind::Write(*w))
    }
}

/// The claims of a ticket: canonical JSON `{account, cell, expires_at,
/// issued_at, kind, nonce, proposal, scope}` (ADR-009 "Format").
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TicketClaims {
    /// What it admits.
    pub kind: TicketKind,
    /// The cell, 16 bytes, as 32 lowercase hex digits.
    pub cell: [u8; 16],
    /// The writer of a write, the subject of a release.
    pub account: WireAccount,
    /// The proposal, if the kind names one.
    pub proposal: Option<WireProposal>,
    /// A short label, such as `programme:<id>` for a country.
    pub scope: String,
    /// When it was issued, in UTC microseconds.
    pub issued_at: i64,
    /// When it expires, in UTC microseconds. Valid strictly before.
    pub expires_at: i64,
    /// The ticket id, 16 random bytes.
    pub nonce: [u8; 16],
}

const CLAIMS: &str = "ticket claims";

/// The members of a claims body, in key order.
const CLAIM_MEMBERS: [&str; 8] = [
    "account",
    "cell",
    "expires_at",
    "issued_at",
    "kind",
    "nonce",
    "proposal",
    "scope",
];

impl TicketClaims {
    /// The canonical body.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Shape`] for a scope longer than [`MAX_SCOPE_LEN`] or
    /// holding a control character, or an instant beyond 2^53 - 1.
    pub fn canonical(&self) -> Result<Vec<u8>, ProtoError> {
        if !scope_ok(&self.scope) {
            return Err(ProtoError::Shape(CLAIMS));
        }
        let v = json::obj(vec![
            ("account", json::id_json(self.account.0)),
            ("cell", Value::String(json::hex(&self.cell))),
            ("expires_at", json::int_json(self.expires_at, CLAIMS)?),
            ("issued_at", json::int_json(self.issued_at, CLAIMS)?),
            ("kind", Value::String(self.kind.label())),
            ("nonce", Value::String(json::hex(&self.nonce))),
            ("proposal", json::opt_id_json(self.proposal.map(|p| p.0))),
            ("scope", Value::String(self.scope.clone())),
        ])?;
        json::to_canonical(&v)
    }

    /// Parses a canonical claims body. Call it only after the signature
    /// over `body` verified. Any other spelling is refused, so a signed
    /// re-encoding of the same claims never passes.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Json`], [`ProtoError::NotCanonical`] or
    /// [`ProtoError::Shape`].
    pub fn parse(body: &[u8]) -> Result<TicketClaims, ProtoError> {
        let v = parse_canonical(body, &limits())?;
        let o = json::object(&v, &CLAIM_MEMBERS, CLAIMS)?;
        let kind = TicketKind::from_label(json::string(o, "kind", CLAIMS)?)
            .ok_or(ProtoError::Shape(CLAIMS))?;
        let scope = json::string(o, "scope", CLAIMS)?;
        if !scope_ok(scope) {
            return Err(ProtoError::Shape(CLAIMS));
        }
        Ok(TicketClaims {
            kind,
            cell: json::hex_array(json::string(o, "cell", CLAIMS)?, CLAIMS)?,
            account: WireAccount(json::id(o, "account", CLAIMS)?),
            proposal: json::opt_id(o, "proposal", CLAIMS)?.map(WireProposal),
            scope: scope.to_owned(),
            issued_at: json::int(o, "issued_at", CLAIMS)?,
            expires_at: json::int(o, "expires_at", CLAIMS)?,
            nonce: json::hex_array(json::string(o, "nonce", CLAIMS)?, CLAIMS)?,
        })
    }
}

fn scope_ok(s: &str) -> bool {
    s.len() <= MAX_SCOPE_LEN && !s.chars().any(char::is_control)
}

/// The scope a `CountryStated` ticket carries for programme `programme`:
/// `programme:<id>` (W1c reading, since the claims have no programme
/// member and the vault does not know a proposal's programme).
pub fn country_scope(programme: crate::WireProgramme) -> String {
    format!("programme:{}", programme.0)
}

/// The programme a scope names, if it is the one spelling
/// `programme:<id>` of [`country_scope`]. A release ticket names the
/// proposal's programme this way, and the vault shows only that
/// programme's facts.
pub fn scope_programme(scope: &str) -> Option<crate::WireProgramme> {
    let id = scope.strip_prefix("programme:")?;
    json::parse_id(id, CLAIMS).ok().map(crate::WireProgramme)
}
