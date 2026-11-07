//! Fact kinds and their canonical bodies (ADR-009 "Write kinds", design
//! sections 6.5 to 6.8).
//!
//! The kind codes and bodies are lane W1c's proposal in
//! `fstp_celltest::reference::vault::wire`. Kinds 1 to 9 are the write
//! kinds of ADR-009, 10 is `RecordRelationship`, and 11 to 13 are the
//! withdrawals. Bodies are canonical JSON with ids as decimal strings,
//! instants as integers and sets as ascending arrays.
//!
//! Reading: `DocumentUpload` (kind 5) stores a sealed document, not a
//! fact. No query reads it, so it is not a [`Fact`] and its body is
//! refused here.
//!
//! Kind 6 replaces W1c's `{account, person}`. R-ID-02 and design sections
//! 4.3 and 6.7 ask the stored record to hold the method, document type,
//! checks, time and verifier. So its body is `{account, at, checks,
//! document_type, identity, method, verifier}`. `identity` is the
//! `vault.identity` id that `fstp-vault` resolves from the match key. This
//! body is the stored form only. No write ticket carries kind 6
//! (`ticket::fact_kinds_of`), so the vault origin never decodes it from a
//! browser body. The recorder route of ADR-008 will take its own body
//! through `fstp_vault::Vault::verification_fact`, which sets the identity
//! from the match key and the verifier from the ticket account.
//!
//! Interim reading, pending Daniel: kind 8 names a reviewer's relatives
//! as vault identity ids. The minimum attribute set for relatives is the
//! `TODO(legal)` of design section 6.8 and Q31. Once it is settled, the
//! origin body takes attribute tuples, resolved through `match_key`.

use std::collections::BTreeSet;

use fstp_json::Value;
use fstp_vault_proto::json::{self, limits, parse_canonical};
use fstp_vault_proto::{
    ProtoError, WireAccount, WireClass, WireEvidence, WireList, WireProgramme, WireProposal,
};

/// A person: the vault's identity id, which `fstp-vault` resolves from
/// the identity match key before the write (design section 6.4, Q17).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Person(pub u128);

/// An organisation, as a declared affiliation or a proximity list names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Org(pub u128);

/// How a verification was carried out (R-ID-02). M3 records manual
/// checks only (design section 6.7, Q14 B). EUDI methods come in M4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerificationMethod {
    /// A manual check of an identity document by a recorder.
    Manual,
}

impl VerificationMethod {
    /// Every method, in label order.
    pub const ALL: [VerificationMethod; 1] = [VerificationMethod::Manual];

    /// The wire spelling.
    pub const fn label(self) -> &'static str {
        match self {
            VerificationMethod::Manual => "manual",
        }
    }
}

/// The type of the document a verification checked (R-ID-02). The vault
/// stores the type only, never a document number or image.
///
/// Reading, reported to Daniel: no source lists the accepted document
/// types, so this closed set is interim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DocumentType {
    /// A national identity card.
    IdentityCard,
    /// A passport.
    Passport,
    /// A residence permit.
    ResidencePermit,
}

impl DocumentType {
    /// Every type, in label order.
    pub const ALL: [DocumentType; 3] = [
        DocumentType::IdentityCard,
        DocumentType::Passport,
        DocumentType::ResidencePermit,
    ];

    /// The wire spelling.
    pub const fn label(self) -> &'static str {
        match self {
            DocumentType::IdentityCard => "identity_card",
            DocumentType::Passport => "passport",
            DocumentType::ResidencePermit => "residence_permit",
        }
    }
}

/// One check a verification performed (R-ID-02).
///
/// Reading, reported to Daniel: no source lists the checks, so this
/// closed set is interim. Labels sort in the order of the variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Check {
    /// The attributes on the document match the account's.
    DataMatch,
    /// The document shows no sign of tampering.
    DocumentAuthentic,
    /// The document is within its validity dates.
    DocumentValid,
    /// The holder matches the document photo.
    PhotoMatch,
}

impl Check {
    /// Every check, in label order.
    pub const ALL: [Check; 4] = [
        Check::DataMatch,
        Check::DocumentAuthentic,
        Check::DocumentValid,
        Check::PhotoMatch,
    ];

    /// The wire spelling.
    pub const fn label(self) -> &'static str {
        match self {
            Check::DataMatch => "data_match",
            Check::DocumentAuthentic => "document_authentic",
            Check::DocumentValid => "document_valid",
            Check::PhotoMatch => "photo_match",
        }
    }
}

/// The record R-ID-02 asks the vault to store for a verification:
/// method, document type, checks, time and verifier. The outcome is the
/// record itself: a check that fails writes no record. It holds no
/// document number and no image.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VerificationRecord {
    /// The method.
    pub method: VerificationMethod,
    /// The document type.
    pub document_type: DocumentType,
    /// The checks performed. At least one.
    pub checks: BTreeSet<Check>,
    /// When the checks were made, in UTC microseconds.
    pub at: i64,
    /// The account that recorded the outcome.
    pub verifier: WireAccount,
}

fn label_of<T: Copy>(all: &[T], label: fn(T) -> &'static str, s: &str) -> Result<T, ProtoError> {
    all.iter()
        .copied()
        .find(|x| label(*x) == s)
        .ok_or(ProtoError::Shape(BODY))
}

fn checks_of(v: &Value) -> Result<BTreeSet<Check>, ProtoError> {
    let a = v.as_array().ok_or(ProtoError::Shape(BODY))?;
    let mut out = BTreeSet::new();
    let mut last: Option<Check> = None;
    for item in a.iter() {
        let s = item.as_str().ok_or(ProtoError::Shape(BODY))?;
        let c = label_of(&Check::ALL, Check::label, s)?;
        if last.is_some_and(|l| l >= c) {
            return Err(ProtoError::Shape(BODY));
        }
        last = Some(c);
        out.insert(c);
    }
    if out.is_empty() {
        return Err(ProtoError::Shape(BODY));
    }
    Ok(out)
}

/// How a bank detail verification was carried out (I-33, R-PR-05).
///
/// Reading, reported to Daniel: no source lists the methods, so this
/// closed set is interim. The record holds no document number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BankMethod {
    /// A letter from the bank confirming the account holder.
    BankLetter,
    /// A recent bank statement.
    BankStatement,
}

impl BankMethod {
    /// Every method, in label order.
    pub const ALL: [BankMethod; 2] = [BankMethod::BankLetter, BankMethod::BankStatement];

    /// The wire spelling.
    pub const fn label(self) -> &'static str {
        match self {
            BankMethod::BankLetter => "bank_letter",
            BankMethod::BankStatement => "bank_statement",
        }
    }
}

/// One check of a bank detail verification. Interim closed set, as for
/// [`BankMethod`]. Labels sort in the order of the variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BankCheck {
    /// The holder on the document matches the grantee.
    HolderMatches,
    /// The IBAN on the document matches the entered one.
    IbanMatches,
}

impl BankCheck {
    /// Every check, in label order.
    pub const ALL: [BankCheck; 2] = [BankCheck::HolderMatches, BankCheck::IbanMatches];

    /// The wire spelling.
    pub const fn label(self) -> &'static str {
        match self {
            BankCheck::HolderMatches => "holder_matches",
            BankCheck::IbanMatches => "iban_matches",
        }
    }
}

/// The longest account holder name, in characters. Interim, no P- id.
pub const MAX_HOLDER_CHARS: usize = 140;

/// The longest hardship statement, in characters. Interim, no P- id.
pub const MAX_STATEMENT_CHARS: usize = 4000;

/// Whether `s` is a holder name: 1 to [`MAX_HOLDER_CHARS`] characters, no
/// control character, and no leading or trailing space.
pub fn holder_ok(s: &str) -> bool {
    let n = s.chars().count();
    (1..=MAX_HOLDER_CHARS).contains(&n) && s.trim() == s && !s.chars().any(char::is_control)
}

/// Whether `s` is a hardship statement: 1 to [`MAX_STATEMENT_CHARS`]
/// characters, with no control character but a line feed.
pub fn statement_ok(s: &str) -> bool {
    let n = s.chars().count();
    (1..=MAX_STATEMENT_CHARS).contains(&n)
        && !s.trim().is_empty()
        && !s.chars().any(|c| c.is_control() && c != '\n')
}

/// Whether `s` is an IBAN in its electronic form (ISO 13616): two capital
/// letters, two check digits, then 11 to 30 capitals or digits, 15 to 34
/// characters in all, whose MOD 97-10 remainder is 1. Fuzzed through the
/// fact body decoders. The country lengths are not checked (interim).
pub fn iban_ok(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 15 || b.len() > 34 {
        return false;
    }
    let (head, rest) = b.split_at(4);
    let shape = matches!(head, [a, c, d, e] if a.is_ascii_uppercase() && c.is_ascii_uppercase() && d.is_ascii_digit() && e.is_ascii_digit())
        && rest
            .iter()
            .all(|x| x.is_ascii_uppercase() || x.is_ascii_digit());
    if !shape {
        return false;
    }
    let mut rem: u32 = 0;
    for x in rest.iter().chain(head) {
        // A digit is its value, a capital A to Z is 10 to 35. Each step
        // stays below 97 * 100 + 35, far inside u32.
        let v = u32::from(x.wrapping_sub(if x.is_ascii_digit() { b'0' } else { 55 }));
        let scale = if v >= 10 { 100 } else { 10 };
        rem = rem.wrapping_mul(scale).wrapping_add(v).wrapping_rem(97);
    }
    rem == 1
}

fn labels_of<T: Copy + Ord>(
    v: &Value,
    all: &[T],
    label: fn(T) -> &'static str,
) -> Result<BTreeSet<T>, ProtoError> {
    let a = v.as_array().ok_or(ProtoError::Shape(BODY))?;
    let mut out = BTreeSet::new();
    let mut last: Option<T> = None;
    for item in a.iter() {
        let s = item.as_str().ok_or(ProtoError::Shape(BODY))?;
        let c = label_of(all, label, s)?;
        if last.is_some_and(|l| l >= c) {
            return Err(ProtoError::Shape(BODY));
        }
        last = Some(c);
        out.insert(c);
    }
    if out.is_empty() {
        return Err(ProtoError::Shape(BODY));
    }
    Ok(out)
}

/// The fact kind codes.
pub mod kind {
    /// `CountryStated` (P-17, NOTE 6).
    pub const COUNTRY_STATED: u16 = 1;
    /// `AffiliationDeclared`, with no class.
    pub const AFFILIATION_DECLARED: u16 = 2;
    /// `AdultAttestation` (NOTE 7).
    pub const ADULT_ATTESTATION: u16 = 3;
    /// `GuardianConsent` (I-18).
    pub const GUARDIAN_CONSENT: u16 = 4;
    /// `DocumentUpload`. Not a fact.
    pub const DOCUMENT_UPLOAD: u16 = 5;
    /// `VerificationRecorded` (design section 6.7).
    pub const VERIFICATION_RECORDED: u16 = 6;
    /// `ProximityListDeclared` (P-38).
    pub const PROXIMITY_LIST_DECLARED: u16 = 7;
    /// `ReviewerDeclaration` (Q31).
    pub const REVIEWER_DECLARATION: u16 = 8;
    /// `PartnerStaffDeclared`: an affiliation that may carry a P-13 class.
    pub const PARTNER_STAFF_DECLARED: u16 = 9;
    /// `RecordRelationship` (I-54).
    pub const RELATIONSHIP: u16 = 10;
    /// A consent withdrawal.
    pub const CONSENT_WITHDRAWN: u16 = 11;
    /// An attestation withdrawal.
    pub const ATTESTATION_WITHDRAWN: u16 = 12;
    /// An ended affiliation.
    pub const AFFILIATION_ENDED: u16 = 13;
    /// `BankDetails`: the payee bank details of a grant (I-33, I-86).
    pub const BANK_DETAILS: u16 = 14;
    /// `BankVerified`: a verification of one bank detail version.
    pub const BANK_VERIFIED: u16 = 15;
    /// `BankDispute`: a dispute opened or resolved.
    pub const BANK_DISPUTE: u16 = 16;
    /// `HardshipEvidence` (R-PR-04).
    pub const HARDSHIP_EVIDENCE: u16 = 17;
    /// `HardshipVerified` (R-PR-04).
    pub const HARDSHIP_VERIFIED: u16 = 18;
}

/// One fact write, typed. A withdrawal is a write too.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Fact {
    /// The P-17 country stated at submission. It never leaves the vault.
    CountryStated {
        /// The applicant lead.
        account: WireAccount,
        /// The programme.
        programme: WireProgramme,
        /// The country code.
        country: u16,
    },
    /// A declared affiliation, with the P-13 class it falls in, if any.
    AffiliationDeclared {
        /// The declaring account.
        account: WireAccount,
        /// The organisation.
        org: Org,
        /// The excluded class, which only a partner staff write carries.
        class: Option<WireClass>,
        /// Whether it is a `PartnerStaffDeclared` write (kind 9).
        partner_staff: bool,
    },
    /// An over-18 attestation.
    AdultAttestation {
        /// The attesting account.
        account: WireAccount,
        /// The instant from which it shows the account 18 or older.
        adult_from: i64,
    },
    /// A guardian's consent for a proposal.
    GuardianConsent {
        /// The proposal.
        proposal: WireProposal,
        /// The guardian's account.
        guardian: WireAccount,
    },
    /// A verification outcome, which gives the account its person.
    VerificationRecorded {
        /// The verified account.
        account: WireAccount,
        /// The person the verification shows: the `vault.identity` id that
        /// `fstp-vault` resolves from the identity match key (design
        /// section 6.4, Q17). The origin never decodes a verification.
        person: Person,
        /// The R-ID-02 record.
        record: VerificationRecord,
    },
    /// A P-38 proximity list. It replaces the earlier list with its id.
    ProximityListDeclared {
        /// The list.
        list: WireList,
        /// The organisations on it.
        orgs: BTreeSet<Org>,
    },
    /// A Judging-role holder's own employer and relatives. It replaces the
    /// holder's earlier declaration.
    ReviewerDeclaration {
        /// The reviewer.
        reviewer: WireAccount,
        /// The employer, if declared.
        employer: Option<Org>,
        /// The relatives, by person. Interim reading, pending Daniel: the
        /// origin body names them as identity ids until the relatives'
        /// attribute set is settled (see the module documentation).
        relatives: BTreeSet<Person>,
    },
    /// An I-54 relationship, ids only.
    Relationship {
        /// One account.
        a: WireAccount,
        /// The other account.
        b: WireAccount,
    },
    /// The withdrawal of a proposal's consent.
    ConsentWithdrawn {
        /// The proposal.
        proposal: WireProposal,
    },
    /// The withdrawal of an attestation.
    AttestationWithdrawn {
        /// The account.
        account: WireAccount,
    },
    /// The end of a declared affiliation.
    AffiliationEnded {
        /// The account.
        account: WireAccount,
        /// The organisation.
        org: Org,
    },
    /// A new version of the payee bank details of a grant. Every write,
    /// the first included, starts the I-33 hold. The details never leave
    /// the vault origin (I-86).
    BankDetails {
        /// The grant.
        grant: WireProposal,
        /// The writer, the grant's lead.
        account: WireAccount,
        /// When the vault took the write, in UTC microseconds. The vault
        /// sets it, never the browser.
        at: i64,
        /// The account holder name.
        holder: String,
        /// The IBAN, electronic form.
        iban: String,
    },
    /// A verification of one bank detail version (I-33, R-PR-05).
    BankVerified {
        /// The grant.
        grant: WireProposal,
        /// The version verified: the count of bank writes of the grant.
        version: u64,
        /// The verifier, never the writer.
        verifier: WireAccount,
        /// When the vault took it, in UTC microseconds.
        at: i64,
        /// The method.
        method: BankMethod,
        /// The checks performed. At least one.
        checks: BTreeSet<BankCheck>,
    },
    /// A dispute of the bank details of a grant, opened or resolved.
    BankDispute {
        /// The grant.
        grant: WireProposal,
        /// The lead who opens it, or the verifier who resolves it.
        account: WireAccount,
        /// Whether it opens (true) or resolves (false) the dispute.
        open: bool,
    },
    /// Hardship evidence for a grant (R-PR-04).
    HardshipEvidence {
        /// The grant.
        grant: WireProposal,
        /// The opaque reference. The vault sets it from the ticket id.
        evidence: WireEvidence,
        /// The submitter.
        account: WireAccount,
        /// The statement of hardship.
        statement: String,
    },
    /// A verification of hardship evidence (R-PR-04).
    HardshipVerified {
        /// The grant.
        grant: WireProposal,
        /// The evidence.
        evidence: WireEvidence,
        /// The verifier, never the submitter.
        verifier: WireAccount,
        /// When the vault took it, in UTC microseconds.
        at: i64,
    },
}

const BODY: &str = "fact body";

/// The grant a bank or hardship fact is about, if it is one.
pub fn grant_of(f: &Fact) -> Option<WireProposal> {
    match f {
        Fact::BankDetails { grant, .. }
        | Fact::BankVerified { grant, .. }
        | Fact::BankDispute { grant, .. }
        | Fact::HardshipEvidence { grant, .. }
        | Fact::HardshipVerified { grant, .. } => Some(*grant),
        _ => None,
    }
}

/// The fact an origin write of kind `code` carries in `body`, received at
/// `now` under the ticket id `ticket_id`.
///
/// The vault sets the members the browser must not choose: `at` of a bank
/// write or verification and of a hardship verification, `version` of a
/// bank verification, which is the latest version in `latest`, and
/// `evidence` of a hardship submission, which is the ticket id. A body that names
/// one of them itself is refused, so no browser back-dates a write.
/// Every other kind decodes as [`decode_fact`] does.
///
/// # Errors
///
/// As [`decode_fact`].
pub fn origin_fact(
    code: u16,
    body: &[u8],
    now: i64,
    ticket_id: [u8; 16],
    latest: &crate::eval::Facts,
) -> Result<Fact, ProtoError> {
    let at = || json::int_json(now, BODY);
    let mut v = parse_canonical(body, &limits())?;
    let Value::Object(o) = &mut v else {
        return Err(ProtoError::Shape(BODY));
    };
    let stamped: Vec<(&str, Value)> = match code {
        kind::BANK_DETAILS | kind::HARDSHIP_VERIFIED => vec![("at", at()?)],
        kind::BANK_VERIFIED => {
            let grant = WireProposal(json::id(o, "grant", BODY)?);
            let version = latest
                .bank_of(grant)
                .map(|b| b.version)
                .ok_or(ProtoError::Shape(BODY))?;
            vec![("at", at()?), ("version", json::uint_json(version, BODY)?)]
        }
        kind::HARDSHIP_EVIDENCE => {
            vec![("evidence", json::id_json(u128::from_be_bytes(ticket_id)))]
        }
        _ => return decode_fact(code, body),
    };
    for (name, value) in stamped {
        if o.get(name).is_some() {
            return Err(ProtoError::Shape(BODY));
        }
        o.insert(name, value);
    }
    fact_from_value(code, &v)
}

impl Fact {
    /// The kind code.
    pub const fn kind(&self) -> u16 {
        match self {
            Fact::CountryStated { .. } => kind::COUNTRY_STATED,
            Fact::AffiliationDeclared {
                partner_staff: false,
                ..
            } => kind::AFFILIATION_DECLARED,
            Fact::AffiliationDeclared {
                partner_staff: true,
                ..
            } => kind::PARTNER_STAFF_DECLARED,
            Fact::AdultAttestation { .. } => kind::ADULT_ATTESTATION,
            Fact::GuardianConsent { .. } => kind::GUARDIAN_CONSENT,
            Fact::VerificationRecorded { .. } => kind::VERIFICATION_RECORDED,
            Fact::ProximityListDeclared { .. } => kind::PROXIMITY_LIST_DECLARED,
            Fact::ReviewerDeclaration { .. } => kind::REVIEWER_DECLARATION,
            Fact::Relationship { .. } => kind::RELATIONSHIP,
            Fact::ConsentWithdrawn { .. } => kind::CONSENT_WITHDRAWN,
            Fact::AttestationWithdrawn { .. } => kind::ATTESTATION_WITHDRAWN,
            Fact::AffiliationEnded { .. } => kind::AFFILIATION_ENDED,
            Fact::BankDetails { .. } => kind::BANK_DETAILS,
            Fact::BankVerified { .. } => kind::BANK_VERIFIED,
            Fact::BankDispute { .. } => kind::BANK_DISPUTE,
            Fact::HardshipEvidence { .. } => kind::HARDSHIP_EVIDENCE,
            Fact::HardshipVerified { .. } => kind::HARDSHIP_VERIFIED,
        }
    }

    /// The account the stored fact row names as its subject: the account
    /// it is about, or the guardian for a consent. A proximity list names
    /// no account and has none.
    pub fn subject(&self) -> Option<WireAccount> {
        match self {
            Fact::CountryStated { account, .. }
            | Fact::AffiliationDeclared { account, .. }
            | Fact::AdultAttestation { account, .. }
            | Fact::VerificationRecorded { account, .. }
            | Fact::AttestationWithdrawn { account }
            | Fact::AffiliationEnded { account, .. }
            | Fact::BankDetails { account, .. }
            | Fact::BankDispute { account, .. }
            | Fact::HardshipEvidence { account, .. } => Some(*account),
            Fact::BankVerified { verifier, .. } | Fact::HardshipVerified { verifier, .. } => {
                Some(*verifier)
            }
            Fact::GuardianConsent { guardian, .. } => Some(*guardian),
            Fact::ReviewerDeclaration { reviewer, .. } => Some(*reviewer),
            Fact::Relationship { a, .. } => Some(*a),
            Fact::ProximityListDeclared { .. } | Fact::ConsentWithdrawn { .. } => None,
        }
    }

    /// The canonical JSON value of the body.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Shape`] for a class on a plain affiliation, or an
    /// instant beyond 2^53 - 1.
    pub fn body_value(&self) -> Result<Value, ProtoError> {
        use json::{id_json, id_list_json, int_json, obj, opt_id_json, uint_json};
        match self {
            Fact::CountryStated {
                account,
                programme,
                country,
            } => obj(vec![
                ("account", id_json(account.0)),
                ("country", uint_json(u64::from(*country), BODY)?),
                ("programme", id_json(programme.0)),
            ]),
            Fact::AffiliationDeclared {
                account,
                org,
                class,
                partner_staff,
            } => {
                if class.is_some() && !partner_staff {
                    return Err(ProtoError::Shape(BODY));
                }
                obj(vec![
                    ("account", id_json(account.0)),
                    ("class", opt_id_json(class.map(|c| c.0))),
                    ("org", id_json(org.0)),
                ])
            }
            Fact::AdultAttestation {
                account,
                adult_from,
            } => obj(vec![
                ("account", id_json(account.0)),
                ("adult_from", int_json(*adult_from, BODY)?),
            ]),
            Fact::GuardianConsent { proposal, guardian } => obj(vec![
                ("guardian", id_json(guardian.0)),
                ("proposal", id_json(proposal.0)),
            ]),
            Fact::VerificationRecorded {
                account,
                person,
                record,
            } => {
                if record.checks.is_empty() {
                    return Err(ProtoError::Shape(BODY));
                }
                let checks = record
                    .checks
                    .iter()
                    .map(|c| Value::String(c.label().to_owned()))
                    .collect();
                obj(vec![
                    ("account", id_json(account.0)),
                    ("at", int_json(record.at, BODY)?),
                    ("checks", Value::Array(checks)),
                    (
                        "document_type",
                        Value::String(record.document_type.label().to_owned()),
                    ),
                    ("identity", id_json(person.0)),
                    ("method", Value::String(record.method.label().to_owned())),
                    ("verifier", id_json(record.verifier.0)),
                ])
            }
            Fact::ProximityListDeclared { list, orgs } => obj(vec![
                ("list", id_json(list.0)),
                ("orgs", id_list_json(orgs.iter().map(|o| o.0))),
            ]),
            Fact::ReviewerDeclaration {
                reviewer,
                employer,
                relatives,
            } => obj(vec![
                ("employer", opt_id_json(employer.map(|e| e.0))),
                ("relatives", id_list_json(relatives.iter().map(|p| p.0))),
                ("reviewer", id_json(reviewer.0)),
            ]),
            Fact::Relationship { a, b } => obj(vec![("a", id_json(a.0)), ("b", id_json(b.0))]),
            Fact::ConsentWithdrawn { proposal } => obj(vec![("proposal", id_json(proposal.0))]),
            Fact::AttestationWithdrawn { account } => obj(vec![("account", id_json(account.0))]),
            Fact::AffiliationEnded { account, org } => obj(vec![
                ("account", id_json(account.0)),
                ("org", id_json(org.0)),
            ]),
            Fact::BankDetails {
                grant,
                account,
                at,
                holder,
                iban,
            } => {
                if !holder_ok(holder) || !iban_ok(iban) {
                    return Err(ProtoError::Shape(BODY));
                }
                obj(vec![
                    ("account", id_json(account.0)),
                    ("at", int_json(*at, BODY)?),
                    ("grant", id_json(grant.0)),
                    ("holder", Value::String(holder.clone())),
                    ("iban", Value::String(iban.clone())),
                ])
            }
            Fact::BankVerified {
                grant,
                version,
                verifier,
                at,
                method,
                checks,
            } => {
                if checks.is_empty() {
                    return Err(ProtoError::Shape(BODY));
                }
                let checks = checks
                    .iter()
                    .map(|c| Value::String(c.label().to_owned()))
                    .collect();
                obj(vec![
                    ("at", int_json(*at, BODY)?),
                    ("checks", Value::Array(checks)),
                    ("grant", id_json(grant.0)),
                    ("method", Value::String(method.label().to_owned())),
                    ("verifier", id_json(verifier.0)),
                    ("version", uint_json(*version, BODY)?),
                ])
            }
            Fact::BankDispute {
                grant,
                account,
                open,
            } => obj(vec![
                ("account", id_json(account.0)),
                ("grant", id_json(grant.0)),
                ("open", Value::Bool(*open)),
            ]),
            Fact::HardshipEvidence {
                grant,
                evidence,
                account,
                statement,
            } => {
                if !statement_ok(statement) {
                    return Err(ProtoError::Shape(BODY));
                }
                obj(vec![
                    ("account", id_json(account.0)),
                    ("evidence", id_json(evidence.0)),
                    ("grant", id_json(grant.0)),
                    ("statement", Value::String(statement.clone())),
                ])
            }
            Fact::HardshipVerified {
                grant,
                evidence,
                verifier,
                at,
            } => obj(vec![
                ("at", int_json(*at, BODY)?),
                ("evidence", id_json(evidence.0)),
                ("grant", id_json(grant.0)),
                ("verifier", id_json(verifier.0)),
            ]),
        }
    }

    /// The canonical body bytes.
    ///
    /// # Errors
    ///
    /// As [`Fact::body_value`].
    pub fn body(&self) -> Result<Vec<u8>, ProtoError> {
        json::to_canonical(&self.body_value()?)
    }
}

/// Decodes the body value `v` of a fact of kind `code`.
///
/// # Errors
///
/// [`ProtoError::Shape`] for an unknown kind, members of another kind, or
/// a class on a plain affiliation.
pub fn fact_from_value(code: u16, v: &Value) -> Result<Fact, ProtoError> {
    use json::{id, id_set, int, object, opt_id, small};
    let account = |o: &fstp_json::Object, name: &str| id(o, name, BODY).map(WireAccount);
    Ok(match code {
        kind::COUNTRY_STATED => {
            let o = object(v, &["account", "country", "programme"], BODY)?;
            Fact::CountryStated {
                account: account(o, "account")?,
                programme: WireProgramme(id(o, "programme", BODY)?),
                country: small(o, "country", BODY)?,
            }
        }
        kind::AFFILIATION_DECLARED | kind::PARTNER_STAFF_DECLARED => {
            let o = object(v, &["account", "class", "org"], BODY)?;
            let partner_staff = code == kind::PARTNER_STAFF_DECLARED;
            let class = opt_id(o, "class", BODY)?.map(WireClass);
            if class.is_some() && !partner_staff {
                return Err(ProtoError::Shape(BODY));
            }
            Fact::AffiliationDeclared {
                account: account(o, "account")?,
                org: Org(id(o, "org", BODY)?),
                class,
                partner_staff,
            }
        }
        kind::ADULT_ATTESTATION => {
            let o = object(v, &["account", "adult_from"], BODY)?;
            Fact::AdultAttestation {
                account: account(o, "account")?,
                adult_from: int(o, "adult_from", BODY)?,
            }
        }
        kind::GUARDIAN_CONSENT => {
            let o = object(v, &["guardian", "proposal"], BODY)?;
            Fact::GuardianConsent {
                proposal: WireProposal(id(o, "proposal", BODY)?),
                guardian: account(o, "guardian")?,
            }
        }
        kind::VERIFICATION_RECORDED => {
            let o = object(
                v,
                &[
                    "account",
                    "at",
                    "checks",
                    "document_type",
                    "identity",
                    "method",
                    "verifier",
                ],
                BODY,
            )?;
            let label = |name: &str| json::string(o, name, BODY);
            Fact::VerificationRecorded {
                account: account(o, "account")?,
                person: Person(id(o, "identity", BODY)?),
                record: VerificationRecord {
                    method: label_of(
                        &VerificationMethod::ALL,
                        VerificationMethod::label,
                        label("method")?,
                    )?,
                    document_type: label_of(
                        &DocumentType::ALL,
                        DocumentType::label,
                        label("document_type")?,
                    )?,
                    checks: checks_of(json::member(o, "checks", BODY)?)?,
                    at: int(o, "at", BODY)?,
                    verifier: account(o, "verifier")?,
                },
            }
        }
        kind::PROXIMITY_LIST_DECLARED => {
            let o = object(v, &["list", "orgs"], BODY)?;
            Fact::ProximityListDeclared {
                list: WireList(id(o, "list", BODY)?),
                orgs: id_set(o, "orgs", BODY, Org)?,
            }
        }
        kind::REVIEWER_DECLARATION => {
            let o = object(v, &["employer", "relatives", "reviewer"], BODY)?;
            Fact::ReviewerDeclaration {
                reviewer: account(o, "reviewer")?,
                employer: opt_id(o, "employer", BODY)?.map(Org),
                relatives: id_set(o, "relatives", BODY, Person)?,
            }
        }
        kind::RELATIONSHIP => {
            let o = object(v, &["a", "b"], BODY)?;
            Fact::Relationship {
                a: account(o, "a")?,
                b: account(o, "b")?,
            }
        }
        kind::CONSENT_WITHDRAWN => {
            let o = object(v, &["proposal"], BODY)?;
            Fact::ConsentWithdrawn {
                proposal: WireProposal(id(o, "proposal", BODY)?),
            }
        }
        kind::ATTESTATION_WITHDRAWN => {
            let o = object(v, &["account"], BODY)?;
            Fact::AttestationWithdrawn {
                account: account(o, "account")?,
            }
        }
        kind::AFFILIATION_ENDED => {
            let o = object(v, &["account", "org"], BODY)?;
            Fact::AffiliationEnded {
                account: account(o, "account")?,
                org: Org(id(o, "org", BODY)?),
            }
        }
        kind::BANK_DETAILS => {
            let o = object(v, &["account", "at", "grant", "holder", "iban"], BODY)?;
            let holder = json::string(o, "holder", BODY)?;
            let iban = json::string(o, "iban", BODY)?;
            if !holder_ok(holder) || !iban_ok(iban) {
                return Err(ProtoError::Shape(BODY));
            }
            Fact::BankDetails {
                grant: WireProposal(id(o, "grant", BODY)?),
                account: account(o, "account")?,
                at: int(o, "at", BODY)?,
                holder: holder.to_owned(),
                iban: iban.to_owned(),
            }
        }
        kind::BANK_VERIFIED => {
            let o = object(
                v,
                &["at", "checks", "grant", "method", "verifier", "version"],
                BODY,
            )?;
            Fact::BankVerified {
                grant: WireProposal(id(o, "grant", BODY)?),
                version: json::uint(o, "version", BODY)?,
                verifier: account(o, "verifier")?,
                at: int(o, "at", BODY)?,
                method: label_of(
                    &BankMethod::ALL,
                    BankMethod::label,
                    json::string(o, "method", BODY)?,
                )?,
                checks: labels_of(
                    json::member(o, "checks", BODY)?,
                    &BankCheck::ALL,
                    BankCheck::label,
                )?,
            }
        }
        kind::BANK_DISPUTE => {
            let o = object(v, &["account", "grant", "open"], BODY)?;
            Fact::BankDispute {
                grant: WireProposal(id(o, "grant", BODY)?),
                account: account(o, "account")?,
                open: json::boolean(o, "open", BODY)?,
            }
        }
        kind::HARDSHIP_EVIDENCE => {
            let o = object(v, &["account", "evidence", "grant", "statement"], BODY)?;
            let statement = json::string(o, "statement", BODY)?;
            if !statement_ok(statement) {
                return Err(ProtoError::Shape(BODY));
            }
            Fact::HardshipEvidence {
                grant: WireProposal(id(o, "grant", BODY)?),
                evidence: WireEvidence(id(o, "evidence", BODY)?),
                account: account(o, "account")?,
                statement: statement.to_owned(),
            }
        }
        kind::HARDSHIP_VERIFIED => {
            let o = object(v, &["at", "evidence", "grant", "verifier"], BODY)?;
            Fact::HardshipVerified {
                grant: WireProposal(id(o, "grant", BODY)?),
                evidence: WireEvidence(id(o, "evidence", BODY)?),
                verifier: account(o, "verifier")?,
                at: int(o, "at", BODY)?,
            }
        }
        _ => return Err(ProtoError::Shape("fact kind")),
    })
}

/// Decodes a fact body of kind `code`: the one canonical spelling of that
/// kind's members.
///
/// # Errors
///
/// [`ProtoError::Json`], [`ProtoError::NotCanonical`] or
/// [`ProtoError::Shape`].
pub fn decode_fact(code: u16, body: &[u8]) -> Result<Fact, ProtoError> {
    let v = parse_canonical(body, &limits())?;
    fact_from_value(code, &v)
}
