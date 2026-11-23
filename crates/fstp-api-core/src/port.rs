//! The ports M4 needs from M3 (M4 design section 6.1).
//!
//! M4 is built against these traits. `fstp-api-testkit` holds a fake for
//! each, so M4 lanes start before M3 lands. If the M3 design names them
//! differently, only `crates/fstp-cell/src/routes/m4.rs` changes. Only
//! this file may name [`CellPorts`], [`AsyncEngine`] or a port trait in a
//! public item (layering rule A2). Adapters never name this module (rule
//! A2b).
//!
//! Ownership: lane W0 wrote this file, and the lead holds it after W0
//! (design section 13). The value types follow section 6.1. Where the
//! design leaves a type open, it is a W0 placeholder, and a lane that
//! needs it asks the lead.
//!
//! Every answer a vault port gives, dry runs and previews included, is
//! recorded through [`VaultAudit`] (`overview.md` NOTE 5).

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::Arc;

use fstp_domain::id::{AccountId, OrganisationId, ProgrammeId, ProposalId, VaultEpoch};
use fstp_domain::oracle::{Answer, OracleDown, Query};
use fstp_domain::refusal::Refusal;
use fstp_domain::time::Timestamp;
use fstp_domain::{Ctx, Via};
use fstp_engine::EngineState;
use fstp_ledger::Seq;

use crate::{ActionDigest, ApiCore, Credential, DispatchFuture, Op, RequestHead, RightsFuture};

macro_rules! port_id {
    ($($(#[$doc:meta])* $n:ident),* $(,)?) => { $(
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $n(u128);

        impl $n {
            /// The id with raw value `r`, as drawn by the shell.
            pub const fn from_raw(r: u128) -> Self {
                Self(r)
            }

            /// The raw value.
            pub const fn raw(self) -> u128 {
                self.0
            }
        }
    )* };
}

port_id!(
    /// An M3 session.
    SessionId,
    /// An OAuth client of an agent.
    AgentClientId,
    /// A pending action (I-85).
    PendingId,
    /// An account recovery case.
    RecoveryId,
    /// A break-glass request (SoD-08).
    BreakGlassId,
    /// A second tenant admin approval (SoD-07).
    ApprovalId,
    /// A tenant, in the control plane.
    TenantId,
    /// A pre-check run (M7 design section 4).
    PrecheckRunId,
);

/// A port that could not answer. Every caller fails closed on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortError {
    /// The port is unavailable.
    Unavailable,
    /// The port refused the request.
    Refused,
}

/// A login method (`authentication.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoginMethod {
    /// A passkey.
    Passkey,
    /// A magic link.
    MagicLink,
    /// OPAQUE.
    Opaque,
    /// The EUDI Wallet.
    EudiWallet,
}

/// What an M3 session attests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionPrincipal {
    /// The account.
    pub account: AccountId,
    /// The session.
    pub session: SessionId,
    /// How the session logged in.
    pub method: LoginMethod,
    /// Whether the method is phishing-resistant (I-77).
    pub phishing_resistant: bool,
    /// Whether the attested tenant admin set holds the account.
    pub tenant_admin: bool,
}

/// A step-up challenge bound to one action digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepUpChallenge {
    /// The digest the challenge is bound to.
    pub action: ActionDigest,
    /// The WebAuthn challenge bytes.
    pub challenge: Vec<u8>,
}

/// A reference to a finished step-up, recorded with the action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StepUpRef(pub u128);

/// A fresh step-up proof for one digest and session. Consumed on use.
#[derive(Debug, PartialEq, Eq)]
pub struct StepUpProof {
    /// The step-up this proof comes from.
    pub step_up: StepUpRef,
    /// The digest it authorises.
    pub action: ActionDigest,
}

/// A passkey registration of `me.add_passkey` (R-LG-04, design section
/// 8.3): the browser's response to the creation options the cell's
/// `/auth/passkeys/options` route issued, as that route's body form names
/// it. The cell's own passkey ceremony verifies it, through the sessions
/// admin port, so no second ceremony exists in the API core.
#[derive(Clone, PartialEq, Eq)]
pub struct PasskeyRegistration {
    /// The id of the single-use creation challenge.
    pub challenge_id: [u8; 16],
    /// The client data JSON bytes.
    pub client_data_json: Vec<u8>,
    /// The attestation object bytes.
    pub attestation_object: Vec<u8>,
}

impl std::fmt::Debug for PasskeyRegistration {
    /// The lengths only: the bytes name a new credential.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyRegistration")
            .field("client_data_json", &self.client_data_json.len())
            .field("attestation_object", &self.attestation_object.len())
            .finish_non_exhaustive()
    }
}

/// The user's approval of an agent consent (`agents.consent`, ADR-013
/// "Consent"). The handle names a consent of the `fstp-oauth` authorize
/// flow. The API core checked the session and took a fresh step-up bound
/// to this request, whose digest covers the handle (I-78). The token port
/// attests that step-up to the authorisation server, bound to the
/// consent's own digest.
#[derive(Clone, PartialEq, Eq)]
pub struct ConsentApproval {
    /// The consenting account.
    pub account: AccountId,
    /// The consent handle, a secret of the user's browser.
    pub handle: String,
    /// How the approving session logged in. The grant keeps it.
    pub method: LoginMethod,
    /// The step-up the API core took for this request.
    pub step_up: StepUpRef,
    /// The instant of the approval.
    pub at: Timestamp,
}

impl std::fmt::Debug for ConsentApproval {
    /// Never shows the handle.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsentApproval")
            .field("account", &self.account)
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}

/// No fresh step-up proof exists for the digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepUpRequired;

/// The secret token of an invitation link (J2, lane inv).
///
/// The API core draws it through `fstp-crypto` and hands it to M3 only,
/// inside an [`InviteKind`]. The ledger holds only its digest. Its
/// `Debug` never shows the bytes, so no log line carries it in clear.
#[derive(Clone, PartialEq, Eq)]
pub struct LinkToken([u8; 32]);

impl LinkToken {
    /// The token with the drawn bytes `b`.
    pub const fn from_bytes(b: [u8; 32]) -> LinkToken {
        LinkToken(b)
    }

    /// The token's bytes.
    pub const fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The token as the link carries it: 64 lowercase hexadecimal digits,
    /// the spelling the `invitation_token` route parameter takes.
    pub fn hex(&self) -> String {
        crate::action::hex(&self.0)
    }
}

impl std::fmt::Debug for LinkToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LinkToken(..)")
    }
}

/// What an invitation is for, as M3 receives it to mail the link and
/// bind the address to the enrolled account (J2, lane inv).
///
/// Interim, pending Daniel and the lead: the test author of lane inv
/// wrote this shape before the production code. The email goes to M3
/// and the text store only, never to the ledger (I-86). Its `Debug`
/// shows neither the email nor the token.
#[derive(Clone, PartialEq, Eq)]
pub enum InviteKind {
    /// An invitation to a programme role (`creator.invite`).
    ProgrammeRole {
        /// The programme.
        programme: ProgrammeId,
        /// The invitation of the creator draft.
        invitation: fstp_creator::InvitationId,
        /// The invited role.
        role: fstp_domain::roles::Role,
        /// The address M3 mails the link to.
        email: String,
        /// The link token.
        token: LinkToken,
    },
    /// The invitation of a second tenant admin (`tenant.invite_admin`,
    /// SoD-07, ADR-026 record of lane L18). The ledger holds the
    /// invitation with the invitee and the token's digest.
    TenantAdmin {
        /// The tenant admin invitation.
        invitation: fstp_tenant::InvitationId,
        /// The invitee, a new account the API core drew.
        invitee: AccountId,
        /// The address M3 mails the link to.
        email: String,
        /// The link token.
        token: LinkToken,
    },
}

impl std::fmt::Debug for InviteKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InviteKind::ProgrammeRole {
                programme,
                invitation,
                role,
                ..
            } => f
                .debug_struct("ProgrammeRole")
                .field("programme", programme)
                .field("invitation", invitation)
                .field("role", role)
                .finish_non_exhaustive(),
            InviteKind::TenantAdmin {
                invitation,
                invitee,
                ..
            } => f
                .debug_struct("TenantAdmin")
                .field("invitation", invitation)
                .field("invitee", invitee)
                .finish_non_exhaustive(),
        }
    }
}

/// An invitation link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitationLink(pub String);

/// A pseudonymous display handle. Never an email.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayHandle(pub String);

/// A fact that only the vault may receive. It has no `Debug`, `Display`,
/// `ToJson` or `Clone`, and no accessor here. Only the M3 vault client
/// consumes it, through the W6 adapter.
pub struct VaultBound<T>(T);

impl<T> VaultBound<T> {
    /// Wraps a fact for the vault.
    pub fn new(fact: T) -> VaultBound<T> {
        VaultBound(fact)
    }

    /// The fact, for the vault client that delivers it. Only an
    /// implementation of [`Vault`] calls it. The API core never does
    /// (I-86, R-NG-01).
    pub fn into_vault(self) -> T {
        self.0
    }
}

/// A vault receipt for one intake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt(pub u128);

/// An ISO 3166-1 alpha-2 country code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CountryCode(pub [u8; 2]);

/// Declared affiliations of one account, as the lead wrote them (R-NG-01).
///
/// Interim reading of lane mapp, pending Daniel: free text of 1 to
/// [`Affiliations::MAX_LEN`] bytes with a character other than white
/// space, read by the vault only. Like [`VaultBound`], it has no `Debug`,
/// `Clone` or accessor here except for the vault client.
pub struct Affiliations(String);

impl Affiliations {
    /// The longest declaration, in bytes.
    pub const MAX_LEN: usize = 4096;

    /// The declaration `text`, or `None` when it is blank or too long.
    pub fn new(text: &str) -> Option<Affiliations> {
        let fits = text.len() <= Affiliations::MAX_LEN;
        (fits && !text.trim().is_empty()).then(|| Affiliations(text.to_owned()))
    }

    /// The text, for the vault client that delivers it (I-86).
    pub fn into_text(self) -> String {
        self.0
    }
}

/// A date of birth the lead states at submission, to the vault only
/// (Q23 B, design section 15.0, 2026-11-06; R-ID-04, I-18, I-86).
///
/// It has no `Debug`, `Display`, `Clone` or JSON form, so no log, reply
/// or ledger record can carry it. Only the vault reads it, through
/// [`BirthDate::adult_from`].
///
/// TODO(legal): L-02, the legal basis for collecting the date of birth
/// before NEGOTIATION, and whether Article 8 GDPR applies to it.
pub struct BirthDate {
    year: i64,
    month: i64,
    day: i64,
}

impl BirthDate {
    /// The date `YYYY-MM-DD`: a real calendar day from 1900-01-01 to
    /// 9999-12-31, ASCII digits only, or `None`.
    pub fn parse(s: &str) -> Option<BirthDate> {
        let b = s.as_bytes();
        if b.len() != 10 || b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') {
            return None;
        }
        let num = |r: core::ops::Range<usize>| -> Option<i64> {
            let part = s.get(r)?;
            if !part.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            part.parse().ok()
        };
        let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
        if year < 1900 || !(1..=12).contains(&month) || day < 1 || day > month_len(year, month)? {
            return None;
        }
        Some(BirthDate { year, month, day })
    }

    /// The instant from which the person is 18 in every time zone: noon
    /// UTC of the 18th birthday, which is the start of that day at
    /// UTC-12. A birthday of 29 February falls on 1 March in a year
    /// without it. The vault compares it with a call deadline and answers
    /// one bit (R-ID-04, state-machine NOTE 14). `None` past year 9999.
    ///
    /// Interim reading of lane mapp, pending Daniel: the latest zone
    /// decides, so no lead counts as 18 before the birthday anywhere.
    pub fn adult_from(&self) -> Option<Timestamp> {
        let year = self.year.checked_add(18)?;
        if year > 9999 {
            return None;
        }
        let (month, day) = if self.day > month_len(year, self.month)? {
            (3, 1)
        } else {
            (self.month, self.day)
        };
        let days = days_from_civil(year, month, day)?;
        let micros = days
            .checked_mul(86_400)?
            .checked_add(12 * 3_600)?
            .checked_mul(1_000_000)?;
        Some(Timestamp::from_micros(micros))
    }
}

/// The length of `month` of `year`, or `None` for no month.
fn month_len(year: i64, month: i64) -> Option<i64> {
    let leap = (year.rem_euclid(4) == 0 && year.rem_euclid(100) != 0) || year.rem_euclid(400) == 0;
    let lens = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    lens.get(usize::try_from(month.checked_sub(1)?).ok()?)
        .copied()
}

/// Days from 1970-01-01 to a valid civil date, on integers only.
fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    let (yy, mm) = if m <= 2 {
        (y.checked_sub(1)?, m.checked_add(9)?)
    } else {
        (y, m.checked_sub(3)?)
    };
    let era = yy.div_euclid(400);
    let yoe = yy.checked_sub(era.checked_mul(400)?)?;
    let doy = mm
        .checked_mul(153)?
        .checked_add(2)?
        .div_euclid(5)
        .checked_add(d.checked_sub(1)?)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe.div_euclid(4))?
        .checked_sub(yoe.div_euclid(100))?
        .checked_add(doy)?;
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
}

/// Why a verification runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerificationPurpose {
    /// Applicant identity.
    Applicant,
    /// Tenant admin identity, for the I-67 Sybil check (design section 6.1, item 13).
    AdminIdentity,
    /// The identity of an invitee who accepted a Drafting or Judging role,
    /// for SoD-09 (J2, `people.begin_verification`, lane inv).
    ProgrammeRole,
    /// The guardian's identity and consent for a minor-flagged proposal,
    /// on the vault origin (I-18, R-NG-01 NOTE, state-machine NOTE 14).
    /// The redirect is the vault's write page with the ticket in the
    /// fragment (M3 design section 6.5).
    GuardianConsent(ProposalId),
    /// M5 lane L-API (I-33, I-86): the lead writes the payee bank details
    /// of a grant on the vault origin.
    BankDetails(ProposalId),
    /// The finance approver verifies the latest bank details (I-33).
    BankVerification(ProposalId),
    /// The lead disputes the bank details (I-33).
    BankDispute(ProposalId),
    /// The payment releaser views the payee of one released request
    /// (M5 design reading 6).
    BankView(fstp_domain::id::RequestId),
    /// The lead submits hardship evidence (R-PR-04).
    HardshipEvidence(ProposalId),
    /// The finance approver verifies hardship evidence (R-PR-04).
    HardshipVerification(ProposalId),
    /// ADR-023 (I-17 as amended 2026-11-15): the FSTP coordinator of
    /// `programme` sees who `subject` is, on the vault origin's release
    /// page. The cell recorded `PartyUnmasked` first. The ticket names the
    /// subject's account, the party kind and the programme, never an
    /// identity attribute.
    Unmask {
        /// The programme.
        programme: ProgrammeId,
        /// The account behind the party.
        subject: AccountId,
        /// The party kind.
        party: fstp_domain::unmask::PartyKind,
    },
}

/// Where the browser goes to verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationRedirect(pub String);

/// The P-13 exclusion classes of a programme.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExclusionClasses(pub BTreeSet<fstp_domain::id::ClassId>);

/// The operation name recorded in audit entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpName(pub &'static str);

/// What an execution carries besides the command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecMeta {
    /// The channel.
    pub via: Via,
    /// The session, if any.
    pub session: Option<SessionId>,
    /// The agent client, for MCP calls.
    pub agent: Option<AgentClientId>,
    /// The operation.
    pub op: OpName,
    /// The request digest.
    pub request: ActionDigest,
    /// The step-up, for high-risk operations.
    pub step_up: Option<StepUpRef>,
    /// The pending action this execution confirms.
    pub pending: Option<PendingId>,
    /// The second tenant admin of a recorded approval (SoD-07).
    pub second_tenant_admin: Option<AccountId>,
}

/// Why an execution failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecError {
    /// The domain refused the command.
    Refused(Refusal),
    /// A port failed. Nothing was appended.
    Port(PortError),
}

/// An open database transaction of the cell.
///
/// W0 placeholder with no fields. The lead writes it with the M3 seam.
pub struct Tx {
    _w0: (),
}

/// The outcome an audit entry records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The call succeeded.
    Accepted,
    /// The call was refused, with the rule text.
    Refused(&'static str),
}

/// One audit entry per call, accepted or refused (I-24).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    /// The account, if any.
    pub actor: Option<AccountId>,
    /// The channel.
    pub via: Via,
    /// The agent client, for MCP calls.
    pub agent: Option<AgentClientId>,
    /// The operation.
    pub op: OpName,
    /// The outcome.
    pub outcome: Outcome,
    /// The request digest.
    pub request: ActionDigest,
    /// The step-up, for high-risk operations.
    pub step_up: Option<StepUpRef>,
}

/// The class of a stored text, which picks its data key (ADR-004, ADR-007).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TextClass {
    /// Proposal and review text.
    Confidential,
    /// Text approved for public pages.
    Public,
}

/// Who owns a stored text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TextOwner {
    /// A proposal.
    Proposal(ProposalId),
    /// A programme.
    Programme(ProgrammeId),
    /// The tenant, for its onboarding texts such as the data protection
    /// contact (Q22, lane m4tenant).
    Tenant,
    /// An account, for its own display name (SA-11). An account erasure
    /// erases every text its account owns (ADR-007).
    Account(AccountId),
}

/// A reference to a stored text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TextRef(pub u128);

/// A reference to a stored public text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicTextRef(pub u128);

// A text read takes the clearance a read obtained, `fstp_access::ReadClearance`,
// which a store checks before it releases text. Only
// `fstp_access::authorize_read` builds one (Daniel, 2026-11-13: the
// knock-out reason is read through the text store with a clearance). It is
// named by path, not re-exported (M4 design section 1.3 rule A2).
use fstp_access::ReadClearance;

/// Who owns a stored blob, such as an uploaded import document (R-PG-02).
///
/// W0 placeholder. The lead writes it with the M3 seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlobOwner {
    /// A programme, for its import documents.
    Programme(ProgrammeId),
    /// The tenant's brand assets: the checked logos of ADR-030. They are
    /// public data, shown on public pages.
    Brand,
}

/// A content address of a stored blob: the SHA-256 of its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlobRef(pub [u8; 32]);

/// Who owns sealed bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SealOwner {
    /// The workspace of a proposal.
    Workspace(ProposalId),
}

/// Sealed bytes under a hybrid-wrapped data key (ADR-001, ADR-004).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed(pub Vec<u8>);

/// SHA-256 of one vault query, recorded with its answer bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QueryDigest(pub [u8; 32]);

/// One session of an account (R-LG-04).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    /// The session.
    pub session: SessionId,
    /// How it logged in.
    pub method: LoginMethod,
    /// When it started.
    pub started: Timestamp,
}

/// The tenant settings the cell holds.
///
/// Interim (W3b seam proposal for the lead): the three values dispatch
/// reads. Lane W2d writes the full settings in `fstp-tenant`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantSettings {
    /// P-74: whether the MCP server is enabled, and for which roles.
    pub mcp: fstp_access::McpSettings,
    /// The tenant's inference record (design section 3.5). `None` before
    /// onboarding records one, so a publication is refused (R-LA-05).
    pub inference: Option<InferenceRecord>,
    /// The tenant, bound into every action digest.
    pub tenant: Option<TenantId>,
}

/// The tenant's inference configuration record: the `LlmConfigId` and
/// the primary model a publication names (design section 3.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferenceRecord {
    /// The configuration.
    pub config: fstp_domain::id::LlmConfigId,
    /// The primary model, which must equal the programme's P-21 primary.
    pub model: fstp_domain::policy::ModelRef,
    /// The endpoint and decoding inputs of the `config_id` derivation (M7
    /// design section 2, reading 2). `None` before onboarding records
    /// them, and then no assessment or pre-check runs.
    pub endpoint: Option<InferenceEndpoint>,
}

/// The wire protocol of an inference endpoint (ADR-019). Daniel decided
/// on 2026-11-06 that the Anthropic Messages API is the default and the
/// chat-completions shape the secondary path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InferenceProvider {
    /// The in-memory synthetic model of the demo cell. Its findings say
    /// "Synthetic assessor (demo)", and it is never an LLM result.
    Synthetic,
    /// The Anthropic Messages API, non-streaming. The default for a
    /// hosted model. The tenant picks the model (P-21).
    Anthropic,
    /// One endpoint speaking the chat-completions JSON shape, non-streaming,
    /// for an open-weight EU-hosted or local model.
    ChatCompletions,
}

/// The endpoint part of a tenant's inference record (M7 design sections
/// 2 and 9, R-LA-04). With the prompt set digest, the rubric digest and
/// the call's P-01, it is the input of the `config_id` derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferenceEndpoint {
    /// The wire protocol.
    pub provider: InferenceProvider,
    /// The endpoint URL. `None` for [`InferenceProvider::Synthetic`].
    pub url: Option<String>,
    /// The most tokens of a reply.
    pub max_tokens: u32,
    /// The temperature in thousandths, 0 to 2000. No floats.
    pub temperature_milli: u16,
    /// The sampling seed.
    pub seed: u32,
    /// The P-21 fallback models in order. Each gets its own `config_id`
    /// at publication (M7 design section 2, reading 3).
    pub fallbacks: Vec<fstp_domain::policy::ModelRef>,
    /// Pinned trust anchors (PEM) for the endpoint's TLS certificate.
    /// Interim, pending Daniel (Q2): no allowlisted crate holds a public
    /// root store, so a hosted endpoint is reachable only through these.
    pub trust_anchors_pem: Vec<u8>,
}

/// A recorded second tenant admin approval (SoD-07).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecondAdminApproval {
    /// The approval.
    pub approval: ApprovalId,
    /// The approving admin.
    pub approver: AccountId,
}

/// One page of a listing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Page {
    /// The first item.
    pub offset: u32,
    /// The item count.
    pub limit: u32,
}

/// One page of in-app notices.
///
/// W0 placeholder with no fields. The lead writes it with the M3 seam.
/// Interim (W3b seam proposal): `Default` builds the empty page.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NoticePage {
    _w0: (),
}

/// What a probe checks (Q5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProbeKind {
    /// An enabled channel of P-32.
    Channel,
    /// SPF, DKIM and DMARC of the sending domain.
    SendingDomain,
    /// The inference configuration (P-21).
    Inference,
}

/// The result of one probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The probe passed.
    Pass,
    /// The probe failed, or no prober exists (Q5).
    Fail,
}

/// Sessions and principals (`authentication.md`).
pub trait Sessions: Send + Sync {
    /// The principal of the request's session.
    fn principal(
        &self,
        head: &RequestHead,
        cred: &Credential,
        now: Timestamp,
    ) -> impl Future<Output = Result<SessionPrincipal, PortError>> + Send;
}

/// Step-up (I-78), bound to one action digest and consumed on use.
pub trait StepUp: Send + Sync {
    /// Starts a step-up for one digest.
    fn begin(
        &self,
        s: SessionId,
        action: ActionDigest,
    ) -> impl Future<Output = Result<StepUpChallenge, PortError>> + Send;
    /// Finishes a step-up with the authenticator response.
    fn finish(
        &self,
        s: SessionId,
        response: &[u8],
    ) -> impl Future<Output = Result<StepUpRef, PortError>> + Send;
    /// A proof for exactly this digest and session, younger than P-71 at
    /// `now`. Consumed.
    fn take(
        &self,
        s: SessionId,
        action: ActionDigest,
        now: Timestamp,
    ) -> impl Future<Output = Result<StepUpProof, StepUpRequired>> + Send;
    /// Records the step-up `proof`, which [`StepUp::take`] gave for
    /// `action` in session `s`, as used at `now` (I-78). An operation
    /// whose step-up no executed command consumes spends it before it
    /// acts: `agents.consent` (ADR-013 "Consent page", ADR-026 record of
    /// lane L12). A proof spent once is refused. The default is the seam
    /// of a port that cannot record a use: it fails closed.
    fn spend(
        &self,
        s: SessionId,
        proof: StepUpRef,
        action: ActionDigest,
        now: Timestamp,
    ) -> impl Future<Output = Result<(), PortError>> + Send {
        let _ = (s, proof, action, now);
        std::future::ready(Err(PortError::Unavailable))
    }
}

/// Accounts: invitations, enrolment and pseudonymous display handles only.
pub trait Accounts: Send + Sync {
    /// Creates an invitation.
    fn invite(
        &self,
        kind: InviteKind,
    ) -> impl Future<Output = Result<InvitationLink, PortError>> + Send;
    /// The display handle of an account. Never an email.
    fn display_handle(
        &self,
        a: AccountId,
    ) -> impl Future<Output = Result<DisplayHandle, PortError>> + Send;
    /// The login email of an account, from the cell's login email index,
    /// or `None` when the account has none (SA-11). Only the team and
    /// member pages read it, both web only (I-86). The default is the seam
    /// of a cell that keeps no index: it fails closed.
    fn login_email(
        &self,
        a: AccountId,
    ) -> impl Future<Output = Result<Option<String>, PortError>> + Send {
        let _ = a;
        std::future::ready(Err(PortError::Unavailable))
    }
    /// The passkeys the cell disabled for good after a sign count went
    /// down (ADR-008, decided 2026-11-19): the owner of each flagging
    /// event with the event's ordinal, from 1, in ledger order. The mailbox
    /// tells the holder of each, and the tenant admins when no mail relay
    /// sends the email. The default is the seam of a cell that keeps no
    /// such list: it is empty, so the mailbox shows none.
    fn disabled_passkeys(&self) -> Vec<(AccountId, u64)> {
        Vec::new()
    }
}

/// The M2 oracle answers, asynchronously.
pub trait AsyncIdentityOracle: Send + Sync {
    /// Answers one query.
    fn answer(&self, q: &Query) -> impl Future<Output = Result<Answer, OracleDown>> + Send;
}

/// The vault: the oracle, write-only intake and two proposed one-bit
/// queries (Q35, blocking).
pub trait Vault: AsyncIdentityOracle {
    /// States the applicant's country, to the vault only (R-NG-01).
    fn state_country(
        &self,
        a: AccountId,
        p: ProposalId,
        c: VaultBound<CountryCode>,
    ) -> impl Future<Output = Result<Receipt, OracleDown>> + Send;
    /// Declares affiliations, to the vault only.
    fn declare_affiliations(
        &self,
        a: AccountId,
        p: ProposalId,
        d: VaultBound<Affiliations>,
    ) -> impl Future<Output = Result<Receipt, OracleDown>> + Send;
    /// States the lead's date of birth, to the vault only (Q23 B). The
    /// vault derives from it whether the lead is 18 at a call deadline and
    /// answers that one bit to `IsVerifiedAdultAtDeadline`.
    fn state_birth_date(
        &self,
        a: AccountId,
        p: ProposalId,
        d: VaultBound<BirthDate>,
    ) -> impl Future<Output = Result<Receipt, OracleDown>> + Send;
    /// Starts a verification.
    fn begin_verification(
        &self,
        purpose: VerificationPurpose,
        a: AccountId,
    ) -> impl Future<Output = Result<VerificationRedirect, OracleDown>> + Send;
    /// Whether `a` has an open verification request in the cell's ledger
    /// (ADR-026 record of lane L24, lead reading of 2026-11-22). A port
    /// with no ledger has none.
    fn verification_requested(&self, a: AccountId) -> impl Future<Output = bool> + Send {
        let _ = a;
        std::future::ready(false)
    }
    /// Whether [`Vault::begin_verification`] can open the release page of
    /// an unmask now (ADR-023 reading 7, ADR-026 amendment of
    /// 2026-11-23, M10 F-058). The API core asks it before the step-up
    /// and the append of `UnmaskParty`, so no unmask is recorded that
    /// would show nothing. The default answers no, so a port that serves
    /// no unmask fails closed.
    fn releases_unmask(&self) -> impl Future<Output = bool> + Send {
        std::future::ready(false)
    }
    /// Whether the vault knows every P-13 class (Q35).
    fn classes_defined(
        &self,
        programme: ProgrammeId,
        classes: &ExclusionClasses,
    ) -> impl Future<Output = Result<Answer, OracleDown>> + Send;
    /// Whether every partner organisation declared a P-38 list (Q35).
    fn proximity_lists_declared(
        &self,
        programme: ProgrammeId,
        orgs: &BTreeSet<OrganisationId>,
    ) -> impl Future<Output = Result<Answer, OracleDown>> + Send;
    /// The name mask (M7 Q4, ADR-033 record of lane L31, `overview.md`
    /// "Masks"): for each of `texts`, the spans that hold a verified name
    /// or date of birth of one of `team`, a proposal's team from the
    /// cell's own bindings in ascending order. The vault answers spans
    /// only, into the texts the cell sent. The default fails closed.
    fn mask_names(
        &self,
        team: &[AccountId],
        texts: &[String],
    ) -> impl Future<Output = Result<Vec<Vec<NameMaskSpan>>, OracleDown>> + Send {
        let _ = (team, texts);
        std::future::ready(Err(OracleDown))
    }
}

/// One span of the vault name mask (M7 Q4, ADR-033 record of lane L31):
/// byte offsets into the text the cell sent, the person by its index in
/// the team the cell named, and whether it is a date of birth rather than
/// a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NameMaskSpan {
    /// The first byte offset.
    pub start: u32,
    /// The byte offset just after the span.
    pub end: u32,
    /// The person, by its index in the team the cell named.
    pub person: u32,
    /// Whether the span holds a date of birth.
    pub birth_date: bool,
}

/// The asynchronous driver over the M2 pure functions, with a dry run.
pub trait AsyncEngine: Send + Sync {
    /// Queries, vault answers, decide, then one transaction: the ledger
    /// batch, the audit entry and the pending status.
    fn execute(
        &self,
        cmd: fstp_engine::Command,
        ctx: Ctx,
        meta: ExecMeta,
    ) -> impl Future<Output = Result<Seq, ExecError>> + Send;
    /// The same with no append and no audit entry for a commit.
    fn dry_run(
        &self,
        cmd: &fstp_engine::Command,
        ctx: Ctx,
    ) -> impl Future<Output = Result<(), Refusal>> + Send;
    /// A dry run that also returns every vault answer it obtained, in
    /// order, whether it was refused or not, so dispatch records each one
    /// (`overview.md` NOTE 5). Interim (W3b seam proposal for the lead).
    fn dry_run_answers(
        &self,
        cmd: &fstp_engine::Command,
        ctx: Ctx,
    ) -> impl Future<Output = (Result<(), Refusal>, Vec<Answer>)> + Send;
    /// The current engine state.
    fn snapshot(&self) -> Arc<EngineState>;
    /// The cell's ledger from genesis, in sequence order, which the
    /// journey reads fold into journey rows (ADR-015 "Read model only",
    /// I-92). The API core reads it and writes nothing.
    ///
    /// Interim (lane j2 seam proposal for the lead): the cell's projector
    /// writes the rows into the `journey` schema, and this port will serve
    /// those rows with the entries the diary sentences read. The default
    /// answers `None`, so the journey reads fail closed as unavailable.
    fn ledger(&self) -> Option<Vec<fstp_ledger::Entry<fstp_engine::Record>>> {
        None
    }
    /// The cell's ledger entries after `after`, in sequence order, which
    /// the API core's journal folds before each read (`journal.rs`).
    /// `None` when the engine serves no ledger. The default filters
    /// [`AsyncEngine::ledger`]. An engine that reads its store from a
    /// sequence number answers it directly.
    fn ledger_after(&self, after: Seq) -> Option<Vec<fstp_ledger::Entry<fstp_engine::Record>>> {
        let mut all = self.ledger()?;
        all.retain(|e| e.seq > after);
        Some(all)
    }
    /// The shell's creator facts for `cmd` by `ctx` (design section 3.2,
    /// `CreatorInputs`): the facts the engine port's
    /// `fstp_engine::CreatorEnvironment` answers for the same command. The
    /// API core reads them for the validation report, the invitations and
    /// the approval inbox, so a read shows what a decision would see.
    ///
    /// The engine replaces the parts it owns before it decides: the count
    /// of unresolved imports and the vault answers of the builders. The
    /// API core does the same for its reads.
    ///
    /// Interim (lane m4wire seam proposal for the lead). The default
    /// supplies no shell fact, as `fstp_engine::NoEnvironment` does, so
    /// every check that needs one fails closed. The one exception is the
    /// funder profile: it comes from the shipped profiles only, as the
    /// production shell of `fstp-cell` reads it (rule A9b). A draft that
    /// names no shipped profile gets none.
    fn creator_inputs(
        &self,
        state: &EngineState,
        cmd: &fstp_creator::CreatorCommand,
        ctx: &Ctx,
    ) -> fstp_creator::CreatorInputs {
        use fstp_guide::ProfileSource as _;
        let mut inputs = fstp_engine::CreatorEnvironment::creator_inputs(
            &fstp_engine::NoEnvironment,
            state,
            cmd,
            ctx,
        );
        inputs.profile = fstp_engine::compose::profile_ref(state, cmd)
            .and_then(|r| fstp_engine::compose::profile_name(&r))
            .and_then(|name| fstp_guide::ShippedProfiles.profile(&name).ok());
        inputs
    }
}

/// MCP bearer tokens (design sections 3.7 step 0 and 3.8). Interim (W3b
/// seam proposal for the lead): ADR-013 is a draft, so the token store of
/// `fstp-oauth` is not built. This port resolves a token to its grant.
pub trait Tokens: Send + Sync {
    /// The grant of a valid token at `now`.
    fn grant(
        &self,
        token: &[u8],
        now: Timestamp,
    ) -> impl Future<Output = Result<fstp_access::GrantFacts, PortError>> + Send;
    /// Revokes every token of `client` for `account` at once (R-MC-03).
    fn revoke(
        &self,
        account: AccountId,
        client: AgentClientId,
    ) -> impl Future<Output = Result<(), PortError>> + Send;
    /// Approves the consent of `c` at the authorisation server of ADR-013
    /// and answers where the browser goes: the client's redirect URI with
    /// a single-use code, `state` and `iss`. A handle the server does not
    /// hold, or holds no longer, is refused.
    fn approve_consent(
        &self,
        c: ConsentApproval,
    ) -> impl Future<Output = Result<String, PortError>> + Send;
    /// The live agent clients of `account` at `now`, one per client,
    /// each with the scopes of its tokens (R-MC-03, `mcp-server.md`).
    fn agents(
        &self,
        account: AccountId,
        now: Timestamp,
    ) -> impl Future<Output = Result<Vec<AgentInfo>, PortError>> + Send;
    /// The pending consent `handle` at `now`, as the consent page shows it
    /// (`agents.consent_request`, ADR-013 amendment of 2026-11-20, lane
    /// L2). A handle the server does not hold, or holds no longer, is
    /// refused. The default holds no authorisation server, so it fails
    /// closed.
    fn consent_request(
        &self,
        handle: &str,
        now: Timestamp,
    ) -> impl Future<Output = Result<ConsentRequestInfo, PortError>> + Send {
        let _ = (handle, now);
        std::future::ready(Err(PortError::Unavailable))
    }
}

/// A pending consent as the consent page shows it (lane L2,
/// `agents.consent_request`): the client, its own name as unverified text,
/// the host the browser goes back to and the scopes asked for. It names
/// no account, no handle and no digest (I-86).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentRequestInfo {
    /// The agent client.
    pub client: AgentClientId,
    /// The client name it registered with: untrusted text, unverified.
    pub name: Option<String>,
    /// The host of the redirect URI.
    pub redirect_host: String,
    /// Whether that host is a loopback host on the user's own device.
    pub loopback: bool,
    /// The scopes asked for.
    pub scopes: BTreeSet<fstp_access::Scope>,
    /// When the consent expires.
    pub expires: Timestamp,
}

/// One connected agent client of an account (R-MC-03): what its tokens
/// grant. It names no other account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentInfo {
    /// The agent client.
    pub client: AgentClientId,
    /// The client name it registered with: untrusted text, unverified.
    pub name: Option<String>,
    /// The scopes its live tokens hold.
    pub scopes: BTreeSet<fstp_access::Scope>,
    /// How the session that consented logged in.
    pub method: LoginMethod,
    /// When the grant started, when the token store knows it.
    pub since: Option<Timestamp>,
    /// When it ends at the latest (P-72), when the token store knows it.
    pub until: Option<Timestamp>,
}

/// Audit (I-24): one entry per call, in the same transaction as any append.
pub trait AuditSink: Send + Sync {
    /// Records one entry.
    fn record(&self, tx: &mut Tx, e: AuditEntry) -> Result<(), PortError>;
    /// Makes every entry recorded before this call durable (ADR-010
    /// amendment of 2026-11-20). [`ApiCore`] awaits it before it answers a
    /// call, and a failure turns the answer into a 503 refusal. The
    /// default is the seam of a sink whose `record` is durable at once.
    fn flush(&self) -> impl Future<Output = Result<(), PortError>> + Send {
        std::future::ready(Ok(()))
    }
}

/// A boxed future of a [`PendingActions`] call, so the port is object
/// safe and a cell passes it as `&dyn PendingActions`.
pub type PendingFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Why [`PendingActions::insert`] stored nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingInsertError {
    /// The id is taken.
    Taken,
    /// The account holds the most open actions it may hold.
    Full,
    /// The port failed.
    Port(PortError),
}

/// The pending actions of a cell (I-85, ADR-026): stored with their
/// canonical request, found by their own account only. The API core keeps
/// the claims of confirmations in flight in its own memory, so a store
/// holds statuses only.
///
/// The production cell stores them in `api.pending_actions`, and records
/// a confirmation in the append that executes it, so a second
/// confirmation aborts that append.
pub trait PendingActions: Send + Sync {
    /// Stores a new open action at `now`, within the bounds of
    /// `crate::pending::OPEN_PER_ACCOUNT`.
    fn insert(
        &self,
        a: crate::pending::PendingAction,
        now: Timestamp,
    ) -> PendingFuture<'_, Result<(), PendingInsertError>>;
    /// The action `id` of `account`, or `None`, also when another account
    /// holds it.
    fn get(
        &self,
        id: PendingId,
        account: AccountId,
    ) -> PendingFuture<'_, Result<Option<crate::pending::PendingAction>, PortError>>;
    /// Every listed action of `account` at `now`, in id order.
    fn list(
        &self,
        account: AccountId,
        now: Timestamp,
    ) -> PendingFuture<'_, Result<Vec<crate::pending::PendingAction>, PortError>>;
    /// Closes the open, unconfirmed action `id` as `to` at `now`. `false`
    /// when it is not open.
    fn close(
        &self,
        id: PendingId,
        to: crate::pending::PendingStatus,
        now: Timestamp,
    ) -> PendingFuture<'_, Result<bool, PortError>>;
    /// Removes `id` entirely, such as a preparation whose audit entry
    /// could not be written.
    fn remove(&self, id: PendingId) -> PendingFuture<'_, Result<(), PortError>>;
    /// Whether `id` is confirmed, after the engine executed it at `now`.
    /// A store whose engine records no confirmation marks it here.
    fn confirmed(
        &self,
        id: PendingId,
        now: Timestamp,
    ) -> PendingFuture<'_, Result<bool, PortError>>;
}

/// Free text, each under its own data key (ADR-004, ADR-007).
pub trait TextStore: Send + Sync {
    /// Stores a text.
    fn put(
        &self,
        class: TextClass,
        owner: TextOwner,
        bytes: &[u8],
    ) -> impl Future<Output = Result<TextRef, PortError>> + Send;
    /// Reads a text against a clearance.
    fn get(
        &self,
        r: TextRef,
        clearance: &ReadClearance,
    ) -> impl Future<Output = Result<Vec<u8>, PortError>> + Send;
    /// Reads a public text.
    fn get_public(
        &self,
        r: PublicTextRef,
    ) -> impl Future<Output = Result<Vec<u8>, PortError>> + Send;

    /// Whether the confidential text `r` of a proposal, stored in the
    /// salted form of [`crate::salted::stored`], is exactly `candidate`
    /// after its salt (F-079, ADR-038). It answers one bit and releases no
    /// text, so it needs no read clearance. The API core asks it only with
    /// the caller's own login email, to match a team invitation's address
    /// before the caller is on the proposal. Any other text answers
    /// `false`. The default is the seam of a store that cannot compare: it
    /// fails closed.
    fn text_equals(
        &self,
        r: TextRef,
        candidate: &[u8],
    ) -> impl Future<Output = Result<bool, PortError>> + Send {
        let _ = (r, candidate);
        std::future::ready(Err(PortError::Unavailable))
    }

    /// The erasure log, oldest first: one row per erased text (ADR-007,
    /// lane m5/retention). The default is the seam of a store that keeps
    /// no log: it fails closed.
    fn erasures(&self) -> impl Future<Output = Result<Vec<ErasureRow>, PortError>> + Send {
        std::future::ready(Err(PortError::Unavailable))
    }

    /// Erases every text that grant `grant` owns, with `cause`, as tenant
    /// admin `by` asked at `at` with the step-up of `proof` (ADR-007, P-41,
    /// lane m5/retention). The API core checked the admin, the cause and
    /// the end of the grant's retention first. Each erased text gets one
    /// log row naming its cause and authoriser. A grant that owns no live
    /// text is refused. The default fails closed.
    fn request_erasure(
        &self,
        by: AccountId,
        cause: ErasureCause,
        grant: ProposalId,
        at: Timestamp,
        proof: StepUpProof,
    ) -> impl Future<Output = Result<(), PortError>> + Send {
        let _ = (by, cause, grant, at, proof);
        std::future::ready(Err(PortError::Unavailable))
    }

    /// Sets the display name of account `a` to `name`, or clears it with
    /// `None` (SA-11). The store keeps it as a confidential text that the
    /// account owns (`TextOwner::Account`, ADR-007), so an account
    /// erasure erases it. A text it replaces or clears is erased at once.
    /// The API core checked the name first. The default fails closed.
    ///
    /// The name is unique within the tenant (SA-11 amendment). The store
    /// keeps the keyed fingerprint of [`crate::display_name::fingerprint`]
    /// beside the sealed name, under the fingerprint key of the cell's
    /// `Lookup` key, and erases it with the name. The uniqueness check and
    /// the write are one atomic step: a name whose fingerprint another
    /// account of the tenant holds is [`DisplayNameSet::Taken`], and
    /// nothing changes. The account's own current name again is
    /// [`DisplayNameSet::Set`]. A clear is always `Set`.
    ///
    /// Interim reading, pending Daniel: a display name changes no domain
    /// fact, so no ledger record names it. The store alone knows which of
    /// an account's texts is its display name.
    fn set_display_name(
        &self,
        a: AccountId,
        name: Option<String>,
        at: Timestamp,
    ) -> impl Future<Output = Result<DisplayNameSet, PortError>> + Send {
        let _ = (a, name, at);
        std::future::ready(Err(PortError::Unavailable))
    }

    /// The display names of those of `accounts` that have one, under
    /// `clearance` (SA-11). A store releases them only to a clearance of
    /// the team read, the member read, or the account's own display name
    /// read, so no other read can show one (I-17, P-11, I-27). The default
    /// fails closed.
    fn display_names(
        &self,
        accounts: Vec<AccountId>,
        clearance: &ReadClearance,
    ) -> impl Future<Output = Result<BTreeMap<AccountId, String>, PortError>> + Send {
        let _ = (accounts, clearance);
        std::future::ready(Err(PortError::Unavailable))
    }

    /// The display names of those of `accounts` that have one, for the
    /// name mask alone (M10 F-006, ADR-033, Daniel 2026-11-23). The API
    /// core passes the accounts of one proposal's team and turns the names
    /// into mask handles. No read model carries them, so the release rule
    /// of [`TextStore::display_names`] stands (SA-11, I-17). The default
    /// fails closed.
    fn mask_handles(
        &self,
        accounts: Vec<AccountId>,
    ) -> impl Future<Output = Result<BTreeMap<AccountId, String>, PortError>> + Send {
        let _ = accounts;
        std::future::ready(Err(PortError::Unavailable))
    }
}

/// What [`TextStore::set_display_name`] did (SA-11 amendment).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayNameSet {
    /// The name is now the account's display name, or it was cleared.
    Set,
    /// Another account of the tenant holds the name. Nothing changed.
    Taken,
}

/// An erasure cause of ADR-007, with the closed code of
/// `fstp_cell_core::decide::ERASURE_CAUSES`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErasureCause {
    /// The funder retention period ended (P-41). Code 1.
    RetentionExpiry,
    /// A person's erasure request. Code 2.
    ErasureRequest,
    /// The cell is erased. Code 3.
    CellErasure,
    /// An identity verification completed (R-ID-03). Code 4.
    VerificationCompleted,
}

impl ErasureCause {
    /// Every cause, in code order.
    pub const ALL: [ErasureCause; 4] = [
        ErasureCause::RetentionExpiry,
        ErasureCause::ErasureRequest,
        ErasureCause::CellErasure,
        ErasureCause::VerificationCompleted,
    ];

    /// The closed code the cell records.
    pub const fn code(self) -> u16 {
        match self {
            ErasureCause::RetentionExpiry => 1,
            ErasureCause::ErasureRequest => 2,
            ErasureCause::CellErasure => 3,
            ErasureCause::VerificationCompleted => 4,
        }
    }

    /// The wire name (`fstp_access::ERASURE_CAUSES`).
    pub const fn wire(self) -> &'static str {
        match self {
            ErasureCause::RetentionExpiry => "retention_expiry",
            ErasureCause::ErasureRequest => "erasure_request",
            ErasureCause::CellErasure => "cell_erasure",
            ErasureCause::VerificationCompleted => "verification_completed",
        }
    }

    /// The cause of the closed code `code`, if it is one (lane L33).
    pub fn from_code(code: u16) -> Option<ErasureCause> {
        ErasureCause::ALL.into_iter().find(|c| c.code() == code)
    }

    /// The cause of the wire name `s`, if it is one.
    pub fn from_wire(s: &str) -> Option<ErasureCause> {
        ErasureCause::ALL.into_iter().find(|c| c.wire() == s)
    }
}

/// One erasure-log row (ADR-007): the text, its cause, the grant whose
/// texts were asked for, and when it was requested and completed. It
/// names no account and holds no text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErasureRow {
    /// The erased text.
    pub text: TextRef,
    /// The cause.
    pub cause: ErasureCause,
    /// The grant the request named, if any.
    pub grant: Option<ProposalId>,
    /// When the erasure was requested.
    pub requested_at: Timestamp,
    /// When it completed, once it did.
    pub completed_at: Option<Timestamp>,
    /// What the text held (lane L33).
    pub kind: ErasureKind,
    /// The root epoch whose destruction completed the erasure, once the
    /// store knows it (I-81, lane L33).
    pub destroyed_epoch: Option<u64>,
    /// Whether the system authorised it rather than an account (ADR-007,
    /// Daniel 2026-11-23, question 3; lane L39). The row never names
    /// which account (R-CF-03).
    pub by_system: bool,
    /// The text of the reason a tenant admin stated, if any (lane L39),
    /// resolved at read time under the reader's clearance (I-97).
    pub reason: Option<TextRef>,
}

/// What an erased text held (ADR-007 section "Built by lane L33").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErasureKind {
    /// A text the ledger names.
    Text,
    /// A display name an account replaced or cleared (SA-11).
    DisplayName,
    /// A document the blob store sealed (ADR-007 section "Built by lane
    /// L37").
    Document,
    /// Every slot of a proposal's workspace, under the proposal's own key
    /// (F-017, ADR-026 section "Written by the M10 fix lane").
    Workspace,
}

impl ErasureKind {
    /// Every kind.
    pub const ALL: [ErasureKind; 4] = [
        ErasureKind::Text,
        ErasureKind::DisplayName,
        ErasureKind::Document,
        ErasureKind::Workspace,
    ];

    /// The wire name (`fstp_access::ERASURE_KINDS`).
    pub const fn wire(self) -> &'static str {
        match self {
            ErasureKind::Text => "text",
            ErasureKind::DisplayName => "display_name",
            ErasureKind::Document => "document",
            ErasureKind::Workspace => "workspace",
        }
    }
}

/// Blobs, such as uploaded import documents (R-PG-02): content-addressed,
/// size-limited and each under its own data key (ADR-004, ADR-007).
///
/// W0 placeholder methods. The lead writes the size limit and the key
/// handling with the M3 seam.
pub trait BlobStore: Send + Sync {
    /// Stores a blob and returns its content address.
    fn put(
        &self,
        owner: BlobOwner,
        bytes: &[u8],
    ) -> impl Future<Output = Result<BlobRef, PortError>> + Send;
    /// Reads a blob against a clearance.
    fn get(
        &self,
        owner: BlobOwner,
        r: BlobRef,
        clearance: &ReadClearance,
    ) -> impl Future<Output = Result<Vec<u8>, PortError>> + Send;
    /// Reads a brand asset of owner [`BlobOwner::Brand`], with no
    /// clearance: a logo is public data (ADR-030). A blob of any other
    /// owner is refused. The default fails closed.
    fn get_brand(&self, r: BlobRef) -> impl Future<Output = Result<Vec<u8>, PortError>> + Send {
        let _ = r;
        std::future::ready(Err(PortError::Unavailable))
    }

    /// Erases blob `r` of `owner` as tenant admin `by` asked, with the
    /// stated reason `reason`, a text of the text store (ADR-007, Daniel
    /// 2026-11-23, decision 1c; lane L39). Only an import document of a
    /// programme is erased: a brand asset is refused. The key dies with
    /// the next erasure batch, and the sealed row is deleted after it. A
    /// blob already erased is a no-op. The default fails closed.
    fn erase(
        &self,
        owner: BlobOwner,
        r: BlobRef,
        by: AccountId,
        reason: TextRef,
    ) -> impl Future<Output = Result<(), PortError>> + Send {
        let _ = (owner, r, by, reason);
        std::future::ready(Err(PortError::Unavailable))
    }

    /// Whether blob `r` is erased or under erasure (lane L39). The default
    /// fails closed.
    fn erased(&self, r: BlobRef) -> impl Future<Output = Result<bool, PortError>> + Send {
        let _ = r;
        std::future::ready(Err(PortError::Unavailable))
    }
}

/// One section of a pre-check snapshot (M7 design section 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrecheckSection {
    /// The title.
    Title,
    /// The neutral summary.
    Summary,
    /// The narrative.
    Narrative,
}

/// The draft a pre-check run reads: the workspace as it stood when the
/// applicant asked. Every text is untrusted data. The port passes it to
/// a model only as a data part (`fstp-infer`, TH-01).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrecheckSnapshot {
    /// The call's pin the run uses (I-11). Lane L-DEMO added it: the port
    /// cannot read the engine state, so dispatch passes the pin.
    pub pin: PrecheckPin,
    /// The title.
    pub title: fstp_findings::UntrustedText,
    /// The neutral summary.
    pub summary: fstp_findings::UntrustedText,
    /// The narrative.
    pub narrative: fstp_findings::UntrustedText,
}

/// The configuration a pre-check run uses: the call's pinned config and
/// model, its frozen P-01 criteria, and the tenant's endpoint record
/// (I-11, M7 design section 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrecheckPin {
    /// The draft's call.
    pub call: fstp_domain::id::CallId,
    /// The call's pinned configuration (I-11).
    pub config: fstp_domain::id::LlmConfigId,
    /// The call's pinned model (P-21).
    pub model: fstp_domain::policy::ModelRef,
    /// The call's frozen P-01 criterion ids, in order.
    pub criteria: Vec<fstp_domain::id::CriterionId>,
    /// The tenant's endpoint record, `None` before onboarding.
    pub endpoint: Option<InferenceEndpoint>,
}

/// A quote that supports a pre-check finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrecheckEvidence {
    /// The section it quotes.
    pub section: PrecheckSection,
    /// The quoted text, as data.
    pub quote: fstp_findings::UntrustedText,
}

/// One pre-check finding. It carries no confidence and no number, so no
/// score or band is derivable from it (R-LA-06, TH-02, T-LLM-ORACLE).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrecheckFinding {
    /// Completeness, quality, accuracy or integrity.
    pub kind: fstp_findings::FindingKind,
    /// The P-01 criterion, where one applies.
    pub criterion: Option<fstp_domain::id::CriterionId>,
    /// The rubric element tag, such as `team_experience`, where one
    /// applies. The intake admits only the pinned rubric's tags.
    pub element: Option<String>,
    /// Info, minor or major.
    pub severity: fstp_findings::Severity,
    /// The observation, as data.
    pub statement: fstp_findings::UntrustedText,
    /// Quotes from the snapshot.
    pub evidence: Vec<PrecheckEvidence>,
}

/// Where a pre-check run stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrecheckRunState {
    /// The run is queued or running.
    Pending,
    /// The run finished with findings, possibly none.
    Done,
    /// The provider was unavailable. The run still counts (P-23).
    Unavailable,
}

/// One pre-check run, stored in the applicant workspace beside the draft
/// and never in the `FindingStore` (I-21).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrecheckRun {
    /// The run.
    pub run: PrecheckRunId,
    /// When it was requested, which is when it was counted (P-23).
    pub requested: Timestamp,
    /// The call's pinned configuration (I-11).
    pub config: fstp_domain::id::LlmConfigId,
    /// Where it stands.
    pub state: PrecheckRunState,
    /// Its findings, empty until it is done.
    pub findings: Vec<PrecheckFinding>,
}

/// The remaining P-23 checks of one applicant on one draft. These counts
/// are the only numbers a pre-check reply shows (M7 design section 2,
/// reading 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrecheckQuota {
    /// Runs left today on this proposal.
    pub proposal_today: u32,
    /// Runs left in this call on this proposal.
    pub proposal_call: u32,
    /// Runs left for this account across its drafts in this call (TH-29).
    pub account_call: u32,
    /// When the next run becomes available, if none is left now.
    pub next: Option<Timestamp>,
}

/// Why a pre-check request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrecheckRefusal {
    /// The port failed or is not built yet. Fails closed.
    Port(PortError),
    /// A P-23 limit is reached.
    QuotaExhausted(PrecheckQuota),
    /// The draft's call is not published, so it has no pinned config.
    CallNotPublished,
}

/// The pre-check provider (M7 design section 4, R-LA-06, I-21). M4
/// production cells have none, so `PrecheckUnavailable` fails validation
/// there (Q38). The e2e cell supplies a fake.
///
/// L-SEAM stub: every method has a default that fails closed with
/// [`PortError::Unavailable`], so the ops answer "unavailable" until lane
/// L-PRE implements the port over `fstp-infer`.
pub trait Precheck: Send + Sync {
    /// Requests one run on `snapshot` for `account`, counted at once
    /// against every P-23 limit (TH-29).
    fn request(
        &self,
        proposal: ProposalId,
        account: AccountId,
        snapshot: PrecheckSnapshot,
    ) -> impl Future<Output = Result<PrecheckRunId, PrecheckRefusal>> + Send {
        let _ = (proposal, account);
        drop(snapshot);
        std::future::ready(Err(PrecheckRefusal::Port(PortError::Unavailable)))
    }
    /// The runs of a proposal, newest first. Only its team reads them.
    fn runs(
        &self,
        proposal: ProposalId,
    ) -> impl Future<Output = Result<Vec<PrecheckRun>, PortError>> + Send {
        let _ = proposal;
        std::future::ready(Err(PortError::Unavailable))
    }
    /// The remaining checks of `account` on `proposal`.
    fn quota(
        &self,
        proposal: ProposalId,
        account: AccountId,
    ) -> impl Future<Output = Result<PrecheckQuota, PortError>> + Send {
        let _ = (proposal, account);
        std::future::ready(Err(PortError::Unavailable))
    }
    /// Whether this provider can run an assessment again (issue 6 M3).
    /// Dispatch asks before it executes `assess.rerun`, so no record is
    /// written for a job that cannot start. The default is no.
    fn can_rerun(&self) -> bool {
        false
    }
    /// Starts the re-run of the assessment of a submitted proposal on
    /// `snapshot` (issue 6 M3, I-10, I-11). Only the coordinator's
    /// `assess.rerun` reaches it, after the ledger holds the request. The
    /// implementation runs the assessment and records the new findings and
    /// the refusal list as the system through its own engine handle, which
    /// closes the run in flight. The API core issues no system command
    /// (I-84, rule A7). The production cell has no implementation yet.
    fn start_rerun(
        &self,
        proposal: ProposalId,
        snapshot: PrecheckSnapshot,
    ) -> impl Future<Output = Result<(), PortError>> + Send {
        let _ = proposal;
        drop(snapshot);
        std::future::ready(Err(PortError::Unavailable))
    }
}

/// Sealing under ADR-004 level 3 keys, hybrid-wrapped in M3 (ADR-001).
pub trait Sealer: Send + Sync {
    /// Seals bytes for an owner.
    fn seal(
        &self,
        owner: SealOwner,
        plaintext: &[u8],
    ) -> impl Future<Output = Result<Sealed, PortError>> + Send;
    /// Opens sealed bytes against a clearance.
    fn open(
        &self,
        owner: SealOwner,
        sealed: &Sealed,
        clearance: &ReadClearance,
    ) -> impl Future<Output = Result<Vec<u8>, PortError>> + Send;
}

/// The slot of a proposal's content in the workspace store (I-21,
/// R-CF-02, `content.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WorkspaceSlot {
    /// The team's latest autosave of the form.
    Draft,
    /// The content frozen when the proposal was submitted with this plan.
    /// A later submission, after a re-entry, has another plan, so it
    /// never reads an earlier submission's content.
    Submitted(fstp_domain::id::PlanVersionId),
}

/// Proposal content beside the ledger, each value sealed through the
/// [`Sealer`] under [`SealOwner::Workspace`] (lane W6, `content.rs`). The
/// store holds sealed bytes only and opens nothing.
pub trait Workspaces: Send + Sync {
    /// Stores `sealed` as the content of `proposal` in `slot`, replacing
    /// what the slot held.
    fn put(
        &self,
        proposal: ProposalId,
        slot: WorkspaceSlot,
        sealed: Sealed,
    ) -> impl Future<Output = Result<(), PortError>> + Send;
    /// The sealed content of `proposal` in `slot`, or `None` when the slot
    /// was never stored.
    fn get(
        &self,
        proposal: ProposalId,
        slot: WorkspaceSlot,
    ) -> impl Future<Output = Result<Option<Sealed>, PortError>> + Send;
    /// Requests the erasure of every slot of `proposal`, with `cause`, as
    /// tenant admin `by` asked (F-017, ADR-026 section "Written by the M10
    /// fix lane"). `false` when the store holds no workspace of the
    /// proposal. A store that seals each proposal under a key of its own
    /// destroys that key first and deletes the rows after it. A repeated
    /// request is `true` and does nothing more. The default fails closed.
    fn erase(
        &self,
        proposal: ProposalId,
        cause: ErasureCause,
        by: AccountId,
    ) -> impl Future<Output = Result<bool, PortError>> + Send {
        let _ = (proposal, cause, by);
        std::future::ready(Err(PortError::Unavailable))
    }
}

/// Records vault answers that commit no command, as a query digest and the
/// answer bit (`overview.md` NOTE 5).
pub trait VaultAudit: Send + Sync {
    /// Records one answer.
    fn record(
        &self,
        q: QueryDigest,
        answer: bool,
        epoch: VaultEpoch,
    ) -> impl Future<Output = Result<(), PortError>> + Send;
}

/// Sessions and devices (R-LG-04).
pub trait SessionsAdmin: Send + Sync {
    /// The sessions of an account.
    fn list(
        &self,
        a: AccountId,
    ) -> impl Future<Output = Result<Vec<SessionInfo>, PortError>> + Send;
    /// Ends one session of an account.
    fn end(&self, a: AccountId, s: SessionId)
    -> impl Future<Output = Result<(), PortError>> + Send;
    /// Adds the passkey of `reg` to account `a` in its session `s`
    /// through the cell's own registration ceremony, the one behind
    /// `POST /auth/passkeys` (high-risk `AddPasskey`, design sections 8.3
    /// and 8.7). The API core checked the session's strength and took the
    /// step-up of `proof` first. The ceremony takes the challenge once,
    /// verifies the registration through `fstp-webauthn` and needs a
    /// credential id new to the cell. Any failure is refused.
    fn add_passkey(
        &self,
        a: AccountId,
        s: SessionId,
        reg: PasskeyRegistration,
        proof: StepUpProof,
    ) -> impl Future<Output = Result<(), PortError>> + Send;
}

/// The M3 recovery approval flow (Q41).
pub trait Recovery: Send + Sync {
    /// Approves a recovery case.
    fn approve(
        &self,
        approver: AccountId,
        r: RecoveryId,
        proof: StepUpProof,
    ) -> impl Future<Output = Result<(), PortError>> + Send;
}

/// The M3 break-glass approval flow (SoD-08, Q41).
pub trait BreakGlass: Send + Sync {
    /// Approves or refuses a break-glass request.
    fn decide(
        &self,
        approver: AccountId,
        b: BreakGlassId,
        approve: bool,
        proof: StepUpProof,
    ) -> impl Future<Output = Result<(), PortError>> + Send;
}

/// Tenant configuration: the attested admin set and second-admin approvals.
pub trait TenantConfig: Send + Sync {
    /// The current tenant settings.
    fn settings(&self) -> Arc<TenantSettings>;
    /// Whether the attested tenant admin set holds the account.
    fn is_tenant_admin(&self, a: AccountId) -> bool;
    /// Whether the organisation is activated, for a cell whose ledger
    /// holds no tenant part yet (ADR-021, interim). Once the ledger holds
    /// it, the ledger alone answers. The default is the seam of a port
    /// that does not know: it answers no, so the setup gate fails closed.
    fn organisation_active(&self) -> bool {
        false
    }
    /// A recorded second-admin approval.
    fn approval(
        &self,
        id: ApprovalId,
    ) -> impl Future<Output = Result<SecondAdminApproval, PortError>> + Send;
    /// The facts of the tenant admins' System page (ADR-028 record of
    /// lane L20): whether the vault answers, whether outgoing mail works,
    /// and the host status file. The default is a cell that knows nothing
    /// of itself, which the page shows as problems.
    fn system(&self) -> impl Future<Output = crate::system::SystemFacts> + Send {
        std::future::ready(crate::system::SystemFacts::default())
    }
}

/// The in-app notice list, read from outbox records.
pub trait Outbox: Send + Sync {
    /// One page of an account's notices.
    fn notices(&self, a: AccountId, page: Page) -> NoticePage;

    /// One page of the tenant's delivery log, newest first (M6 design
    /// section 6, lane L6-API): the head of each message in
    /// `ops.delivery`. A row holds no body and no address (I-27). The
    /// default is the seam of a cell that has no delivery log: it fails
    /// closed.
    fn deliveries(
        &self,
        page: Page,
    ) -> impl Future<Output = Result<Vec<crate::views::DeliveryRow>, PortError>> + Send {
        let _ = page;
        std::future::ready(Err(PortError::Unavailable))
    }

    /// The scheduled, cancelled and fired events of `programme`, by due
    /// instant (M6 design section 6, R-NT-01). The default is the seam of
    /// a cell that has no timeline: it fails closed.
    fn timeline(
        &self,
        programme: fstp_domain::id::ProgrammeId,
    ) -> impl Future<Output = Result<Vec<crate::views::TimelineRow>, PortError>> + Send {
        let _ = programme;
        std::future::ready(Err(PortError::Unavailable))
    }
}

/// Probes for channels, the sending domain and inference (Q5).
pub trait Prober: Send + Sync {
    /// Runs one probe.
    fn probe(&self, p: ProbeKind) -> impl Future<Output = ProbeOutcome> + Send;

    /// The sending domain probe of `domain`, the domain a tenant admin
    /// saved in the Domains and email step (ADR-026 record of lane L18).
    /// The default asks [`Prober::probe`], which names no domain.
    fn sending_domain(&self, domain: &str) -> impl Future<Output = ProbeOutcome> + Send {
        let _ = domain;
        self.probe(ProbeKind::SendingDomain)
    }

    /// The channel probe of a Channels save that names a Matrix
    /// homeserver (`matrix`) or WhatsApp (`whatsapp`), beside email (ADR-026
    /// record of lane L18). The default asks [`Prober::probe`].
    fn channels(&self, matrix: bool, whatsapp: bool) -> impl Future<Output = ProbeOutcome> + Send {
        let _ = (matrix, whatsapp);
        self.probe(ProbeKind::Channel)
    }
}

/// The cell clock.
pub trait Clock: Send + Sync {
    /// The current instant.
    fn now(&self) -> Timestamp;
}

/// Fresh ids, drawn with `fstp_crypto::random_array`.
pub trait Ids: Send + Sync {
    /// A fresh 128-bit id value.
    fn fresh(&self) -> Result<u128, PortError>;
}

/// Every port of one cell. Only `fstp-cell` implements it, and only
/// [`api_core`] takes it.
pub trait CellPorts: Send + Sync + 'static {
    /// The sessions port.
    type Sessions: Sessions;
    /// The step-up port.
    type StepUp: StepUp;
    /// The accounts port.
    type Accounts: Accounts;
    /// The vault port.
    type Vault: Vault;
    /// The engine port.
    type Engine: AsyncEngine;
    /// The audit port.
    type Audit: AuditSink;
    /// The text store.
    type Texts: TextStore;
    /// The blob store.
    type Blobs: BlobStore;
    /// The pre-check provider, absent in M4 production cells (Q38).
    type Precheck: Precheck;
    /// The sealer.
    type Sealer: Sealer;
    /// The sealed workspace store.
    type Workspaces: Workspaces;
    /// The vault answer recorder.
    type VaultAudit: VaultAudit;
    /// The sessions admin port.
    type SessionsAdmin: SessionsAdmin;
    /// The recovery port.
    type Recovery: Recovery;
    /// The break-glass port.
    type BreakGlass: BreakGlass;
    /// The tenant configuration.
    type Tenant: TenantConfig;
    /// The outbox.
    type Outbox: Outbox;
    /// The prober.
    type Prober: Prober;
    /// The clock.
    type Clock: Clock;
    /// The id source.
    type Ids: Ids;
    /// The MCP token grants.
    type Tokens: Tokens;

    /// The sessions port.
    fn sessions(&self) -> &Self::Sessions;
    /// The step-up port.
    fn step_up(&self) -> &Self::StepUp;
    /// The accounts port.
    fn accounts(&self) -> &Self::Accounts;
    /// The vault port.
    fn vault(&self) -> &Self::Vault;
    /// The engine port.
    fn engine(&self) -> &Self::Engine;
    /// The audit port.
    fn audit(&self) -> &Self::Audit;
    /// The text store.
    fn texts(&self) -> &Self::Texts;
    /// The blob store.
    fn blobs(&self) -> &Self::Blobs;
    /// The pre-check provider. `None` in every M4 production cell, so
    /// `PrecheckUnavailable` fails validation there (Q38).
    fn precheck(&self) -> Option<&Self::Precheck>;
    /// The sealer.
    fn sealer(&self) -> &Self::Sealer;
    /// The sealed workspace store.
    fn workspaces(&self) -> &Self::Workspaces;
    /// The vault answer recorder.
    fn vault_audit(&self) -> &Self::VaultAudit;
    /// The sessions admin port.
    fn sessions_admin(&self) -> &Self::SessionsAdmin;
    /// The recovery port.
    fn recovery(&self) -> &Self::Recovery;
    /// The break-glass port.
    fn break_glass(&self) -> &Self::BreakGlass;
    /// The tenant configuration.
    fn tenant(&self) -> &Self::Tenant;
    /// The outbox.
    fn outbox(&self) -> &Self::Outbox;
    /// The prober.
    fn prober(&self) -> &Self::Prober;
    /// The clock.
    fn clock(&self) -> &Self::Clock;
    /// The id source.
    fn ids(&self) -> &Self::Ids;
    /// The MCP token grants.
    fn tokens(&self) -> &Self::Tokens;
    /// The cell's durable pending actions (ADR-026). `None` keeps them in
    /// the core's memory, as a test cell does: a restart loses them,
    /// which fails closed (I-85).
    fn pending_actions(&self) -> Option<&dyn PendingActions> {
        None
    }
    /// The store of anonymous drafts (ADR-032). `None` refuses every
    /// claim as unavailable, so nothing is claimed without a store.
    fn anonymous_drafts(&self) -> Option<&dyn crate::anon::AnonymousDrafts> {
        None
    }
}

/// The object-safe dispatch behind [`ApiCore`]. Private to this crate.
pub(crate) trait Dispatch: Send + Sync {
    /// Runs one call.
    fn dispatch<'a>(
        &'a self,
        cred: Credential,
        head: &'a RequestHead,
        op: Op,
    ) -> DispatchFuture<'a>;
    /// The rights of a bearer token, with no operation (TH-63).
    fn tool_rights(&self, cred: Credential) -> RightsFuture<'_>;
    /// Whether the `/app/` page at `path` may be served (SA-09).
    fn page<'a>(
        &'a self,
        cred: Credential,
        head: &'a RequestHead,
        path: &'a str,
    ) -> crate::PageFuture<'a>;
    /// The tenant's current branding (M9 lane B2).
    fn brand(&self) -> Option<crate::Brand>;
    /// The paths of the tenant's logos (ADR-030).
    fn tenant_logos(&self) -> crate::brand::LogoPaths;
    /// The funding cards and the tenant defaults (ADR-034).
    fn funding(&self) -> fstp_json::Value;
    /// The legal details as JSON (ADR-037).
    fn legal_details(&self) -> fstp_json::Value;
    /// The legal page at `path` (ADR-037).
    fn legal_page(&self, path: &str) -> Option<String>;
    /// The bytes of the current logo at `path` (ADR-030).
    fn brand_asset<'a>(&'a self, path: &'a str) -> crate::AssetFuture<'a>;
    /// The theme of the session `cred` names (ADR-030).
    fn theme<'a>(&'a self, cred: Credential, head: &'a RequestHead) -> crate::ThemeFuture<'a>;
}

/// The ports of one cell inside an [`ApiCore`], with the dispatch state
/// beside them: pending actions and rate-limit counters, in memory.
struct Core<P> {
    ports: P,
    state: crate::dispatch::State,
}

impl<P: CellPorts> Dispatch for Core<P> {
    fn dispatch<'a>(
        &'a self,
        cred: Credential,
        head: &'a RequestHead,
        op: Op,
    ) -> DispatchFuture<'a> {
        Box::pin(async move {
            let reply = crate::dispatch::run(&self.ports, &self.state, cred, head, op).await;
            // ADR-010 amendment of 2026-11-20: the call's audit entries are
            // durable before it is answered. A failed flush answers 503.
            match self.ports.audit().flush().await {
                Ok(()) => reply,
                Err(_) => Err(crate::ApiError::refused(
                    crate::ErrorCode::Unavailable,
                    "I-24",
                )),
            }
        })
    }

    fn tool_rights(&self, cred: Credential) -> RightsFuture<'_> {
        Box::pin(async move { crate::dispatch::tool_rights(&self.ports, &cred).await })
    }

    fn brand(&self) -> Option<crate::Brand> {
        crate::dispatch::brand_of(&self.ports.engine().snapshot())
    }

    fn tenant_logos(&self) -> crate::brand::LogoPaths {
        let state = self.ports.engine().snapshot();
        crate::brand::paths_of(state.tenant.state(), fstp_tenant::LogoOwner::Tenant)
    }

    fn funding(&self) -> fstp_json::Value {
        crate::funding::answer(&self.ports.engine().snapshot())
    }

    fn legal_details(&self) -> fstp_json::Value {
        crate::legal::details_json(crate::legal::details(&self.ports.engine().snapshot()))
    }

    fn legal_page(&self, path: &str) -> Option<String> {
        let state = self.ports.engine().snapshot();
        let sheet = crate::dispatch::brand_of(&state).map(|b| format!("/brand/{}.css", b.digest));
        crate::legal::page_html(path, crate::legal::details(&state), sheet.as_deref())
    }

    fn brand_asset<'a>(&'a self, path: &'a str) -> crate::AssetFuture<'a> {
        Box::pin(async move { crate::dispatch::brand::asset(&self.ports, path).await })
    }

    fn theme<'a>(&'a self, cred: Credential, head: &'a RequestHead) -> crate::ThemeFuture<'a> {
        Box::pin(async move {
            crate::dispatch::brand::theme(&self.ports, &cred, head)
                .await
                .into()
        })
    }

    fn page<'a>(
        &'a self,
        cred: Credential,
        head: &'a RequestHead,
        path: &'a str,
    ) -> crate::PageFuture<'a> {
        Box::pin(async move {
            crate::dispatch::page::admit(&self.ports, &self.state, &cred, head, path).await
        })
    }
}

/// The dispatch seams over the ports (W3b seam proposal for the lead).
impl<P: CellPorts> crate::dispatch::Seams for P {
    fn grant(
        &self,
        token: &[u8],
        now: Timestamp,
    ) -> impl Future<Output = Result<fstp_access::GrantFacts, PortError>> + Send {
        self.tokens().grant(token, now)
    }

    fn revoke_agent(
        &self,
        account: AccountId,
        client: AgentClientId,
    ) -> impl Future<Output = Result<(), PortError>> + Send {
        self.tokens().revoke(account, client)
    }

    fn dry_run_answers(
        &self,
        cmd: &fstp_engine::Command,
        ctx: Ctx,
    ) -> impl Future<Output = (Result<(), Refusal>, Vec<Answer>)> + Send {
        self.engine().dry_run_answers(cmd, ctx)
    }

    fn mcp_settings(&self) -> fstp_access::McpSettings {
        self.tenant().settings().mcp.clone()
    }

    fn inference(&self) -> Option<(fstp_domain::id::LlmConfigId, fstp_domain::policy::ModelRef)> {
        let s = self.tenant().settings();
        s.inference.as_ref().map(|i| (i.config, i.model.clone()))
    }

    fn tenant_id(&self) -> Option<u128> {
        self.tenant().settings().tenant.map(TenantId::raw)
    }

    fn record_audit(&self, e: AuditEntry) -> Result<(), PortError> {
        self.audit().record(&mut Tx { _w0: () }, e)
    }

    fn call_ids(&self, state: &EngineState) -> Vec<fstp_domain::id::CallId> {
        state.core.calls().iter().map(|(id, _)| id).collect()
    }
}

/// Builds the opaque [`ApiCore`] from a cell's ports. Only `fstp-cell`
/// calls it (rule A2b).
pub fn api_core<P: CellPorts>(ports: P) -> ApiCore {
    ApiCore {
        inner: Box::new(Core {
            ports,
            state: crate::dispatch::State::default(),
        }),
    }
}

/// An [`ApiCore`] whose contract signatures go through `port`, validated
/// against `trust` (M5 design section 3.2). Test and demo cells pass the
/// fake wallet and QTSP of `fstp_contract::fake`. A core built with
/// [`api_core`] refuses every signature (12.1, Q2).
pub fn api_core_with_signing<P: CellPorts>(
    ports: P,
    port: Box<dyn fstp_contract::SignaturePort + Send + Sync>,
    trust: Box<dyn fstp_sigval::TrustedList + Send + Sync>,
) -> ApiCore {
    ApiCore {
        inner: Box::new(Core {
            ports,
            state: crate::dispatch::State::with_signing(crate::dispatch::grant::Signing {
                port,
                trust,
            }),
        }),
    }
}

/// The funding card of `programme` with the tenant's defaults filling its
/// gaps, for the cell's messages (ADR-034, I-69), or `None` when the
/// creator holds no draft of it.
pub fn funding_card(
    state: &fstp_engine::EngineState,
    programme: fstp_domain::id::ProgrammeId,
) -> Option<fstp_brand::funding::FundingCard> {
    crate::funding::card(state, programme)
}

/// The logos of a public page of `programme` with its funding card, for
/// the cell's public pages (ADR-030, ADR-034, I-69).
pub fn public_chrome_logos(
    state: &fstp_engine::EngineState,
    programme: fstp_domain::id::ProgrammeId,
) -> fstp_public::PublicLogos {
    crate::brand::public_chrome_logos(state, programme)
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use fstp_rt::future::block_on;

    struct Stub;
    impl Precheck for Stub {}

    /// R-LA-06, Q38: a pre-check port whose methods are not built yet
    /// fails closed on every method.
    #[test]
    fn r_la_06_precheck_stub_fails_closed() {
        let p = ProposalId::from_raw(1);
        let a = AccountId::from_raw(2);
        let empty = || fstp_findings::UntrustedText::new(String::new());
        let snapshot = PrecheckSnapshot {
            pin: PrecheckPin {
                call: fstp_domain::id::CallId::from_raw(1),
                config: fstp_domain::id::LlmConfigId::from_raw(1),
                model: fstp_domain::policy::ModelRef("synthetic".to_owned()),
                criteria: Vec::new(),
                endpoint: None,
            },
            title: empty(),
            summary: empty(),
            narrative: empty(),
        };
        assert_eq!(
            block_on(Stub.request(p, a, snapshot)),
            Err(PrecheckRefusal::Port(PortError::Unavailable))
        );
        assert_eq!(block_on(Stub.runs(p)), Err(PortError::Unavailable));
        assert_eq!(block_on(Stub.quota(p, a)), Err(PortError::Unavailable));
    }

    /// An engine port that answers nothing but its defaults.
    struct Bare;
    impl AsyncEngine for Bare {
        async fn execute(
            &self,
            _: fstp_engine::Command,
            _: Ctx,
            _: ExecMeta,
        ) -> Result<Seq, ExecError> {
            Err(ExecError::Port(PortError::Unavailable))
        }
        async fn dry_run(&self, _: &fstp_engine::Command, _: Ctx) -> Result<(), Refusal> {
            Ok(())
        }
        async fn dry_run_answers(
            &self,
            _: &fstp_engine::Command,
            _: Ctx,
        ) -> (Result<(), Refusal>, Vec<Answer>) {
            (Ok(()), Vec::new())
        }
        fn snapshot(&self) -> Arc<EngineState> {
            Arc::new(EngineState::genesis())
        }
    }

    /// R-PG-01, R-RP-01, rule A9b: an engine port with no shell of its own
    /// supplies the shipped funder profile a draft's P-53 names, as the
    /// production shell does, and no profile for a name that ships none.
    #[test]
    fn r_pg_01_default_creator_inputs_read_the_shipped_profile() {
        let ctx = Ctx {
            now: Timestamp::from_micros(1),
            actor: fstp_domain::command::Actor::Account(AccountId::from_raw(1)),
            command: fstp_domain::id::CommandId::from_bytes([1; 16]),
            via: Via::Web,
            tenant_admin: true,
            second_tenant_admin: None,
            binds_tenant_admin: false,
        };
        let open = |profile| fstp_creator::CreatorCommand::OpenDraft {
            programme: ProgrammeId::from_raw(5),
            version: fstp_domain::id::PolicyVersionId::from_raw(6),
            profile,
            name: None,
        };
        let state = EngineState::genesis();
        let shipped = crate::creator::default_profile().unwrap();
        let inputs = Bare.creator_inputs(&state, &open(shipped), &ctx);
        assert_eq!(
            inputs.profile.map(|p| p.name().to_owned()),
            Some(fstp_guide::HORIZON_EUROPE.to_owned())
        );
        let other = fstp_domain::policy::FunderProfileRef(
            fstp_domain::policy::OpaqueValue::from_value(
                &fstp_json::parse(br#"{"profile":"no-such-funder","version":1}"#).unwrap(),
            )
            .unwrap(),
        );
        assert!(
            Bare.creator_inputs(&state, &open(other), &ctx)
                .profile
                .is_none()
        );
    }

    const DAY: i64 = 86_400_000_000;

    /// Q23 B, R-ID-04: a date of birth is a real calendar day from 1900
    /// in the one spelling `YYYY-MM-DD`.
    #[test]
    fn r_id_04_birth_date_takes_real_days_only() {
        for ok in [
            "1900-01-01",
            "2009-07-14",
            "2008-02-29",
            "2000-02-29",
            "9999-12-31",
        ] {
            assert!(BirthDate::parse(ok).is_some(), "{ok}");
        }
        for bad in [
            "",
            "1899-12-31",
            "2009-02-29",
            "1900-02-29",
            "2009-13-01",
            "2009-00-10",
            "2009-04-31",
            "2009-7-14",
            "2009/07/14",
            "+009-07-14",
            "2009-07-1a",
            "2009-07-14T00:00:00Z",
            "２００９-07-14",
        ] {
            assert!(BirthDate::parse(bad).is_none(), "{bad}");
        }
    }

    /// Q23 B, R-ID-04, state-machine NOTE 14: the vault's bit turns at
    /// noon UTC of the 18th birthday, and a 29 February birthday turns on
    /// 1 March of a year without it.
    #[test]
    fn r_id_04_adult_from_is_noon_utc_of_the_18th_birthday() {
        let at = |s: &str| BirthDate::parse(s).unwrap().adult_from().unwrap().micros();
        assert_eq!(at("2009-07-14"), 1_815_566_400 * 1_000_000);
        assert_eq!(at("2008-02-29"), 1_772_366_400 * 1_000_000);
        assert_eq!(at("1952-01-01"), DAY / 2);
        assert_eq!(at("2009-07-15") - at("2009-07-14"), DAY);
        assert!(
            BirthDate::parse("9982-01-01")
                .unwrap()
                .adult_from()
                .is_none()
        );
    }

    /// R-NG-01: a declaration of affiliations is not blank and fits its
    /// bound.
    #[test]
    fn r_ng_01_affiliations_are_not_blank_and_bounded() {
        assert!(Affiliations::new("Synthetic organisation").is_some());
        assert!(Affiliations::new(" \n\t").is_none());
        assert!(Affiliations::new("").is_none());
        assert!(Affiliations::new(&"a".repeat(Affiliations::MAX_LEN)).is_some());
        assert!(Affiliations::new(&"a".repeat(Affiliations::MAX_LEN + 1)).is_none());
        assert_eq!(Affiliations::new("x").unwrap().into_text(), "x");
    }
}
